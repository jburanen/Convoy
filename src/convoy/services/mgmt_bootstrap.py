"""Run the Bootstrap panel's service-account commands on a management server,
logging in with an operator-supplied *existing* account.

The Provisioning tab's bootstrap panel renders clish commands (provisioning.py's
``render_gaia_user_commands``) for the operator to paste onto each management
server. This is the alternative: the operator types an existing Gaia login
(typically the box's own admin) once, and this job SSHes in with it and runs
those same commands itself.

That existing login is a **temporary, bootstrap-only** credential and is never
persisted, in either storage mode — not to the credential store, not to job
params, not to a log line or an error message. It lives in the shared
in-memory ``JobCredentialVault`` under the job's id, and the new account's
rendered commands (which carry its password hash) live in this service's own
in-memory map; the runner purges both the moment the job reaches any terminal
state, cancellation included (see ``discard`` and web/app.py's
``job_finished``). Unlike every other host job, the stored credential set is
never consulted here, even in a storage-enabled environment: the account this
creates is the one that set will hold, so it cannot be what logs in.

The target needn't be in the inventory yet — on a new environment this runs
before Connect to Primary has added the primary — so the job addresses a
transient ``Host`` built from the typed address. SSH host keys are still pinned
on first contact and enforced afterwards, by address (transport/ssh.py).

The commands are pure clish (no expert password needed). Sent bare when the
login lands in clish, wrapped ``clish -c`` when it lands in bash — the same
choice ``cpuse.py``'s ``_clish`` makes. If Gaia refuses a command because
another session holds the clish config lock (CLINFR0771, e.g. an open WebUI
session), the job takes it with ``lock database override`` and retries that
command once (operator-directed, 2026-10-02) — ``run_breaking_config_lock``,
the same rule CPUSE installs follow: override only on an observed conflict,
never pre-emptively. **Not yet run against live gear**: in particular whether a
lock taken in one SSH exec session still lets the next command's session
through. An account that already exists fails ``add user``, which is reported,
with the hash redacted, rather than worked around.
"""

from __future__ import annotations

import asyncio
import shlex
import threading

from ..credentials import Credential, CredentialBundle, CredentialKind, JobCredentialVault
from ..errors import JobError, ProvisioningError
from ..inventory import Host, Role
from ..jobs import JobContext, JobRunner
from ..reporting import get_logger
from ..store import JobRecord, Store, new_id
from ..transport.ssh import CommandResult, GaiaShell, run_breaking_config_lock
from .common import EnvironmentRegistry, ensure_host_free
from .provisioning import REDACTED_HASH, render_gaia_user_commands

logger = get_logger(__name__)

JOB_BOOTSTRAP_MGMT = "prov.bootstrap_mgmt"

__all__ = ["JOB_BOOTSTRAP_MGMT", "MgmtBootstrapService"]


class _PendingCommands:
    """job id -> (rendered commands, password hash to redact). In-process
    memory only, the same lifetime as the job's vault entry."""

    def __init__(self) -> None:
        self._by_job: dict[str, tuple[list[str], str]] = {}
        self._lock = threading.Lock()

    def put(self, job_id: str, commands: list[str], secret: str) -> None:
        with self._lock:
            self._by_job[job_id] = (commands, secret)

    def get(self, job_id: str) -> tuple[list[str], str] | None:
        with self._lock:
            return self._by_job.get(job_id)

    def discard(self, job_id: str) -> None:
        with self._lock:
            self._by_job.pop(job_id, None)


def _password_hash(commands: list[str]) -> str:
    """The ``$6$...`` hash out of the rendered ``set user ... password-hash``
    command — the one secret-bearing token, redacted from anything logged."""
    for cmd in commands:
        parts = cmd.split()
        if "password-hash" in parts:
            return parts[parts.index("password-hash") + 1]
    raise ProvisioningError("rendered commands carry no password hash")


class MgmtBootstrapService:
    """Creates this tool's service account on one management server, over SSH,
    using a temporary existing login that is never stored."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        vault: JobCredentialVault,
        runner: JobRunner,
        store: Store,
    ) -> None:
        self.runner = runner
        self._registry = registry
        self._vault = vault
        self._store = store
        self._pending = _PendingCommands()
        runner.register(JOB_BOOTSTRAP_MGMT, self._bootstrap_job)

    def discard(self, job_id: str) -> None:
        """Drop a job's rendered commands. Called by the runner's
        job-finished hook for every job, so it also covers a job cancelled
        before it ever started (its handler, and so its own cleanup, never
        runs)."""
        self._pending.discard(job_id)

    def submit_bootstrap(
        self,
        environment: str,
        *,
        address: str,
        ssh_port: int,
        login_username: str,
        login_password: str,
        account_username: str,
        account_password: str,
        triggered_by: str | None = None,
    ) -> JobRecord:
        connector = self._registry.get(environment)  # raises for an unknown env
        if connector.api_only:
            raise JobError(
                f"environment {environment!r} is API-only management access — there is "
                "no SSH to its management server to bootstrap"
            )
        address = address.strip()
        login_username = login_username.strip()
        if not address:
            raise JobError("an address is required")
        if not login_username or not login_password:
            raise JobError("an existing login username and password are required")
        # Validates the new account's username/password; raises ProvisioningError.
        commands = render_gaia_user_commands(account_username, account_password)
        secret = _password_hash(commands)
        # The job targets the typed address (the server may not be in the
        # inventory yet), so this is also what keeps two bootstraps — or a
        # bootstrap and any other job naming the same address — off one box.
        ensure_host_free(self._store, environment, address)

        login: CredentialBundle = {
            CredentialKind.SSH_PASSWORD: Credential(
                host=address,
                kind=CredentialKind.SSH_PASSWORD,
                username=login_username,
                secret=login_password,  # type: ignore[arg-type]  # pydantic coerces to SecretStr
                environment=environment,
            )
        }
        job_id = new_id()
        self._vault.put(job_id, login)
        self._pending.put(job_id, commands, secret)
        try:
            return self.runner.submit(
                JOB_BOOTSTRAP_MGMT,
                target=address,
                # Deliberately secret-free: no login username either. Job
                # params are persisted with the job record.
                params={"ssh_port": ssh_port, "account_username": account_username},
                environment=environment,
                job_id=job_id,
                triggered_by=triggered_by,
            )
        except Exception:
            self._vault.discard(job_id)
            self._pending.discard(job_id)
            raise

    # -- job handler ------------------------------------------------------------

    async def _bootstrap_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_bootstrap, ctx)

    def _do_bootstrap(self, ctx: JobContext) -> None:
        try:
            self._run(ctx)
        finally:
            # Belt and braces: the runner's job-finished hook purges both too.
            self._vault.discard(ctx.job.id)
            self._pending.discard(ctx.job.id)

    def _run(self, ctx: JobContext) -> None:
        environment = ctx.job.environment
        address = ctx.job.target
        assert address is not None
        connector = self._registry.get(environment)
        login = self._vault.require(ctx.job.id)
        pending = self._pending.get(ctx.job.id)
        if pending is None:
            raise JobError(
                "the bootstrap commands are no longer in memory (the service restarted "
                "since this was submitted) — run the bootstrap again"
            )
        commands, secret = pending
        account = str(ctx.job.params["account_username"])
        # Role only satisfies Host's schema; nothing here branches on it, and
        # this transient Host never enters the inventory.
        host = Host(
            name=address,
            address=address,
            role=Role.PRIMARY_MDS if connector.is_mds else Role.PRIMARY_SMS,
            ssh_port=int(ctx.job.params["ssh_port"]),
        )

        def redact(text: str) -> str:
            return text.replace(secret, REDACTED_HASH)

        # connect() with an explicit bundle never consults the credential
        # store, whatever this environment's storage mode.
        client = connector.connect(host, login)
        try:
            ctx.log(f"connected to {address} with the temporary bootstrap login")
            in_bash = client.shell is GaiaShell.EXPERT
            overrides = 0

            def run_clish(command: str) -> CommandResult:
                nonlocal overrides
                if command == "lock database override":
                    overrides += 1
                wire = f"clish -c {shlex.quote(command)}" if in_bash else command
                return client.run(wire)

            for cmd in commands:
                before = overrides
                result = run_breaking_config_lock(run_clish, cmd, display=redact(cmd))
                if overrides > before:
                    ctx.log(
                        "another session held the clish config lock; took it with "
                        f"`lock database override` and retried `{redact(cmd)}`",
                        level="warning",
                    )
                if not result.ok:
                    # Never require_ok(): its message embeds the raw command,
                    # hash included, and that message becomes job.error.
                    detail = redact(result.stderr.strip() or result.stdout.strip())
                    raise JobError(
                        f"`{redact(cmd)}` failed on {address} (rc={result.exit_status})"
                        + (f": {detail}" if detail else "")
                    )
                ctx.log(f"ran: {redact(cmd)}")
        finally:
            client.close()
        ctx.log(f"created service account {account!r} on {address}")
        logger.info(
            "bootstrapped service account",
            environment=environment,
            address=address,
            account=account,
            triggered_by=ctx.job.username,
        )
