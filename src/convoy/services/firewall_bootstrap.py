"""Re-push a firewall's assigned credential set onto the firewall itself, via
the Management API — the Firewalls panel's recovery path for an SSH
authentication failure during status refresh (app.js's ``refreshFirewallState``).

When a firewall's stored password no longer matches what's actually on the
box, ordinary SSH-based recovery is circular: the only way in is the thing
that's broken. The Management API reaches the firewall over SIC instead (no
SSH needed), so ``run-script`` can push the same clish commands the
Provisioning tab's bootstrap panel already generates
(``render_gaia_user_commands``/``render_bootstrap_script`` in
provisioning.py) — wrapped ``clish -c "..."`` since ``run-script`` executes
as bash, not clish.

``preview_bootstrap_commands`` is read-only rendering (no server contact),
shown in a confirm dialog before the operator commits — same
diagnose-then-confirm-then-job shape as services/api_access.py, just the
Management API instead of SSH as the execution channel. ``submit_bootstrap``
mutates a production firewall's local admin account, so it stays confirm-
gated and runs as its own ``JobRunner`` job for Jobs-tab audit history.

``run-script``/``show-task``'s exact response shape was NOT trusted from the
docs MCP (this repo has been burned twice before on fabricated field names,
see .claude/memory/api-access-repair-flow.md) — it was verified against live
gear 2026-08-18 before this was written: a single-target task's ``show-task``
response carries a ``task-details`` list (one entry per target), each with
``statusCode`` ("succeeded" on success), ``responseError`` (empty string on
success), and ``responseMessage`` (the script's stdout, **base64-encoded**).

``task-details`` only comes back at ``details-level: full``, which
``ManagementAPIClient.show_task`` now requests by default. Without it the
response carries a task-level ``status: succeeded`` and nothing else usable,
and this module correctly refused to confirm a bootstrap it had no evidence
for — observed on an MDS 2026-08-27.
The polling loop/status-set convention below mirrors
services/pkg_repo_ops.py's ``add-repository-package`` polling, which uses the
same generic Management API task mechanism.

**Spark (Quantum SMB) firewalls are a deliberate exception to all of the
above** (operator-directed, 2026-08-18): ``preview_spark_admin_commands``
renders SMB's own ``add administrator`` clish command
(``provisioning.render_spark_admin_commands``) but there is no matching
``submit_*`` / ``run-script`` push — Spark's support for that transport
isn't established, and full Gaia's clish commands aren't valid on Gaia
Embedded anyway. ``preview_bootstrap_commands``/``submit_bootstrap`` (the
full-Gaia path above) explicitly reject a Spark target rather than silently
rendering/pushing the wrong commands to it.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Callable
from types import TracebackType
from typing import Any, Protocol

from ..credentials import CredentialKind
from ..errors import CredentialError, InventoryError, TransportError
from ..inventory import Host, Role
from ..jobs import JobContext, JobRunner, JobTimedOut
from ..store import JobRecord, Store
from ..transport.mgmt_api import ManagementAPIClient
from .common import EnvironmentRegistry, api_auth
from .provisioning import (
    render_bootstrap_script,
    render_gaia_user_commands,
    render_spark_admin_commands,
)

JOB_BOOTSTRAP_CREDENTIALS = "cred.bootstrap"

# Same generic Management API task-status vocabulary as pkg_repo_ops.py's
# add-repository-package polling (Check Point's show-task mechanism is shared
# across async commands) — treat this as the authoritative-but-not-exhaustive
# set, defaulting to "still running" for anything else.
_TASK_SUCCESS = {"succeeded", "succeeded with warnings"}
_TASK_FAILURE = {"failed", "partially succeeded", "aborted", "timed out", "verification_failed"}


class MgmtClientContext(Protocol):
    """The slice of ManagementAPIClient this job uses (as a context manager)."""

    def __enter__(self) -> Any: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
    def run_script(self, script: str, targets: list[str], *, script_name: str = ...) -> str: ...
    def show_task(self, task_id: str) -> dict[str, Any]: ...
    def show_firewalls_and_servers(self, *, details_level: str = ...) -> list[dict[str, Any]]: ...


MgmtClientFactory = Callable[..., MgmtClientContext]


def _default_mgmt_client_factory(host: Host, **kwargs: Any) -> MgmtClientContext:
    return ManagementAPIClient(host, **kwargs)


def _bootstrap_credential(host: Host, bundle: dict[CredentialKind, Any]) -> tuple[str, str]:
    """Pull (username, password) out of a firewall's credential bundle, or
    raise a clear CredentialError. A private-key-only (or key-free) set has
    no plaintext password to hash into a clish ``password-hash`` command —
    bootstrap needs a password-based credential set."""
    pw_cred = bundle.get(CredentialKind.SSH_PASSWORD)
    if pw_cred is None or not pw_cred.username:
        raise CredentialError(
            f"the credential set assigned to {host.name!r} uses a private key, not a "
            "password — bootstrapping credentials needs a password-based credential set "
            "(edit it on the Provisioning tab)"
        )
    return pw_cred.username, pw_cred.reveal()


def _object_address(obj: dict[str, Any]) -> str:
    """The address a management-database object reports, using the same field
    precedence services/discovery.py already applies to these objects."""
    return str(obj.get("ipv4-address") or obj.get("ipv6-address") or "").strip()


def _confirm_target_identity(client: MgmtClientContext, host: Host) -> str:
    """Assert that the management server's object named ``host.name`` really is
    the box at ``host.address``, and return the address it reported.

    ``run-script`` resolves its targets by **name**, against the management
    server's own object database — not against anything this tool configured.
    Without this check, a local inventory row is only a name plus a credential
    set: point one at any address (or none), name it after a real SIC-trusted
    firewall, and the bootstrap script's uid-0 ``adminRole`` account lands on
    that real firewall instead. The local ``address`` is the only field that
    ties a row to a specific device, so it has to be the thing we verify
    against before borrowing the management server's SIC trust.

    Fails closed: an unknown name, an object with no usable address, or any
    mismatch raises rather than proceeding."""
    matches = [
        obj
        for obj in client.show_firewalls_and_servers()
        if str(obj.get("name") or "").strip() == host.name
    ]
    if not matches:
        raise InventoryError(
            f"the management server has no firewall/server object named {host.name!r} — "
            "refusing to push credentials to a target it can't resolve"
        )
    if len(matches) > 1:
        raise InventoryError(
            f"the management server reports {len(matches)} objects named {host.name!r} — "
            "refusing to push credentials to an ambiguous target"
        )
    resolved = _object_address(matches[0])
    if not resolved:
        raise InventoryError(
            f"the management server's object {host.name!r} reports no IP address — "
            "can't confirm it is the host configured at "
            f"{host.address!r}, refusing to push credentials"
        )
    if resolved != host.address.strip():
        raise InventoryError(
            f"refusing to bootstrap {host.name!r}: this environment's inventory has it at "
            f"{host.address!r}, but the management server resolves that name to "
            f"{resolved!r}. run-script targets by name, so pushing now would create an "
            "admin account on a different device than the one configured here. Fix the "
            "address (or the name) so the two agree."
        )
    return resolved


def _decode_task_output(task: dict[str, Any]) -> tuple[bool, str]:
    """(ok, message) for a single-target run-script task from its
    ``task-details[0]`` entry — see the module docstring for the confirmed
    shape. Never raises: an unexpected shape is reported as a failure with
    the raw task attached, not a crash."""
    details = task.get("task-details")
    if not isinstance(details, list) or not details or not isinstance(details[0], dict):
        # Deliberately NOT treated as success even when the task itself says
        # "succeeded": task-details is the only evidence of the SCRIPT's exit
        # status, and confirming on its absence is exactly the confirmed-on-no-
        # evidence failure the security review's M4 closed elsewhere. The raw
        # response goes to the job log rather than into this message — it is a
        # wall of text, and this string is what the UI shows inline.
        return False, (
            "show-task returned no per-target task-details, so the script's own "
            "exit status could not be confirmed (raw response in the job log)"
        )
    detail = details[0]
    status_code = str(detail.get("statusCode") or "").strip()
    error = str(detail.get("responseError") or "").strip()
    raw_message = detail.get("responseMessage")
    output = ""
    if isinstance(raw_message, str) and raw_message:
        try:
            output = base64.b64decode(raw_message).decode("utf-8", errors="replace").strip()
        except ValueError:
            output = raw_message
    ok = status_code.lower() == "succeeded" and not error
    message = error or output or status_code or "no output"
    return ok, message


class FirewallBootstrapService:
    """Preview and execute a credential-set bootstrap onto a firewall via
    the Management API's ``run-script``."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        store: Store,
        runner: JobRunner,
        mgmt_client_factory: MgmtClientFactory | None = None,
        poll_interval: float = 3.0,
        task_timeout: float = 900.0,
    ) -> None:
        self._registry = registry
        self._store = store
        self.runner = runner
        self._mgmt_client_factory = mgmt_client_factory or _default_mgmt_client_factory
        self._poll_interval = poll_interval
        self._task_timeout = task_timeout
        runner.register(JOB_BOOTSTRAP_CREDENTIALS, self._bootstrap_job)

    def preview_bootstrap_commands(self, environment: str, name: str) -> list[str]:
        """Pure rendering (no server contact) for the confirm dialog shown
        before ``submit_bootstrap`` actually runs these via the Management
        API. Raises OrchestratorError if the firewall is unknown, is a Spark
        firewall (see ``preview_spark_admin_commands`` instead — that path
        stays manual, no automated push), or its assigned credential set
        isn't password-based."""
        connector = self._registry.get(environment)
        host = connector.firewall_host(name)
        if host.role == Role.SPARK_FIREWALL:
            raise InventoryError(
                f"{name!r} is a Spark firewall — its bootstrap commands are "
                "display-only, not an automated push (see the Spark bootstrap preview)"
            )
        bundle = connector.host_credentials(host)
        username, password = _bootstrap_credential(host, bundle)
        # Hash elided: this is a plain GET available to every authenticated
        # user, and a 5000-round sha512_crypt hash is offline-crackable. The
        # real value is computed by the push itself (see _do_bootstrap), so the
        # preview loses nothing by showing the command shape alone.
        return render_gaia_user_commands(username, password, redact_hash=True)

    def preview_spark_admin_commands(self, environment: str, name: str) -> list[str]:
        """Read-only rendering (no server contact) of the Quantum Spark (SMB)
        ``add administrator`` clish command for ``name``'s assigned
        credential set, for the operator to paste into the device's own
        clish shell. Unlike ``preview_bootstrap_commands`` (full Gaia),
        there is no matching ``submit_*`` — Spark bootstrap stays manual
        (operator-directed, 2026-08-18): Management API ``run-script``
        support on Spark appliances isn't established, and full Gaia's
        clish account commands aren't valid there anyway (see
        ``provisioning.render_spark_admin_commands``)."""
        connector = self._registry.get(environment)
        host = connector.firewall_host(name)
        if host.role != Role.SPARK_FIREWALL:
            raise InventoryError(f"{name!r} is not a Spark firewall")
        bundle = connector.host_credentials(host)
        username, password = _bootstrap_credential(host, bundle)
        return render_spark_admin_commands(username, password)

    def submit_bootstrap(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        connector = self._registry.get(environment)
        host = connector.firewall_host(name)  # validates existence/role before queuing
        if host.role == Role.SPARK_FIREWALL:
            raise InventoryError(
                f"{name!r} is a Spark firewall — credential bootstrap there is "
                "manual, not an automated push (see the Spark bootstrap preview)"
            )
        return self.runner.submit(
            JOB_BOOTSTRAP_CREDENTIALS,
            target=name,
            environment=environment,
            triggered_by=triggered_by,
        )

    # -- job handler --------------------------------------------------------------

    async def _bootstrap_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_bootstrap, ctx)

    def _do_bootstrap(self, ctx: JobContext) -> None:
        environment = ctx.job.environment
        name = ctx.job.target
        assert name is not None
        connector = self._registry.get(environment)

        # Re-resolve and re-validate here, not just at preview time — the job
        # may run well after the preview was shown, and credentials/roles are
        # never trusted to still match without a fresh check.
        host = connector.firewall_host(name)
        bundle = connector.host_credentials(host)
        username, password = _bootstrap_credential(host, bundle)

        primary = connector.primary_mgmt_host()
        auth = api_auth(connector.host_credentials(primary))
        if connector.is_mds:
            fw_row = self._store.get_firewall(environment, name)
            domain = fw_row.mds_domain if fw_row else None
            if domain:
                auth = {**auth, "domain": domain}

        script = render_bootstrap_script(username, password)
        with self._mgmt_client_factory(primary, read_only=False, **auth) as client:
            resolved = _confirm_target_identity(client, host)
            # Log what the management server actually resolved, not just the
            # locally-chosen name — the audit trail has to record which device
            # was touched, and the name alone is caller-controlled.
            ctx.log(
                f"confirmed target {name!r} resolves to {resolved} on the management "
                f"server, matching this environment's inventory"
            )
            ctx.log(f"pushing credentials for {username!r} to {name!r} via the Management API")
            task_id = client.run_script(script, [name], script_name="convoy-bootstrap-credentials")
            ctx.log(f"run-script task {task_id} submitted — polling for completion")
            self._poll_task(ctx, client, task_id)

    def _poll_task(self, ctx: JobContext, client: MgmtClientContext, task_id: str) -> None:
        """Poll a run-script task to a terminal state, with a wall-clock
        deadline.

        This used to loop forever on any status outside the known
        success/failure sets — including a status a broken or hostile
        management server could simply keep returning. With JobRunner's
        bounded concurrency, two such stuck jobs deadlock the whole queue and
        Cancel cannot help, because the only cancellation check is inside the
        loop the job never leaves."""
        last_status = ""
        deadline = time.monotonic() + self._task_timeout
        while True:
            if time.monotonic() >= deadline:
                raise JobTimedOut(
                    f"bootstrap task {task_id} did not reach a terminal state within "
                    f"{self._task_timeout:.0f}s (last status: {last_status or 'unknown'}) "
                    "— it may still be running on the management server"
                )
            time.sleep(self._poll_interval)
            task = client.show_task(task_id)
            status = str(task.get("status", "")).strip()
            if status != last_status:
                last_status = status
                pct = task.get("progress-percentage")
                suffix = f" ({pct}%)" if pct is not None else ""
                ctx.log(f"bootstrap task status: {status or 'unknown'}{suffix}")
            if status.lower() in _TASK_SUCCESS:
                ok, message = _decode_task_output(task)
                if not ok:
                    ctx.log(f"raw show-task response: {task!r}", level="warning")
                    raise TransportError(f"bootstrap script reported a failure: {message}")
                ctx.log(f"firewall response: {message}")
                return
            if status.lower() in _TASK_FAILURE:
                _, message = _decode_task_output(task)
                ctx.log(f"raw show-task response: {task!r}", level="warning")
                raise TransportError(f"bootstrap task failed: {message}")
            ctx.raise_if_cancelled()


__all__ = ["JOB_BOOTSTRAP_CREDENTIALS", "FirewallBootstrapService"]
