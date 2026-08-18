"""Re-push a firewall's assigned credential set onto the gateway itself, via
the Management API — the Firewalls panel's recovery path for an SSH
authentication failure during status refresh (app.js's ``refreshFirewallState``).

When a firewall's stored password no longer matches what's actually on the
box, ordinary SSH-based recovery is circular: the only way in is the thing
that's broken. The Management API reaches the gateway over SIC instead (no
SSH needed), so ``run-script`` can push the same clish commands the
Provisioning tab's bootstrap panel already generates
(``render_gaia_user_commands``/``render_bootstrap_script`` in
provisioning.py) — wrapped ``clish -c "..."`` since ``run-script`` executes
as bash, not clish.

``preview_bootstrap_commands`` is read-only rendering (no server contact),
shown in a confirm dialog before the operator commits — same
diagnose-then-confirm-then-job shape as services/api_access.py, just the
Management API instead of SSH as the execution channel. ``submit_bootstrap``
mutates a production gateway's local admin account, so it stays confirm-
gated and runs as its own ``JobRunner`` job for Jobs-tab audit history.

``run-script``/``show-task``'s exact response shape was NOT trusted from the
docs MCP (this repo has been burned twice before on fabricated field names,
see .claude/memory/api-access-repair-flow.md) — it was verified against live
gear 2026-08-18 before this was written: a single-target task's ``show-task``
response carries a ``task-details`` list (one entry per target), each with
``statusCode`` ("succeeded" on success), ``responseError`` (empty string on
success), and ``responseMessage`` (the script's stdout, **base64-encoded**).
The polling loop/status-set convention below mirrors
services/pkg_repo_ops.py's ``add-repository-package`` polling, which uses the
same generic Management API task mechanism.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Callable
from types import TracebackType
from typing import Any, Protocol

from ..credentials import CredentialKind
from ..errors import CredentialError, TransportError
from ..inventory import Host
from ..jobs import JobContext, JobRunner
from ..store import JobRecord, Store
from ..transport.mgmt_api import ManagementAPIClient
from .common import EnvironmentRegistry, api_auth
from .provisioning import render_bootstrap_script, render_gaia_user_commands

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


def _decode_task_output(task: dict[str, Any]) -> tuple[bool, str]:
    """(ok, message) for a single-target run-script task from its
    ``task-details[0]`` entry — see the module docstring for the confirmed
    shape. Never raises: an unexpected shape is reported as a failure with
    the raw task attached, not a crash."""
    details = task.get("task-details")
    if not isinstance(details, list) or not details or not isinstance(details[0], dict):
        return False, f"no usable task-details in show-task response: {task!r}"
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


class GatewayBootstrapService:
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
    ) -> None:
        self._registry = registry
        self._store = store
        self.runner = runner
        self._mgmt_client_factory = mgmt_client_factory or _default_mgmt_client_factory
        self._poll_interval = poll_interval
        runner.register(JOB_BOOTSTRAP_CREDENTIALS, self._bootstrap_job)

    def preview_bootstrap_commands(self, environment: str, name: str) -> list[str]:
        """Pure rendering (no server contact) for the confirm dialog shown
        before ``submit_bootstrap`` actually runs these via the Management
        API. Raises OrchestratorError if the firewall is unknown or its
        assigned credential set isn't password-based."""
        connector = self._registry.get(environment)
        host = connector.firewall_host(name)
        bundle = connector.host_credentials(host)
        username, password = _bootstrap_credential(host, bundle)
        return render_gaia_user_commands(username, password)

    def submit_bootstrap(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        connector = self._registry.get(environment)
        connector.firewall_host(name)  # validates existence/role before queuing
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
        ctx.log(f"pushing credentials for {username!r} to {name!r} via the Management API")
        with self._mgmt_client_factory(primary, read_only=False, **auth) as client:
            task_id = client.run_script(
                script, [name], script_name="chkp-cpuse-orch-bootstrap-credentials"
            )
            ctx.log(f"run-script task {task_id} submitted — polling for completion")
            self._poll_task(ctx, client, task_id)

    def _poll_task(self, ctx: JobContext, client: MgmtClientContext, task_id: str) -> None:
        last_status = ""
        while True:
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
                    raise TransportError(f"bootstrap script reported a failure: {message}")
                ctx.log(f"gateway response: {message}")
                return
            if status.lower() in _TASK_FAILURE:
                _, message = _decode_task_output(task)
                raise TransportError(f"bootstrap task failed: {message}")
            ctx.raise_if_cancelled()


__all__ = ["JOB_BOOTSTRAP_CREDENTIALS", "GatewayBootstrapService"]
