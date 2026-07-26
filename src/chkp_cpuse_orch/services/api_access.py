"""Diagnose and repair Check Point Management API accessibility on a primary
management server — the SSH-based follow-up the web UI runs proactively
right after a Connect to Primary job (services/connect_primary.py) succeeds,
so a broken accessibility setting surfaces where it was just provisioned
instead of later as a confusing HTTP 403 during estate discovery.

An unreachable Management API almost always means one of two things: the API
process isn't started, or its ``accessibility`` setting is scoped to
``require-local`` (loopback only) and refuses this app's connection outright.
``api status``, run over SSH since by construction the API itself is what's
unreachable, tells the two apart. The fix for the second case widens
accessibility to ``"minimize"`` — Check Point's own "All IP addresses that
can be used for GUI clients" (Trusted Clients) option, the least-broad
setting that unblocks this app — via ``mgmt_cli set-api-settings``, then
publishes and restarts the API server (required for the new setting to take
effect; this briefly drops other API/SmartConsole sessions, not gateway
policy enforcement — CLI reference: set-api-settings v2.1).

``diagnose()`` is read-only and synchronous, same shape as
``DiscoveryService.list_domains`` — the UI calls it automatically, no
operator click needed. ``submit_repair()`` mutates a production server's API
settings and forces a brief restart, so it stays confirm-gated (preview then
Run, same pattern as ``PrimaryConnectService``) and runs as its own
``JobRunner`` job (``prov.repair_api_access``, audited via ``ctx.log``) —
deliberately not folded into ``PrimaryConnectService``'s own mgmt_cli session
(see .claude/memory/api-access-repair-flow.md for why)."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from ..errors import CredentialError, OrchestratorError, TransportError
from ..jobs import JobContext, JobRunner
from ..store import JobRecord
from ..transport.ssh import require_ok
from .common import EnvironmentRegistry
from .provisioning import (
    render_mgmt_login_command,
    render_publish_logout_commands,
    render_set_api_settings_command,
)

JOB_REPAIR_API_ACCESS = "prov.repair_api_access"

__all__ = [
    "JOB_REPAIR_API_ACCESS",
    "ApiAccessDiagnosis",
    "ApiAccessService",
    "parse_api_status",
    "render_repair_commands",
]


@dataclass
class ApiAccessDiagnosis:
    """Result of running ``api status`` on an environment's primary over SSH.

    ``error`` is set instead of the other fields when the SSH connection or
    the command itself failed — never raised, so the UI always gets
    something to show (same never-raises convention as
    ``DiscoveryService.find_cluster_name``).
    """

    overall_started: bool = False
    restricted_to_local: bool = False
    raw_output: str = ""
    error: str | None = None


# `api status`'s accessibility line isn't a fixed, documented schema (Check
# Point ships it as free text alongside a process table), so this matches
# loosely: any line mentioning "accessib..." whose value contains "local"
# means the API only accepts connections from itself.
_ACCESSIBILITY_RE = re.compile(r"accessib\w*\W*(.+)", re.IGNORECASE)
_STARTED_RE = re.compile(r"Overall API Status:\s*Started", re.IGNORECASE)


def parse_api_status(stdout: str) -> tuple[bool, bool]:
    """``(overall_started, restricted_to_local)`` parsed from ``api status``."""
    started = bool(_STARTED_RE.search(stdout))
    restricted = False
    match = _ACCESSIBILITY_RE.search(stdout)
    if match and "local" in match.group(1).lower():
        restricted = True
    return started, restricted


def render_repair_commands(*, is_mds: bool) -> list[str]:
    """The exact mgmt_cli sequence ``submit_repair`` runs over SSH — exposed
    so the UI can show the operator what will change before they confirm.

    NOT YET CONFIRMED against live MDS gear: ``api restart`` here runs
    without an ``mdsenv <Domain>`` context, same as everywhere else this
    login is used (``render_mgmt_login_command``) — Check Point's own docs
    describe restarting a specific Domain's API via ``mdsenv``, but this
    tool has no confirmed model yet for which scope a plain ``api
    restart``/``api status`` on an MDS affects."""
    return [
        render_mgmt_login_command(is_mds=is_mds),
        render_set_api_settings_command(),
        *render_publish_logout_commands(),
        "api restart",
    ]


class ApiAccessService:
    """Diagnoses and repairs a primary management server's Management API
    accessibility over SSH — the operator-facing follow-up to a 403 on
    estate discovery."""

    def __init__(self, *, registry: EnvironmentRegistry, runner: JobRunner) -> None:
        self._registry = registry
        self.runner = runner
        runner.register(JOB_REPAIR_API_ACCESS, self._repair_job)

    def diagnose(self, environment: str) -> ApiAccessDiagnosis:
        try:
            connector = self._registry.get(environment)
            primary = connector.primary_mgmt_host()
        except OrchestratorError as exc:
            return ApiAccessDiagnosis(error=str(exc))
        try:
            client = connector.connect(primary)
        except (CredentialError, TransportError) as exc:
            return ApiAccessDiagnosis(
                error=f"SSH connection to {primary.name} ({primary.address}) failed: {exc}"
            )
        try:
            result = client.run("api status")
        except TransportError as exc:
            return ApiAccessDiagnosis(error=f"`api status` failed: {exc}")
        finally:
            client.close()
        if result.exit_status != 0:
            stderr = result.stderr.strip() or "(no stderr)"
            return ApiAccessDiagnosis(error=f"`api status` exited {result.exit_status}: {stderr}")
        started, restricted = parse_api_status(result.stdout)
        return ApiAccessDiagnosis(
            overall_started=started, restricted_to_local=restricted, raw_output=result.stdout
        )

    def preview_repair_commands(self, environment: str) -> list[str]:
        """Pure rendering (no SSH) for the confirm dialog shown before
        ``submit_repair`` actually runs these over SSH."""
        is_mds = self._registry.get(environment).is_mds
        return render_repair_commands(is_mds=is_mds)

    def submit_repair(self, environment: str, *, triggered_by: str | None = None) -> JobRecord:
        connector = self._registry.get(environment)
        primary = connector.primary_mgmt_host()
        return self.runner.submit(
            JOB_REPAIR_API_ACCESS,
            target=primary.name,
            params={"is_mds": connector.is_mds},
            environment=environment,
            triggered_by=triggered_by,
        )

    # -- job handler --------------------------------------------------------------

    async def _repair_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_repair, ctx)

    def _do_repair(self, ctx: JobContext) -> None:
        environment = ctx.job.environment
        name = ctx.job.target
        assert name is not None
        connector = self._registry.get(environment)
        host = connector.mgmt_host(name)
        is_mds = bool(ctx.job.params["is_mds"])

        client = connector.connect(host)
        try:
            ctx.log(f"connected to {host.name} ({host.address}) over SSH")
            status = require_ok(client.run("api status"))
            _started, restricted = parse_api_status(status.stdout)
            if not restricted:
                ctx.log(
                    "API accessibility is already open to non-local connections — nothing to repair"
                )
                return
            ctx.log(
                "API accessibility is restricted to localhost — widening it to "
                '"minimize" (All IP addresses that can be used for GUI clients)'
            )
            require_ok(client.run(render_mgmt_login_command(is_mds=is_mds)))
            require_ok(client.run(render_set_api_settings_command()))
            for cmd in render_publish_logout_commands():
                require_ok(client.run(cmd))
            ctx.log("published the change and logged out of mgmt_cli")
            require_ok(client.run("api restart"))
            ctx.log("restarted the API server for the new setting to take effect")
        finally:
            client.close()
