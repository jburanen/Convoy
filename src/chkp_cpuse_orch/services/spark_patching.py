"""Spark (Quantum Spark / Gaia Embedded) firmware patching service.

Spark firewalls don't go through CPUSE or CDT — see patching.py's module
docstring for that path, used by every other host kind this tool patches.
Spark patches via SCP + expert-mode shell commands instead (operator-
specified, 2026-08-19): enable ``bashUser``, transfer a ``.img`` file to
``/storage``, disable ``bashUser`` again — that's the whole transfer job,
see JOB_TRANSFER below — then, as its own separately-triggered install job
(JOB_INSTALL), run ``upgrade_revert_image.sh ... upgrade safe``, which
reboots the device on its own a minute or two later. See
.claude/memory/spark-firmware-patching.md for
the assumptions here that shipped **unvalidated against real Spark
hardware** and how they've resolved since: the file transfer originally
reused ``Transport.put()`` (Paramiko's SFTP subsystem, same as the Gaia CPUSE
path) but a real-hardware run confirmed Spark's SSH server doesn't speak SFTP
in either ``bashUser`` state — it failed with "Channel closed" — so the
transfer now goes over ``SSHClient.put_scp()`` (transport/ssh.py), the
classic SCP protocol, which matches what ``bashUser on``'s own banner
actually advertises ("SCP access enabled", no mention of SFTP). The exact
prompt text the ``expert`` command's password escalation uses
(transport/ssh.py's GaiaExpertSession) was confirmed correct the same day.
Both were isolated behind narrow interfaces so a wrong guess was a contained
fix, not a rewrite.

Three job kinds:

- **test_credentials** — proves SSH login *and* ``expert``-mode escalation
  work for a Spark firewall's assigned credential set. Never runs a mutating
  command, so it's safe to run repeatedly with no confirmation gate — unlike
  transfer/install below.
- **transfer** — SCP the ``.img`` to ``/storage`` and nothing else (operator-
  directed, 2026-08-19, after "Upload and import" was found to also fire the
  upgrade command — see .claude/memory/spark-firmware-patching.md). No
  confirmation gate: it doesn't reboot anything, mirroring CPUSE's plain
  ``/import``. Once it succeeds, the package filename is recorded into the
  same ``ServerStateRow.installable`` cache CPUSE hosts use, so the
  Firewalls-panel row's Install picker (originally CPUSE-only) lists it too.
- **install** — runs ``upgrade_revert_image.sh ... upgrade safe`` against a
  ``.img`` already sitting in ``/storage`` (a prior transfer job, almost
  always — nothing stops issuing install against a file staged some other
  way, same as CPUSE's install trusts its own picker rather than re-checking
  device state). Requires ``confirmed=True``: the device reboots on its own
  once the upgrade command is issued (scheduled by the script itself for
  ~1 minute out — it returns control on both success and failure well
  before that, it doesn't wait for the reboot), and that can't be undone or
  cancelled after the fact. The job cannot and does not fully confirm the
  upgrade actually completed — Spark has nothing like CPUSE's ``show
  installer package`` to poll — but it does fail closed on one specific,
  confirmed-on-real-hardware bad outcome (see ``_STALE_MOUNT_MARKER``);
  beyond that, success only means the command was issued.

Refresh (``detect``, not a job — synchronous, mirrors ``PatchingService.
detect()``'s shape) is also Spark-specific: there's no CPUSE agent on Gaia
Embedded, so none of ``show installer status``/``show installer packages
...``/``show cluster state`` apply. Version comes from plain ``fw ver``
instead (operator-specified, 2026-08-19) — assumed to work over a bare SSH
exec without needing ``expert`` escalation first, unvalidated against real
hardware like the two assumptions above.
"""

from __future__ import annotations

import asyncio
import contextlib
import posixpath
import re
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

from ..credentials import CredentialBundle, CredentialKind, JobCredentialVault
from ..errors import (
    CredentialError,
    ExpertModeError,
    JobError,
    TransportError,
    TransportTimeoutError,
)
from ..inventory import Host
from ..jobs import JobContext, JobRunner, JobTimedOut
from ..packages import PackageStore, package_kind
from ..store import JobRecord, ServerStateRow, Store, utcnow
from ..transport.ssh import GaiaExpertSession, InteractiveShell, require_ok
from .common import (
    EnvironmentRegistry,
    HostConnector,
    ProgressReporter,
    Transport,
    ensure_host_free,
    job_run_credentials,
    submit_host_job,
    verify_uploaded_file,
)

__all__ = [
    "JOB_INSTALL",
    "JOB_TEST_CREDENTIALS",
    "JOB_TRANSFER",
    "EnvironmentRegistry",
    "HostConnector",
    "SparkPatchingService",
]

JOB_TEST_CREDENTIALS = "spark.testcred"
JOB_TRANSFER = "spark.scp"
JOB_INSTALL = "spark.install"

# Gaia Embedded's fixed staging location for upgrade_revert_image.sh.
_STORAGE_DIR = "/storage"

# Generous — the script validates the image and copies/extracts a large
# rootfs (the .tgz alone is ~200MB on the image real-hardware testing has
# used) onto embedded flash before returning control, which real-hardware
# testing 2026-08-20 confirmed can genuinely take several minutes — the
# previous 120s value was cutting that off mid-extraction, not catching a
# hang. Per upgrade_revert_image.sh's own quit_upgrade_revert_image(), the
# script exits (and this returns) on BOTH success and failure — it only
# *schedules* the reboot (a DB flag, default ~60s out) before exiting, it
# doesn't wait for it — so a normal return here is expected either way, not
# just on failure; the device rebooting is a separate, later event this SSH
# session won't see. A dropped connection mid-response is still handled
# below as a plausible (if less likely, given the above) outcome, not
# assumed away. See .claude/memory/spark-firmware-patching.md.
_UPGRADE_TIMEOUT = 600.0

# Operator-specified 2026-08-20: once the script returns control (the Expert
# prompt reappears), actively wait to *observe* the scheduled reboot close
# this session, rather than assuming it happened — the script's own default
# schedules it ~60s out, this is generous headroom above that. If it never
# closes in time (e.g. the script actually failed without ever scheduling
# one — see _run_upgrade), this session is closed and the flow proceeds to
# ping/reconnect/verify anyway, which is the actual arbiter either way.
_REBOOT_CLOSE_TIMEOUT = 300.0

# How long to keep probing for the device to respond again after this
# session disconnects (a full boot cycle, not just the ~60s reboot delay
# above), and how often.
_PING_TIMEOUT = 900.0
_PING_POLL_INTERVAL = 5.0
_PING_CONNECT_TIMEOUT = 3.0

# How long to retry the post-reboot SSH reconnect once ping succeeds (sshd
# can come up slightly after the host starts accepting TCP connects), and
# how often.
_RECONNECT_TIMEOUT = 300.0
_RECONNECT_POLL_INTERVAL = 10.0

# mke2fs's own refusal message (not a Check Point string — e2fsprogs' fixed
# wording) when the inactive partition is already mounted — confirmed via
# the actual upgrade_revert_image.sh source: mount_pfrm_inactive_part()
# only checks the *following* `mount` command's exit status, not mke2fs's,
# so this failure doesn't necessarily abort the script — it can silently
# extract the new rootfs onto a partition that was never reformatted. Real-
# hardware-confirmed 2026-08-19, see .claude/memory/spark-firmware-patching.md.
_STALE_MOUNT_MARKER = "is mounted; will not make a filesystem here"

# `fw ver`'s banner opens with "This is Check Point's " before the actual
# model/version/build text we want — strip it. `.` (not a literal `'`)
# tolerates either a straight or a typographic apostrophe in case CPUSE
# renders the latter on some builds.
_FW_VER_PREFIX_RE = re.compile(r"^\s*this is check point.s\s+", re.IGNORECASE)


def parse_fw_ver(stdout: str) -> str:
    """Truncate `fw ver`'s output to the descriptive tail the Firewalls
    table shows as this Spark firewall's version — e.g. "This is Check
    Point's 1550 Appliance R81.10.17 - Build 892" becomes "1550 Appliance
    R81.10.17 - Build 892". Falls back to the trimmed first line as-is if
    the expected prefix isn't there, rather than raising — this only feeds
    a display string, not a decision."""
    first_line = next((line.strip() for line in stdout.splitlines() if line.strip()), "")
    return _FW_VER_PREFIX_RE.sub("", first_line).strip()


# Spark .img packages embed a numeric build id in the filename (e.g.
# "fw1_vx_dep_R81_10_17_996004936.img"), and `fw ver`'s own "Build NNN" text
# is only ever the trailing few digits of that same number (operator-
# specified, 2026-08-20: compare the two builds' *last three digits* to
# confirm a post-install reboot actually landed on the requested image).
_IMAGE_BUILD_RE = re.compile(r"_(\d+)\.img$", re.IGNORECASE)
_FW_VER_BUILD_RE = re.compile(r"\bBuild\s+(\d+)", re.IGNORECASE)


def _image_build_suffix(filename: str) -> str | None:
    """Last 3 digits of the build id embedded in a Spark .img filename, or
    None if the filename doesn't match the expected convention — callers
    must treat that as "can't verify", not "assume success"."""
    match = _IMAGE_BUILD_RE.search(filename)
    return None if match is None else match.group(1)[-3:]


def _fw_ver_build_suffix(fw_ver_output: str) -> str | None:
    """Last 3 digits of `fw ver`'s own "Build NNN" number, or None if that
    text isn't present in its output."""
    match = _FW_VER_BUILD_RE.search(fw_ver_output)
    return None if match is None else match.group(1)[-3:]


def _default_probe_reachable(address: str, port: int, *, timeout: float) -> bool:
    """Stands in for "ping" via a TCP connect, not ICMP — unprivileged ICMP
    needs CAP_NET_RAW or a suid ping binary, neither of which this tool's
    container image provides (nor does the slim base image even ship a ping
    binary at all). Connecting to the SSH port this job is about to use next
    anyway is also a more directly relevant signal than a bare ICMP echo
    would be — SSH-adjacent reachability, not just kernel-is-up."""
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


class ExpertCapableTransport(Transport, Protocol):
    """A Transport that can also open a pty-backed interactive shell — what
    the Spark expert-mode commands (bashUser on/off,
    upgrade_revert_image.sh) need — and upload over classic SCP rather than
    ``Transport.put()``'s SFTP, which Spark's SSH server doesn't speak (see
    module docstring). SSHClient satisfies this structurally (see
    transport/ssh.py); tests substitute a fake with the same shape."""

    def open_interactive_shell(self) -> InteractiveShell: ...

    def put_scp(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int: ...


def _safe_close(closable: object) -> None:
    """Best-effort close — used in ``finally`` blocks around a connection
    that may already be dead (e.g. the device started rebooting). A raise
    here would shadow whatever real exception is propagating."""
    close = getattr(closable, "close", None)
    if close is None:
        return
    with contextlib.suppress(Exception):
        close()


class SparkPatchingService:
    """Per-Spark-firewall firmware operations, across independent environments."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        packages: PackageStore,
        runner: JobRunner,
        vault: JobCredentialVault,
        store: Store,
        probe_reachable: Callable[[str, int], bool] | None = None,
        reboot_close_timeout: float = _REBOOT_CLOSE_TIMEOUT,
        ping_timeout: float = _PING_TIMEOUT,
        ping_poll_interval: float = _PING_POLL_INTERVAL,
        reconnect_timeout: float = _RECONNECT_TIMEOUT,
        reconnect_poll_interval: float = _RECONNECT_POLL_INTERVAL,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self._packages = packages
        self._vault = vault
        self._store = store
        # Injectable so tests can skip real socket I/O and control timing —
        # see _default_probe_reachable for why this is TCP-connect, not ICMP.
        self._probe_reachable: Callable[[str, int], bool] = probe_reachable or (
            lambda address, port: _default_probe_reachable(
                address, port, timeout=_PING_CONNECT_TIMEOUT
            )
        )
        # Constructor-configurable (not just module constants), same
        # convention as PatchingService's import/install verify knobs, so
        # tests can shrink these instead of actually waiting real minutes.
        self._reboot_close_timeout = reboot_close_timeout
        self._ping_timeout = ping_timeout
        self._ping_poll_interval = ping_poll_interval
        self._reconnect_timeout = reconnect_timeout
        self._reconnect_poll_interval = reconnect_poll_interval
        runner.register(JOB_TEST_CREDENTIALS, self._test_credentials_job)
        runner.register(JOB_TRANSFER, self._transfer_job)
        runner.register(JOB_INSTALL, self._install_job)

    # -- queries --------------------------------------------------------------------

    def detect(
        self,
        environment: str,
        host_name: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> str:
        """Live-query a Spark firewall's version via `fw ver` — the Refresh
        action's Spark counterpart to ``PatchingService.detect()``, which
        this deliberately does not call into: none of its CPUSE queries
        (`show installer status`/`show installer packages ...`/`show
        cluster state`) apply to a device with no CPUSE agent. Blocking
        (SSH) — call via ``asyncio.to_thread`` from async contexts. Caches
        the result the same way PatchingService does, into the same
        ``ServerStateRow`` table, so the Firewalls list reflects it without
        a separate read; jhf/agent_build/cluster_role are left None since
        none of those concepts apply to Spark. ``installable`` is preserved
        from whatever was already cached rather than cleared — it's not a
        CPUSE concept here, it's this tool's own record of ``.img`` files a
        transfer job has staged in ``/storage`` (see submit_transfer), and a
        plain Refresh shouldn't erase that bookkeeping."""
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        creds = connector.require_credentials(host, credentials)
        client = connector.connect(host, creds)
        try:
            result = require_ok(client.run("fw ver"))
            version = parse_fw_ver(result.stdout)
            existing = self._store.get_server_state(environment, host.name)
            self._store.upsert_server_state(
                ServerStateRow(
                    environment=environment,
                    host=host.name,
                    version=version,
                    checked_at=utcnow(),
                    installable=existing.installable if existing else [],
                )
            )
            return version
        finally:
            client.close()

    # -- job submission -----------------------------------------------------------

    def submit_test_credentials(
        self,
        environment: str,
        host_name: str,
        *,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: SSH login + ``expert``-mode escalation, nothing more —
        never touches device state, so it's safe to run repeatedly."""
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        ensure_host_free(self._store, environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_TEST_CREDENTIALS,
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_transfer(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: bashUser on -> transfer the .img to /storage -> verify ->
        bashUser off. No confirmation gate — this only stores a file on the
        device, it doesn't reboot anything, same as CPUSE's plain import.
        Install (a separate, confirmed job — see submit_install) is what
        actually runs the upgrade."""
        if package_kind(package_filename) != "spark_image":
            raise JobError(
                f"{package_filename!r} isn't a Spark firmware image (.img) — Spark firewalls "
                "only accept .img packages"
            )
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        ensure_host_free(self._store, environment, host_name)
        self._packages.path_for(package_filename)  # validates record + content file
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_TRANSFER,
            params={"package": package_filename},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_install(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        confirmed: bool,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: expert mode -> upgrade_revert_image.sh ... upgrade safe,
        against a ``.img`` expected to already be staged in ``/storage`` by
        a prior transfer job (which already left bashUser off — this job
        doesn't repeat that). ``confirmed`` must be True —
        the device reboots on its own once the upgrade command is issued,
        and that can't be undone or cancelled. Doesn't re-check device state
        before enqueuing (same trust-the-picker posture as CPUSE's
        submit_install) — a package that was never actually transferred
        fails at the device, surfaced as an ordinary job failure."""
        if not confirmed:
            raise JobError(
                "install requires explicit confirmation — the firewall reboots on its own "
                "once the upgrade command is issued, and this cannot be undone"
            )
        if package_kind(package_filename) != "spark_image":
            raise JobError(
                f"{package_filename!r} isn't a Spark firmware image (.img) — Spark firewalls "
                "only accept .img packages"
            )
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        ensure_host_free(self._store, environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_INSTALL,
            params={"package": package_filename},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    # -- job handlers (async wrappers over blocking SSH work) ----------------------

    async def _test_credentials_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_test_credentials, ctx)

    async def _transfer_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_transfer, ctx)

    async def _install_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_install, ctx)

    # -- shared helpers -------------------------------------------------------------

    def _resolve_bundle(
        self, connector: HostConnector, host: Host, ctx: JobContext
    ) -> CredentialBundle:
        """The full credential bundle for this job, whichever way it's
        sourced — the vault (storage-disabled) or the store (storage-
        enabled). The same bundle object is then passed straight to
        ``connect()`` so the expert-password check below and the actual
        connection always see identical credentials."""
        creds = job_run_credentials(connector, self._vault, ctx.job)
        if creds is not None:
            return creds
        return connector.host_credentials(host)

    def _require_expert_password(
        self, bundle: CredentialBundle, host: Host, ctx: JobContext
    ) -> str:
        """Checked before any SSH attempt: a Spark firewall's assigned set
        isn't guaranteed to carry an expert password just because the
        Spark credential modal enforces it at creation time — a set could
        have been reassigned since. Missing it is a config problem, not a
        connectivity one, so this fails without ever opening a connection."""
        cred = bundle.get(CredentialKind.EXPERT_PASSWORD)
        if cred is None:
            raise CredentialError(
                f"the credential set assigned to {host.name!r} has no expert-mode "
                "password — edit it on the Provisioning tab"
            )
        return cred.reveal()

    def _connect(
        self, connector: HostConnector, host: Host, bundle: CredentialBundle
    ) -> ExpertCapableTransport:
        return cast(ExpertCapableTransport, connector.connect(host, bundle))

    # -- test_credentials -------------------------------------------------------------

    def _do_test_credentials(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.spark_firewall_host(ctx.job.target or "")
        bundle = self._resolve_bundle(connector, host, ctx)
        expert_password = self._require_expert_password(bundle, host, ctx)  # no SSH before this

        ctx.log(f"connecting over SSH to {host.name}")
        client = self._connect(connector, host, bundle)
        try:
            ctx.log("SSH login succeeded")
            shell = client.open_interactive_shell()
            try:
                session = GaiaExpertSession(shell)
                try:
                    session.enter_expert(expert_password)
                except ExpertModeError:
                    ctx.log("expert-mode password was rejected", level="error")
                    raise
                ctx.log("expert mode entered successfully")
                session.exit_expert()
            finally:
                _safe_close(shell)
        finally:
            _safe_close(client)

    # -- transfer -----------------------------------------------------------------

    def _do_transfer(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.spark_firewall_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        expected_sha1 = self._packages.get(package).sha1
        remote_path = posixpath.join(_STORAGE_DIR, package)

        bundle = self._resolve_bundle(connector, host, ctx)
        expert_password = self._require_expert_password(bundle, host, ctx)  # no SSH before this

        self._enable_bash_user(connector, host, bundle, expert_password, ctx)
        self._transfer_image(
            connector, host, bundle, local_path, local_size, expected_sha1, remote_path, ctx
        )
        # Restore the device to its normal (bashUser off) state now rather
        # than leaving SCP/shell access enabled until whenever install
        # eventually runs — install (_run_upgrade) does NOT repeat this, so
        # it's the only place bashUser gets turned back off.
        self._disable_bash_user(connector, host, bundle, expert_password, ctx)

        self._mark_staged(ctx.job.environment, host.name, package)
        ctx.log(
            f"{package} is staged in {remote_path} — use the Install button on this "
            "firewall's row to run the upgrade when ready"
        )

    def _mark_staged(self, environment: str, host_name: str, package: str) -> None:
        """Record a successfully-transferred filename into the same
        ``ServerStateRow.installable`` cache CPUSE hosts use, so the
        Firewalls-panel row's Install picker lists it — this tool's own
        record of what it staged, not a live device query (Spark has
        nothing like CPUSE's `show installer packages ...` to ask)."""
        existing = self._store.get_server_state(environment, host_name)
        installable = list(existing.installable) if existing else []
        if package not in installable:
            installable.append(package)
        self._store.upsert_server_state(
            ServerStateRow(
                environment=environment,
                host=host_name,
                version=existing.version if existing else None,
                jhf=existing.jhf if existing else None,
                agent_build=existing.agent_build if existing else None,
                checked_at=existing.checked_at if existing else utcnow(),
                installable=installable,
                installed=existing.installed if existing else [],
                cluster_role=existing.cluster_role if existing else None,
            )
        )

    def _unmark_staged(self, environment: str, host_name: str, package: str) -> None:
        """Drop a package from the staged/installable list once install has
        issued the upgrade command for it — best-effort UI hygiene, not a
        correctness guarantee: this job can't confirm the upgrade actually
        completed (see submit_install), so this only means "no longer worth
        offering to install again", not "confirmed gone from /storage"."""
        existing = self._store.get_server_state(environment, host_name)
        if existing is None or package not in existing.installable:
            return
        self._store.upsert_server_state(
            ServerStateRow(
                environment=environment,
                host=host_name,
                version=existing.version,
                jhf=existing.jhf,
                agent_build=existing.agent_build,
                checked_at=existing.checked_at,
                installable=[p for p in existing.installable if p != package],
                installed=existing.installed,
                cluster_role=existing.cluster_role,
            )
        )

    def _enable_bash_user(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        expert_password: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (enabling SCP transfer)")
        client = self._connect(connector, host, bundle)
        try:
            shell = client.open_interactive_shell()
            try:
                session = GaiaExpertSession(shell)
                session.enter_expert(expert_password)
                ctx.raise_if_cancelled()  # last safe stop before mutating device state
                output = session.run_expert("bashUser on")
                if output:
                    ctx.log(f"bashUser on output:\n{output}")
                session.exit_expert()
            finally:
                _safe_close(shell)
        finally:
            _safe_close(client)
        # Full logout between enabling bashUser and the file transfer, not just
        # exiting expert mode — some Gaia Embedded builds only pick up the new
        # bashUser state on a fresh session (operator-specified sequence).
        ctx.log("logging out before file transfer (full session boundary)")

    def _transfer_image(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        local_path: Path,
        local_size: int,
        expected_sha1: str,
        remote_path: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (transferring the firmware image)")
        client = self._connect(connector, host, bundle)
        try:
            filename = posixpath.basename(remote_path)
            ctx.log(f"uploading {filename} ({local_size} bytes) to {host.name}:{remote_path}")
            reporter = ProgressReporter(ctx, local_size)
            remote_size = client.put_scp(str(local_path), remote_path, progress=reporter)
            verify_uploaded_file(
                client,
                remote_path,
                remote_size=remote_size,
                expected_size=local_size,
                expected_sha1=expected_sha1,
                ctx=ctx,
            )
        finally:
            _safe_close(client)
        ctx.log("logging out before disabling SCP transfer (full session boundary)")

    def _disable_bash_user(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        expert_password: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (disabling SCP transfer)")
        client = self._connect(connector, host, bundle)
        try:
            shell = client.open_interactive_shell()
            try:
                session = GaiaExpertSession(shell)
                session.enter_expert(expert_password)
                output = session.run_expert("bashUser off")
                if output:
                    ctx.log(f"bashUser off output:\n{output}")
                session.exit_expert()
            finally:
                _safe_close(shell)
        finally:
            _safe_close(client)

    # -- install --------------------------------------------------------------------

    def _do_install(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.spark_firewall_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        remote_path = posixpath.join(_STORAGE_DIR, package)
        # Computed up front and checked before touching the device at all:
        # if we can't even parse what build we're expecting, there's no
        # point running the upgrade only to discover we can't verify it.
        expected_build = _image_build_suffix(package)
        if expected_build is None:
            raise JobError(
                f"{package!r} doesn't match the expected Spark image filename "
                "convention (a numeric build id right before .img) — can't verify "
                "the post-install build number, refusing to proceed blind"
            )

        bundle = self._resolve_bundle(connector, host, ctx)
        expert_password = self._require_expert_password(bundle, host, ctx)  # no SSH before this

        self._run_upgrade(connector, host, bundle, expert_password, remote_path, ctx)
        self._unmark_staged(ctx.job.environment, host.name, package)

        ctx.set_status("waiting for firewall to respond to ping")
        self._wait_until_reachable(host, ctx)

        ctx.set_status("reconnecting over SSH")
        client = self._wait_until_reconnected(connector, host, bundle, ctx)
        try:
            ctx.set_status("verifying installed build")
            result = require_ok(client.run("fw ver"))
        finally:
            _safe_close(client)

        version = parse_fw_ver(result.stdout)
        actual_build = _fw_ver_build_suffix(result.stdout)
        if actual_build is None:
            raise JobError(
                "reconnected successfully, but couldn't find a build number in "
                f"fw ver's output to confirm the upgrade: {result.stdout.strip()!r}"
            )
        if actual_build != expected_build:
            raise JobError(
                f"reconnected after reboot, but fw ver reports build ...{actual_build} "
                f"— expected ...{expected_build} (from {package!r}). The device did "
                f"not come up on the installed image — do not treat this as a "
                f"successful upgrade. fw ver: {version!r}"
            )
        ctx.log(
            f"confirmed: fw ver reports build ...{actual_build}, matching {package!r} — {version}"
        )
        ctx.set_status(None)

    def _run_upgrade(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        expert_password: str,
        remote_path: str,
        ctx: JobContext,
    ) -> None:
        """Issue the upgrade command and get off the device's back — this no
        longer tries to judge success/failure from the session's own output
        (operator-directed 2026-08-20, after real-hardware testing showed a
        bounded wait here was either cutting off a still-running script or
        just guessing at what a returned prompt meant). It only logs what it
        observes and always returns normally except for the one specific,
        already-confirmed-bad case (_STALE_MOUNT_MARKER) — the definitive
        verdict comes from _do_install's ping/reconnect/fw-ver check
        afterward, which works whether or not this method ever sees the
        script return or the connection drop."""
        ctx.set_status("connecting")
        ctx.log(f"connecting over SSH to {host.name} (running the upgrade)")
        client = self._connect(connector, host, bundle)
        shell = None
        leave_connected = False
        try:
            shell = client.open_interactive_shell()
            session = GaiaExpertSession(shell)
            session.enter_expert(expert_password)
            # LAST safe stop — the upgrade command below cannot be undone or
            # cancelled once issued.
            ctx.raise_if_cancelled()
            # bashUser off is _do_transfer's job (its last step, before this
            # one is ever triggered) — not this job's; re-running it here was
            # leftover from when transfer+install were one combined job.
            upgrade_cmd = f"upgrade_revert_image.sh {remote_path} upgrade safe"
            ctx.set_status("installing")
            ctx.log(
                f"starting upgrade: {upgrade_cmd} — leaving this session open and "
                "just watching it; the definitive check happens afterward (ping, "
                "reconnect, fw ver), not from this session's own output"
            )
            try:
                output = session.run_expert(upgrade_cmd, timeout=_UPGRADE_TIMEOUT)
                if output:
                    ctx.log(f"upgrade command output:\n{output}")
                if _STALE_MOUNT_MARKER in output:
                    raise JobError(
                        "mke2fs refused to format the inactive partition — "
                        f"{_STALE_MOUNT_MARKER!r} — it was already mounted, almost "
                        "certainly a stale mount left by an earlier, incomplete upgrade "
                        "attempt on this device. upgrade_revert_image.sh's own "
                        "mount_pfrm_inactive_part() only checks the *following* `mount` "
                        "command's exit status, not mke2fs's, so it likely continued "
                        "anyway and extracted the new image onto a partition that was "
                        "never actually reformatted — do not trust this upgrade; reboot "
                        "the firewall to clear the stale mount before retrying"
                    )
                # The script returned control. Per its own
                # quit_upgrade_revert_image(), that happens on both success
                # and failure — it only *schedules* the reboot (~60s out by
                # default) before exiting, it doesn't wait for it. Actively
                # wait to observe that reboot close this session, rather than
                # just assuming it happened.
                ctx.set_status("waiting for reboot")
                ctx.log(
                    "script returned control — waiting for the scheduled reboot to "
                    "close this session"
                )
                try:
                    shell.wait_for_close(timeout=self._reboot_close_timeout)
                    ctx.log("session closed — device is rebooting")
                except TransportTimeoutError:
                    ctx.log(
                        f"session still open {self._reboot_close_timeout:.0f}s after the "
                        "script returned control — no reboot happened (the script may "
                        "have failed without scheduling one); closing this session and "
                        "verifying directly instead of waiting further",
                        level="warning",
                    )
            except TransportTimeoutError as exc:
                # The channel never reported closed within the full
                # script-run budget — real-hardware testing 2026-08-20
                # confirmed this does NOT mean the device is rebooting
                # (that's the channel-closed branch below); it means the
                # script hasn't returned control yet and may still be
                # legitimately working. Forcibly closing the pty-backed
                # channel here would send a hangup to that still-running
                # foreground process and can abort an in-progress upgrade —
                # worse than just not knowing yet. Leave this connection
                # open (leaked, deliberately) and verify independently via
                # ping/reconnect/fw ver instead of waiting on it further.
                leave_connected = True
                ctx.set_status("waiting for reboot")
                ctx.log(
                    f"upgrade_revert_image.sh did not return control within "
                    f"{_UPGRADE_TIMEOUT:.0f}s, and the SSH channel is still open — not "
                    f"closing it (may still be legitimately running); verifying "
                    f"independently instead: {exc}",
                    level="warning",
                )
            except TransportError as exc:
                # Channel actually closed — expected: the device may have
                # dropped the connection as it began rebooting, possibly
                # before ever returning control.
                ctx.set_status("waiting for reboot")
                ctx.log(
                    "connection closed while waiting for upgrade_revert_image.sh output "
                    f"— treating as the scheduled reboot: {exc}",
                    level="warning",
                )
        finally:
            if not leave_connected:
                if shell is not None:
                    _safe_close(shell)
                _safe_close(client)

    def _wait_until_reachable(self, host: Host, ctx: JobContext) -> None:
        """Poll TCP-connect reachability (see _default_probe_reachable) on
        the SSH port until the host responds or ``self._ping_timeout``
        elapses. Raises JobTimedOut, not JobError — the device may simply
        still be rebooting/booting; this isn't evidence of failure by
        itself, only of not being done yet."""
        deadline = time.monotonic() + self._ping_timeout
        attempt = 0
        progress_seq: int | None = None
        while True:
            attempt += 1
            if self._probe_reachable(host.address, host.ssh_port):
                ctx.log(f"{host.name} is responding again (attempt {attempt})")
                return
            if time.monotonic() >= deadline:
                raise JobTimedOut(
                    f"{host.name} never responded within {self._ping_timeout:.0f}s of "
                    "the upgrade command being issued — it may still be rebooting, or "
                    "may have failed to come back up; check it directly"
                )
            ctx.raise_if_cancelled()
            event = ctx.log(
                f"waiting for {host.name} to respond (attempt {attempt})", replace=progress_seq
            )
            progress_seq = event.seq
            time.sleep(self._ping_poll_interval)

    def _wait_until_reconnected(
        self, connector: HostConnector, host: Host, bundle: CredentialBundle, ctx: JobContext
    ) -> ExpertCapableTransport:
        """Retry a full SSH connect (not just the TCP-connect ping above)
        until it succeeds or ``self._reconnect_timeout`` elapses — sshd can
        come up slightly after the host starts accepting TCP connects on the
        same port. Raises JobTimedOut, not JobError, for the same reason as
        _wait_until_reachable."""
        deadline = time.monotonic() + self._reconnect_timeout
        attempt = 0
        progress_seq: int | None = None
        last_error: Exception | None = None
        while True:
            attempt += 1
            try:
                return self._connect(connector, host, bundle)
            except TransportError as exc:
                last_error = exc
            if time.monotonic() >= deadline:
                raise JobTimedOut(
                    f"could not re-establish SSH to {host.name} within "
                    f"{self._reconnect_timeout:.0f}s of it responding to reachability "
                    f"checks — last error: {last_error}"
                )
            ctx.raise_if_cancelled()
            event = ctx.log(
                f"reconnect attempt {attempt} failed, retrying: {last_error}",
                replace=progress_seq,
            )
            progress_seq = event.seq
            time.sleep(self._reconnect_poll_interval)
