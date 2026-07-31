"""CPUSE-local patching service — one host at a time, over SSH.

Glues inventory + credential store + package store + CPUSE wrapper + job runner
into the operations the web UI exposes per host. Serves both management
servers and firewalls identically (see HostConnector.patchable_host) — the
CPUSE mechanics below don't care which kind of Gaia host they're talking to:

- **detect**        — live `show installer packages` (source of truth for the UI)
- **import**        — checks free disk space on `/var/log` (3x the package
  size) and `/` (2x) before doing anything else — `df -Pk`, fails the job
  closed with PreCheckError if either falls short (operator-specified,
  2026-07-23). A shortfall down to 1.5x the package's own size can be
  overridden by the operator — the UI runs check_import_disk_space as a
  synchronous precheck, offers an override when eligible, and the job itself
  re-verifies rather than trusting the flag blindly; below 1.5x there is no
  override, ever (operator-specified, 2026-07-24) — then SFTPs the package to
  a temp path on the host, verifies its
  sha1 on the host itself (catches a corrupted/truncated transfer before
  `installer import` ever touches it), `installer import local`, then remove
  the temp copy. `installer import local` returns before CPUSE has actually
  finished importing (it processes the file asynchronously — "determining
  package type" → "examining the file" → ...) — removing the temp file right
  after the command returns raced that and produced a job that reported
  success while CPUSE itself then failed with "package file is missing"
  (observed 2026-07-22). So: poll `show installer packages imported` until
  the package actually appears before cleaning up and declaring the job
  successful — matching by filename *or* by the version+Take pair read out
  of the package's own hf.config (see hfconfig.py), since CPUSE renders some
  package types (JHFs) as a human-readable string with no relation to the
  uploaded filename (e.g. "R82.10 Jumbo Hotfix Accumulator Take 24"). If it
  still hasn't shown up after `import_verify_attempts * import_verify_delay`
  (default 30 * 10s = 5 minutes — this can genuinely take a while), the job
  finishes as TIMED_OUT rather than FAILED: CPUSE may still be working, so
  this isn't a verdict. The temp copy is left in place either way. The Jobs
  tab offers a manual "Check status" recheck on a TIMED_OUT import job
  (`PatchingService.recheck_import`) — one more live look at `show installer
  packages imported`; if it now shows up, the job is resolved to SUCCEEDED,
  the temp copy is cleaned up, and detected state is refreshed, same as the
  automatic path. If not, the job stays TIMED_OUT for another try later.
- **import_cloud**  — direct the host to fetch + import a package from Check
  Point's cloud repository by identifier; no local file involved
- **install**        — optional `installer verify`, then `installer install`, then
  poll `show installer package <id>` until its Status line shows Installed —
  `installer install` returns before the install actually finishes (same
  asynchronous pattern as import), and can report success while the install
  is still running or has genuinely failed and never left "Imported"
  (observed 2026-07-22). Reboot-required packages drop the SSH session
  partway through polling — expected, not a failure — so a dropped
  connection there reconnects and keeps waiting instead of failing closed.
  Once Status shows real progress (a percentage), the attempts budget is
  dropped and polling continues unbounded until it completes. CPUSE's
  "Installation log" field, once available, names a path on the host — that
  file's actual *content* is fetched over the same connection and saved on
  the job record (`JobRecord.install_log`), since a bare path is worthless
  once CPUSE rotates or deletes the file. The Jobs tab renders it collapsed
  under the job row.

Both import paths, and install, refresh and cache detected state (version/JHF/
agent build/packages ready to install) right after succeeding — so the UI
reflects the change without a separate manual Refresh. Best-effort: a refresh
hiccup here is a warning, not a job failure, since the underlying operation
already succeeded.

Each mutating operation runs as a background job (a web click enqueues and
returns). Blocking SSH work runs in a worker thread via ``asyncio.to_thread``.
Install may reboot the host, so it additionally requires an explicit operator
confirmation flag — full HA-peer gating arrives with checks.py. See
.claude/memory/patching-web-design.md and safety-constraints.md.
"""

from __future__ import annotations

import asyncio
import posixpath
import shlex
import time
from dataclasses import dataclass, field

from ..clusterxl import ClusterMemberState
from ..cpuse import (
    CPUSE,
    DEFAULT_STAGING_DIR,
    GaiaShell,
    PackageScope,
    PackageState,
    summarize_jumbo,
)
from ..cpuse import extract_take as cpuse_extract_take
from ..cpuse import extract_version as cpuse_extract_version
from ..credentials import CredentialBundle, JobCredentialVault
from ..errors import CPUSEError, JobError, OrchestratorError, PreCheckError, TransportError
from ..hfconfig import HfConfig, extract_hf_config
from ..inventory import Host
from ..jobs import JobContext, JobRunner, JobTimedOut
from ..packages import PackageStore
from ..store import JobRecord, JobStatus, ServerStateRow, Store, utcnow
from .common import (
    ClientFactory,
    EnvironmentRegistry,
    HostConnector,
    Transport,
    job_run_credentials,
    submit_host_job,
)

__all__ = [
    "JOB_IMPORT",
    "JOB_IMPORT_CLOUD",
    "JOB_INSTALL",
    "JOB_UNINSTALL",
    "ClientFactory",
    "DiskSpaceCheck",
    "EnvironmentRegistry",
    "HostConnector",
    "PatchingService",
    "Transport",
]

JOB_IMPORT = "cpuse.import"
JOB_IMPORT_CLOUD = "cpuse.import_cloud"
JOB_INSTALL = "cpuse.install"
JOB_UNINSTALL = "cpuse.uninstall"

# Generous cap on captured install-log content — CPUSE logs are normally KBs,
# this just bounds a pathological case from bloating the DB / archive file.
_INSTALL_LOG_MAX_BYTES = 2 * 1024 * 1024

# Pre-import disk space requirements, as a multiple of the package's own size
# (operator-specified, 2026-07-23). /var/log is where the package stages and
# CPUSE needs headroom there for its own extraction/processing; / needs
# enough for CPUSE's bookkeeping during import.
_DISK_CHECK_PATHS = (("/var/log", 3), ("/", 2))

# Below this fraction of the package's own size, a disk-space shortfall can
# never be overridden — regardless of which path/multiplier triggered it
# (operator-specified, 2026-07-24). Above it but still short of the full
# requirement, the UI may offer the operator a way to proceed anyway.
_MIN_OVERRIDE_MULTIPLIER = 1.5


def _fmt_bytes(n: int) -> str:
    """Human-readable byte count for pre-check error/log messages."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _is_imported_now(cpuse: CPUSE, package_filename: str, hf_config: HfConfig | None) -> bool:
    """One live `show installer packages imported` look for the given
    package. A candidate matches if *either* its identifier is (or contains
    the stem of) the uploaded filename, *or* — since CPUSE renders some
    package types (JHFs) as a human-readable string unrelated to the
    filename, e.g. "R82.10 Jumbo Hotfix Accumulator Take 24" — its
    identifier's own version+Take equal the ones recorded in the package's
    hf.config. Either check alone can mismatch depending on the package
    type, so both run and either is sufficient. Shared by
    PatchingService._wait_until_imported (polling) and .recheck_import (a
    single manual check after a timeout)."""
    stem = package_filename.rsplit(".", 1)[0]
    expect_version = hf_config.direct_base_version if hf_config else None
    expect_take = hf_config.take_number if hf_config else None
    for pkg in cpuse.list_packages(PackageScope.IMPORTED):
        if pkg.identifier == package_filename or stem in pkg.identifier:
            return True
        if (
            expect_version is not None
            and expect_take is not None
            and cpuse_extract_version(pkg.identifier) == expect_version
            and cpuse_extract_take(pkg.identifier) == expect_take
        ):
            return True
    return False


@dataclass
class DetectedState:
    """Live CPUSE state of one host, as the UI shows it."""

    host: str
    agent_build: str = ""
    packages: list[PackageState] = field(default_factory=list)
    cluster: ClusterMemberState | None = None


@dataclass
class DiskSpaceCheck:
    """One required path's disk-space precheck result, measured against the
    package's own size. ``override_eligible`` is only meaningful when ``ok``
    is False — see _MIN_OVERRIDE_MULTIPLIER."""

    path: str
    multiplier: int
    available: int
    required: int
    ok: bool
    override_eligible: bool


class PatchingService:
    """Per-management-server CPUSE operations, across independent environments."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        packages: PackageStore,
        runner: JobRunner,
        vault: JobCredentialVault,
        store: Store,
        staging_dir: str = DEFAULT_STAGING_DIR,
        shell: GaiaShell = GaiaShell.EXPERT,
        import_verify_attempts: int = 30,
        import_verify_delay: float = 10.0,
        install_verify_attempts: int = 30,
        install_verify_delay: float = 30.0,
        install_stall_seconds: float = 90.0,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self._packages = packages
        self._vault = vault
        self._store = store
        self._staging_dir = staging_dir
        self._shell = shell
        # How long we're willing to poll `show installer packages imported`
        # for the just-uploaded package to actually show up, before giving up
        # (30 * 10s = 5 minutes) — see the module docstring for why this exists.
        self._import_verify_attempts = import_verify_attempts
        self._import_verify_delay = import_verify_delay
        # Installs commonly take several minutes, so poll less often but for
        # much longer (30 * 30s = 15 minutes) than import verification. But if
        # Status hasn't moved off "Imported" — i.e. the install never even
        # appears to have started — within install_stall_seconds, give up
        # early instead of waiting out the full 15 minutes.
        self._install_verify_attempts = install_verify_attempts
        self._install_verify_delay = install_verify_delay
        self._install_stall_seconds = install_stall_seconds
        runner.register(JOB_IMPORT, self._import_job)
        runner.register(JOB_IMPORT_CLOUD, self._import_cloud_job)
        runner.register(JOB_INSTALL, self._install_job)
        runner.register(JOB_UNINSTALL, self._uninstall_job)

    # -- queries -----------------------------------------------------------------

    def management_servers(self, environment: str) -> list[Host]:
        return self.registry.get(environment).management_servers()

    def firewalls(self, environment: str) -> list[Host]:
        return self.registry.get(environment).firewalls()

    def assigned_credential(self, environment: str, host_name: str) -> str | None:
        """Name of the credential set assigned to a server, or None if unassigned."""
        return self.registry.get(environment).assigned_credential(host_name)

    def detect(
        self,
        environment: str,
        host_name: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> DetectedState:
        """Live-query CPUSE state. Blocking (SSH) — call via ``asyncio.to_thread``
        from async contexts. Always detected state, never assumed. Caches the
        result (see ``_cache_state``) so the servers list reflects it without
        a separate read."""
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        creds = connector.require_credentials(host, credentials)
        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            agent_build = cpuse.agent_build()
            packages = cpuse.list_packages(PackageScope.ALL)
            imported_packages = cpuse.list_packages(PackageScope.IMPORTED)
            cluster = cpuse.cluster_state()
            self._cache_state(
                environment,
                host.name,
                agent_build,
                packages,
                cluster,
                imported_packages=imported_packages,
            )
            return DetectedState(
                host=host.name, agent_build=agent_build, packages=packages, cluster=cluster
            )
        finally:
            client.close()

    def check_import_disk_space(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> list[DiskSpaceCheck]:
        """Synchronous, read-only precheck the UI runs before submit_import:
        same thresholds as the job's own gate (_check_disk_space), but no
        upload and no CPUSE interaction — lets the operator see a shortfall
        and choose to override before the real (background) job ever queues.
        Blocking (SSH) — call via ``asyncio.to_thread`` from async contexts."""
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        creds = connector.require_credentials(host, credentials)
        local_path = self._packages.path_for(package_filename)
        local_size = local_path.stat().st_size
        client = connector.connect(host, creds)
        try:
            return self._disk_space_report(client, local_size)
        finally:
            client.close()

    def _cache_state(
        self,
        environment: str,
        host_name: str,
        agent_build: str,
        packages: list[PackageState],
        cluster: ClusterMemberState | None = None,
        *,
        imported_packages: list[PackageState] | None = None,
    ) -> None:
        """Derive the UI's summary (version/JHF, packages ready to install)
        from detected packages and persist it — shared by ``detect()`` (an
        explicit Refresh) and both import job handlers (an automatic refresh
        right after a successful import, reusing the same open connection).

        ``installable`` identifiers come from ``imported_packages`` — a
        dedicated `show installer packages imported` query — rather than by
        filtering ``packages`` (the combined `show installer packages all`
        query used for the version summary and the installed list). CPUSE
        doesn't reliably render the same identifier for a package across the
        two scopes: some JHFs show a human-readable "R82.10 Jumbo Hotfix
        Accumulator Take 24" style name under `imported` but a bare filename
        under `all` (same quirk `_is_imported_now`/hf.config already work
        around for import confirmation — see the module docstring), and
        `installer verify`/`installer install` need the identifier exactly as
        `imported` scope renders it, since that's what those verbs actually
        recognize (operator-confirmed, 2026-07-31 — installs were issuing
        `installer verify` against the `all`-scoped identifier and failing).
        Falls back to filtering ``packages`` itself when no separate
        imported-scope list is supplied.
        """
        summary = summarize_jumbo(packages)
        installed = [p.identifier for p in packages if p.is_installed]
        if imported_packages is not None:
            installed_ids = set(installed)
            installable = [
                p.identifier for p in imported_packages if p.identifier not in installed_ids
            ]
        else:
            installable = [p.identifier for p in packages if p.is_imported and not p.is_installed]
        self._store.upsert_server_state(
            ServerStateRow(
                environment=environment,
                host=host_name,
                version=summary.version,
                jhf=summary.jhf,
                agent_build=agent_build,
                checked_at=utcnow(),
                installable=installable,
                cluster_role=cluster.role if cluster else None,
                installed=installed,
            )
        )

    # -- job submission ------------------------------------------------------------

    def _ensure_host_free(self, environment: str, host_name: str) -> None:
        """Refuse to start a new job while one is already pending/running for
        this host — two operations touching the same box's CPUSE/SSH state at
        once is unsafe. Mirrors the Management/CPUSE tab's UI, which replaces
        a busy host's selection checkbox with a status glyph for the same
        reason (see app.js markRowIfJobActive) — this is the enforcement
        behind that, since a stale page or a direct API call could otherwise
        still race two jobs onto the same host. Scoped to the environment too
        — host names are only unique within one, not globally."""
        active = self._store.list_jobs(
            targets=[host_name],
            environments=[environment],
            statuses=[JobStatus.PENDING, JobStatus.RUNNING],
            limit=1,
        )
        if active:
            raise JobError(
                f"a job is already {active[0].status.value} for {host_name!r} — wait for it "
                "to finish before starting another"
            )

    def submit_import(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        force_low_space: bool = False,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: SFTP the stored package to the host + `installer import local`.
        ``force_low_space`` carries an operator's override past a disk-space
        shortfall the UI's precheck already showed them (see
        check_import_disk_space) — it's re-verified, not trusted blindly: the
        job's own _check_disk_space still fails closed below
        _MIN_OVERRIDE_MULTIPLIER, no override can cross that floor."""
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        self._ensure_host_free(environment, host_name)
        self._packages.path_for(package_filename)  # validates record + content file
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_IMPORT,
            params={"package": package_filename, "force_low_space": force_low_space},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_import_cloud(
        self,
        environment: str,
        host_name: str,
        package_id: str,
        *,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: direct the host to fetch + `installer import` a package from
        Check Point's cloud repository by identifier. No local file or upload —
        the host needs outbound internet access."""
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        self._ensure_host_free(environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_IMPORT_CLOUD,
            params={"package_id": package_id},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_install(
        self,
        environment: str,
        host_name: str,
        package_id: str,
        *,
        confirmed: bool,
        verify_first: bool = True,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue verify+install of an imported package. ``confirmed`` must be
        True — installs can reboot a management server; the UI collects an
        explicit operator confirmation, never a default."""
        if not confirmed:
            raise JobError(
                "install requires explicit confirmation — it may reboot the management server"
            )
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        self._ensure_host_free(environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_INSTALL,
            params={"package_id": package_id, "verify_first": verify_first},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_uninstall(
        self,
        environment: str,
        host_name: str,
        package_id: str,
        *,
        confirmed: bool,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue an uninstall of a currently-installed package. ``confirmed``
        must be True — uninstalling can revert the host to a prior version and
        may reboot it, the same blast radius as install; the UI collects an
        explicit operator confirmation (typing the host's name), never a
        default."""
        if not confirmed:
            raise JobError(
                "uninstall requires explicit confirmation — it may reboot the host and "
                "reverts it to a prior version"
            )
        connector = self.registry.get(environment)
        host = connector.patchable_host(host_name)
        self._ensure_host_free(environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_UNINSTALL,
            params={"package_id": package_id},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    # -- job handlers (async wrappers over blocking SSH work) ----------------------

    async def _import_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_import, ctx)

    async def _import_cloud_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_import_cloud, ctx)

    async def _install_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_install, ctx)

    async def _uninstall_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_uninstall, ctx)

    def _do_import(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.patchable_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        force_low_space = bool(ctx.job.params.get("force_low_space", False))
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        expected_sha1 = self._packages.get(package).sha1
        hf_config = extract_hf_config(local_path)
        remote_path = posixpath.join(self._staging_dir, package)

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
            self._check_disk_space(client, local_size, ctx, override=force_low_space)

            ctx.log(f"uploading {package} ({local_size} bytes) to {host.name}:{remote_path}")
            reporter = ProgressReporter(ctx, local_size)
            remote_size = client.put(str(local_path), remote_path, progress=reporter)
            if remote_size != local_size:
                raise TransportError(
                    f"size mismatch after upload: local {local_size}, remote {remote_size}"
                )
            ctx.log("upload complete and size-verified")

            ctx.log("verifying sha1 of the uploaded copy before import")
            remote_sha1 = self._remote_sha1(client, remote_path)
            if remote_sha1 != expected_sha1.lower():
                raise TransportError(
                    f"sha1 mismatch after upload: expected {expected_sha1}, "
                    f"remote copy at {remote_path} hashes to {remote_sha1}"
                )
            ctx.log("sha1 verified — remote copy matches the stored package")

            ctx.raise_if_cancelled()  # last safe stop before mutating CPUSE state
            ctx.log("importing into CPUSE repository (installer import local)")
            cpuse = CPUSE(client, shell=self._shell)
            output = cpuse.import_local(remote_path)
            if output:
                ctx.log(f"installer import output:\n{output}")
            ctx.log(
                "import command returned — CPUSE processes it asynchronously, "
                "confirming via `show installer packages imported` before cleanup"
            )

            if not self._wait_until_imported(cpuse, package, hf_config, ctx):
                waited = self._import_verify_attempts * self._import_verify_delay
                raise JobTimedOut(
                    f"{package} still isn't listed by `show installer packages imported` "
                    f"after waiting {waited:.0f}s — NOT removing the temp copy at "
                    f"{remote_path}; CPUSE may still be processing it — use the Jobs tab's "
                    "Check status link to recheck, or verify CPUSE state on the host directly"
                )
            ctx.log("confirmed: package is listed as imported")

            # Best-effort: the import is confirmed, so a cleanup failure here
            # is a warning, not a job failure.
            cleanup = client.run(f"rm -f {remote_path}")
            if cleanup.ok:
                ctx.log(f"removed temp copy {remote_path}")
            else:
                detail = cleanup.stderr.strip() or cleanup.stdout.strip()
                ctx.log(f"could not remove temp copy {remote_path}: {detail}", level="warning")

            self._refresh_state(cpuse, ctx, host.name)
        finally:
            client.close()

    def _refresh_state(self, cpuse: CPUSE, ctx: JobContext, host_name: str) -> None:
        """Re-query and cache detected state right after a successful import,
        reusing the still-open connection, so the servers list shows the
        newly-imported package as ready to install without a separate manual
        Refresh. Best-effort — the import already succeeded, so a hiccup here
        is a warning, not a job failure."""
        ctx.log("refreshing detected state (version/JHF/packages ready to install)")
        try:
            agent_build = cpuse.agent_build()
            packages = cpuse.list_packages(PackageScope.ALL)
            imported_packages = cpuse.list_packages(PackageScope.IMPORTED)
            cluster = cpuse.cluster_state()
            self._cache_state(
                ctx.job.environment,
                host_name,
                agent_build,
                packages,
                cluster,
                imported_packages=imported_packages,
            )
            ctx.log("detected state refreshed")
        except CPUSEError as exc:
            ctx.log(f"could not refresh detected state: {exc}", level="warning")

    def _disk_space_report(self, client: Transport, local_size: int) -> list[DiskSpaceCheck]:
        """Measures free space on every required path against ``local_size``
        (the package's own size) — no upload, no CPUSE interaction. Shared by
        the synchronous UI precheck (check_import_disk_space) and the job's
        own fail-fast gate (_check_disk_space) so both apply identical
        thresholds."""
        hard_floor = int(local_size * _MIN_OVERRIDE_MULTIPLIER)
        report = []
        for path, multiplier in _DISK_CHECK_PATHS:
            available = self._free_bytes(client, path)
            required = local_size * multiplier
            ok = available >= required
            report.append(
                DiskSpaceCheck(
                    path=path,
                    multiplier=multiplier,
                    available=available,
                    required=required,
                    ok=ok,
                    override_eligible=(not ok) and available >= hard_floor,
                )
            )
        return report

    def _check_disk_space(
        self, client: Transport, local_size: int, ctx: JobContext, *, override: bool = False
    ) -> None:
        """Fail fast — before ever uploading — if the target doesn't have
        enough free space to import this package. A shortfall down to
        _MIN_OVERRIDE_MULTIPLIER (1.5x the package's own size) can be passed
        with ``override=True`` (the UI's precheck-then-confirm flow, see
        check_import_disk_space); below that floor there is no override —
        this always raises. Raises PreCheckError (never touches CPUSE state)
        whenever it fails closed."""
        for check in self._disk_space_report(client, local_size):
            if check.ok:
                ctx.log(
                    f"disk space OK on {check.path}: {_fmt_bytes(check.available)} available "
                    f"(need {_fmt_bytes(check.required)}, {check.multiplier}x the package size)"
                )
                continue
            base = (
                f"not enough free space on {check.path} to import this package: "
                f"{_fmt_bytes(check.available)} available, {_fmt_bytes(check.required)} "
                f"required ({check.multiplier}x the {_fmt_bytes(local_size)} package size)"
            )
            if not check.override_eligible:
                raise PreCheckError(
                    f"{base} — below {_MIN_OVERRIDE_MULTIPLIER}x the package size, so this "
                    "cannot be overridden — free up space and try again"
                )
            if not override:
                raise PreCheckError(
                    f"{base} — still at least {_MIN_OVERRIDE_MULTIPLIER}x the package size, "
                    "so this can be overridden if you choose to proceed anyway"
                )
            ctx.log(f"{base} — proceeding anyway (operator override confirmed)", level="warning")

    def _free_bytes(self, client: Transport, path: str) -> int:
        """Available space on ``path``, via `df -Pk` (POSIX output format —
        one line per filesystem, immune to the line-wrapping long device
        names can cause in `df`'s default format)."""
        result = client.run(f"df -Pk {shlex.quote(path)}")
        if not result.ok:
            detail = result.stderr.strip() or result.stdout.strip()
            raise TransportError(f"could not check disk space on {path}: {detail}")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        fields = lines[-1].split() if lines else []
        if len(fields) < 4:
            raise TransportError(f"unexpected `df` output for {path}: {result.stdout!r}")
        try:
            available_kb = int(fields[3])
        except ValueError as exc:
            raise TransportError(f"unexpected `df` output for {path}: {result.stdout!r}") from exc
        return available_kb * 1024

    def _remote_sha1(self, client: Transport, remote_path: str) -> str:
        """sha1 of the just-uploaded file, computed on the host itself — catches
        a corrupted/truncated transfer before `installer import` ever runs
        (the size check alone wouldn't notice bit-level corruption)."""
        result = client.run(f"sha1sum {remote_path}")
        if not result.ok:
            detail = result.stderr.strip() or result.stdout.strip()
            raise TransportError(f"could not compute remote sha1 for {remote_path}: {detail}")
        digest = result.stdout.split()[0] if result.stdout.split() else ""
        if not digest:
            raise TransportError(
                f"unexpected `sha1sum` output for {remote_path}: {result.stdout!r}"
            )
        return digest.lower()

    def _wait_until_imported(
        self, cpuse: CPUSE, package_filename: str, hf_config: HfConfig | None, ctx: JobContext
    ) -> bool:
        """Poll `show installer packages imported` for the just-uploaded file,
        via ``_is_imported_now`` (also used by ``recheck_import`` for a single
        manual check after a timeout). The "still waiting" line is
        overwritten in place each attempt (``ctx.log(..., replace=...)``)
        rather than appended — a slow import can take dozens of attempts,
        and a hundred near-identical lines just buries the one that matters
        under scrolling; the operator still sees the current attempt count
        and a live timestamp, just as one line, not one per poll."""
        progress_seq: int | None = None
        for attempt in range(1, self._import_verify_attempts + 1):
            if _is_imported_now(cpuse, package_filename, hf_config):
                return True
            if attempt < self._import_verify_attempts:
                event = ctx.log(
                    f"not yet listed as imported (check {attempt}/{self._import_verify_attempts}) "
                    "— waiting",
                    replace=progress_seq,
                )
                progress_seq = event.seq
                time.sleep(self._import_verify_delay)
        return False

    def recheck_import(
        self, job_id: str, *, credentials: CredentialBundle | None = None
    ) -> JobRecord:
        """Manual one-shot recheck for an import job the automatic poll gave
        up on (TIMED_OUT) — the Jobs tab's "Check status" link. One more live
        `show installer packages imported` look: if the package now shows up,
        resolves the job to SUCCEEDED, removes the temp copy staged on the
        host, and refreshes cached state, matching the automatic path in
        _do_import. If it still doesn't, the job is left TIMED_OUT and the
        negative result is just logged — the operator can try again later.
        Blocking (SSH) — call via ``asyncio.to_thread`` from async contexts."""
        job = self._store.get_job(job_id)
        if job.kind != JOB_IMPORT:
            raise JobError(f"job {job_id!r} is not an import job (kind: {job.kind})")
        if job.status != JobStatus.TIMED_OUT:
            raise JobError(
                f"job {job_id!r} isn't timed out (status: {job.status.value}) — nothing to recheck"
            )

        connector = self.registry.get(job.environment)
        host = connector.patchable_host(job.target or "")
        creds = connector.require_credentials(host, credentials)
        package = str(job.params["package"])
        local_path = self._packages.path_for(package)
        hf_config = extract_hf_config(local_path)
        remote_path = posixpath.join(self._staging_dir, package)

        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            if not _is_imported_now(cpuse, package, hf_config):
                self._store.append_event(job_id, "manual check: still not listed as imported")
                return self._store.get_job(job_id)

            self._store.append_event(
                job_id, "manual check: confirmed package is listed as imported"
            )
            cleanup = client.run(f"rm -f {remote_path}")
            if cleanup.ok:
                self._store.append_event(job_id, f"removed temp copy {remote_path}")
            else:
                detail = cleanup.stderr.strip() or cleanup.stdout.strip()
                self._store.append_event(
                    job_id, f"could not remove temp copy {remote_path}: {detail}", level="warning"
                )
            try:
                agent_build = cpuse.agent_build()
                packages = cpuse.list_packages(PackageScope.ALL)
                cluster = cpuse.cluster_state()
                self._cache_state(job.environment, host.name, agent_build, packages, cluster)
                self._store.append_event(job_id, "detected state refreshed")
            except CPUSEError as exc:
                self._store.append_event(
                    job_id, f"could not refresh detected state: {exc}", level="warning"
                )
            self._store.finish_job(job_id, JobStatus.SUCCEEDED)
            return self._store.get_job(job_id)
        finally:
            client.close()

    def _do_import_cloud(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.patchable_host(ctx.job.target or "")
        package_id = str(ctx.job.params["package_id"])

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
            ctx.log(f"importing {package_id} from Check Point's cloud (installer import)")
            cpuse = CPUSE(client, shell=self._shell)
            cpuse.import_cloud(package_id)
            ctx.log("import finished")
            self._refresh_state(cpuse, ctx, host.name)
        finally:
            client.close()

    def _do_install(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.patchable_host(ctx.job.target or "")
        package_id = str(ctx.job.params["package_id"])
        verify_first = bool(ctx.job.params.get("verify_first", True))

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            if verify_first:
                ctx.log(f"verifying {package_id} (installer verify)")
                output = cpuse.verify(package_id)
                if output:
                    ctx.log(f"installer verify output:\n{output}")
                ctx.log("verify passed")
            ctx.raise_if_cancelled()  # last safe stop; install may reboot the host
            ctx.log(f"installing {package_id} — host may reboot when this completes")
            output = cpuse.install(package_id)
            if output:
                ctx.log(f"installer install output:\n{output}")
            ctx.log(
                "install command returned — CPUSE installs asynchronously, confirming "
                "via `show installer package` before declaring success"
            )
        finally:
            client.close()

        installed, last_detail = self._wait_until_installed(connector, host, creds, package_id, ctx)
        if last_detail.installation_log:
            self._capture_install_log(connector, host, creds, last_detail.installation_log, ctx)
        if not installed:
            raise CPUSEError(
                f"{package_id} does not show as Installed via `show installer package "
                f"{package_id}` after waiting (last status: {last_detail.status!r}) — check "
                "CPUSE state on the host; the install may have failed, still be in progress, "
                f"or be waiting on a reboot. Last known detail:\n{last_detail.raw}"
            )
        ctx.log(f"confirmed: package is installed (status: {last_detail.status!r})")

        ctx.log("refreshing detected state (version/JHF/packages ready to install)")
        try:
            self.detect(ctx.job.environment, host.name, credentials=creds)
            ctx.log("detected state refreshed")
        except OrchestratorError as exc:
            ctx.log(f"could not refresh detected state: {exc}", level="warning")

    def _do_uninstall(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.patchable_host(ctx.job.target or "")
        package_id = str(ctx.job.params["package_id"])

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            ctx.raise_if_cancelled()  # last safe stop; uninstall may reboot the host
            ctx.log(f"uninstalling {package_id} — host may reboot when this completes")
            output = cpuse.uninstall(package_id)
            if output:
                ctx.log(f"installer uninstall output:\n{output}")
            ctx.log(
                "uninstall command returned — CPUSE processes it asynchronously, "
                "confirming via `show installer packages` before declaring success"
            )
        finally:
            client.close()

        uninstalled, last_detail = self._wait_until_uninstalled(
            connector, host, creds, package_id, ctx
        )
        if not uninstalled:
            status = last_detail.status if last_detail else "unknown"
            raise CPUSEError(
                f"{package_id} still shows as Installed via `show installer packages` "
                f"after waiting (last status: {status!r}) — check CPUSE state on the "
                "host; the uninstall may have failed, still be in progress, or be "
                "waiting on a reboot"
            )
        ctx.log(f"confirmed: {package_id} is no longer installed")

        ctx.log("refreshing detected state (version/JHF/packages ready to install)")
        try:
            self.detect(ctx.job.environment, host.name, credentials=creds)
            ctx.log("detected state refreshed")
        except OrchestratorError as exc:
            ctx.log(f"could not refresh detected state: {exc}", level="warning")

    def _wait_until_uninstalled(
        self,
        connector: HostConnector,
        host: Host,
        creds: CredentialBundle | None,
        package_id: str,
        ctx: JobContext,
    ) -> tuple[bool, PackageState | None]:
        """Poll `show installer packages all` until package_id no longer shows
        as Installed — absent from the list entirely counts too, since some
        package types drop out of it once uninstalled rather than reverting
        to Imported. Uses the list query (like _wait_until_imported) rather
        than the single-package detail view (`show installer package <id>`,
        as _wait_until_installed uses), since that command's own failure mode
        for an unknown identifier is unconfirmed and this needs to tolerate
        the id disappearing outright. Same reboot-tolerant reconnect behavior
        as _wait_until_installed — a package whose install required a reboot
        commonly needs one to revert too, so a dropped connection mid-poll
        reconnects and keeps waiting instead of failing closed."""
        client: Transport | None = None
        last_detail: PackageState | None = None
        last_logged_status: str | None = None
        try:
            for attempt in range(1, self._install_verify_attempts + 1):
                will_continue = attempt < self._install_verify_attempts
                try:
                    if client is None:
                        client = connector.connect(host, creds)
                    packages = CPUSE(client, shell=self._shell).list_packages(PackageScope.ALL)
                except TransportError as exc:
                    ctx.log(
                        f"lost contact checking uninstall status (expected mid-reboot): {exc}",
                        level="warning",
                    )
                    client = None
                    if will_continue:
                        time.sleep(self._install_verify_delay)
                    continue
                except CPUSEError as exc:
                    ctx.log(f"could not read uninstall status yet: {exc}", level="warning")
                    if will_continue:
                        time.sleep(self._install_verify_delay)
                    continue

                match = next((p for p in packages if p.identifier == package_id), None)
                last_detail = match
                if match is None or not match.is_installed:
                    ctx.log(
                        f"uninstall complete: {package_id!r} is now "
                        f"{match.status if match else 'no longer listed'}"
                    )
                    return True, last_detail

                if match.status != last_logged_status:
                    ctx.log(f"status: {match.status}")
                    last_logged_status = match.status
                if will_continue:
                    time.sleep(self._install_verify_delay)
            return False, last_detail
        finally:
            if client is not None:
                client.close()

    def _wait_until_installed(
        self,
        connector: HostConnector,
        host: Host,
        creds: CredentialBundle | None,
        package_id: str,
        ctx: JobContext,
    ) -> tuple[bool, PackageState]:
        """Poll `show installer package <id>` until Status shows Installed.
        Manages its own connection independently of the caller's, since a
        reboot-required install drops the SSH session partway through —
        expected, not a failure, so a dropped connection reconnects and keeps
        waiting rather than failing closed. A CPUSE-level read failure (the
        connection is fine, the command just didn't succeed) retries without
        reconnecting.

        Gives up early — before the full attempts budget — if Status is still
        "Imported" (i.e. the install doesn't appear to have started at all)
        after ``install_stall_seconds``; a genuinely running install moves off
        "Imported" well before then, so there's no reason to wait out the
        full 15 minutes for one that never started. But once Status carries a
        percentage (real install progress, e.g. "Installing 45%"), the
        attempts budget is dropped entirely — operator-directed: a real
        install can legitimately run well past 15 minutes, so from that point
        on this polls every ``install_verify_delay`` seconds indefinitely,
        until it completes (or the connection drops for a reboot and
        reconnects, above).

        Logs just the Status line — with its own timestamp, like every job
        log line — on each check; the full `show installer package <id>`
        block is only logged once, at the end, when Status finally shows
        Installed (or in the raised error if it never does), rather than
        repeating it on every poll. A status line is only logged when it
        actually changed from the last one (operator-directed, 2026-07-23) —
        otherwise a long install sitting at the same percentage for many
        checks in a row would print that same line every 30s for no reason."""
        client: Transport | None = None
        last_detail = PackageState(package_id, "")
        last_logged_status: str | None = None
        started = time.monotonic()
        uncapped = False
        attempt = 0
        try:
            while uncapped or attempt < self._install_verify_attempts:
                attempt += 1
                will_continue = uncapped or attempt < self._install_verify_attempts
                try:
                    if client is None:
                        client = connector.connect(host, creds)
                    detail = CPUSE(client, shell=self._shell).package_detail(package_id)
                except TransportError as exc:
                    ctx.log(
                        f"lost contact checking install status (expected mid-reboot): {exc}",
                        level="warning",
                    )
                    client = None
                    if will_continue:
                        time.sleep(self._install_verify_delay)
                    continue
                except CPUSEError as exc:
                    ctx.log(f"could not read install status yet: {exc}", level="warning")
                    if will_continue:
                        time.sleep(self._install_verify_delay)
                    continue

                last_detail = detail
                if detail.is_installed:
                    ctx.log(f"install complete:\n{detail.raw}")
                    return True, last_detail

                if detail.status != last_logged_status:
                    ctx.log(f"status: {detail.status}")
                    last_logged_status = detail.status
                if "%" in detail.status:
                    uncapped = True

                if not uncapped:
                    elapsed = time.monotonic() - started
                    stalled = detail.status.strip().lower().startswith("imported")
                    if stalled and elapsed >= self._install_stall_seconds:
                        ctx.log(
                            f"status is still {detail.status!r} after {elapsed:.0f}s — the "
                            "install doesn't appear to have started; giving up rather than "
                            "waiting out the full timeout",
                            level="warning",
                        )
                        return False, last_detail

                if uncapped or attempt < self._install_verify_attempts:
                    time.sleep(self._install_verify_delay)
            return False, last_detail
        finally:
            if client is not None:
                client.close()

    def _capture_install_log(
        self,
        connector: HostConnector,
        host: Host,
        creds: CredentialBundle | None,
        path: str,
        ctx: JobContext,
    ) -> None:
        """Copy CPUSE's own install log file into our DB (JobRecord.install_log)
        instead of just noting its path — the path is only useful while the
        file still exists on the box; once CPUSE rotates or deletes it, a bare
        path is worthless for later troubleshooting. Best-effort: a failure
        here is a warning, not a job failure, since the install itself has
        already succeeded or failed independently of this."""
        path = path.strip()
        if not path or path.upper() == "N/A" or not path.startswith("/"):
            return
        try:
            client = connector.connect(host, creds)
        except OrchestratorError as exc:
            ctx.log(f"could not connect to capture installation log: {exc}", level="warning")
            return
        try:
            result = client.run(f"cat {shlex.quote(path)}")
        finally:
            client.close()
        if not result.ok:
            detail = result.stderr.strip() or result.stdout.strip()
            ctx.log(f"could not read installation log at {path}: {detail}", level="warning")
            return
        text = result.stdout
        if len(text) > _INSTALL_LOG_MAX_BYTES:
            text = text[:_INSTALL_LOG_MAX_BYTES] + (
                f"\n... truncated at {_INSTALL_LOG_MAX_BYTES} bytes"
            )
        self._store.set_install_log(ctx.job.id, text, path)
        ctx.log(f"captured installation log from {path} ({len(text)} bytes)")


class ProgressReporter:
    """Paramiko progress callback that logs at ~10% steps, not every chunk."""

    def __init__(self, ctx: JobContext, total: int) -> None:
        self._ctx = ctx
        self._total = max(total, 1)
        self._last_decile = 0

    def __call__(self, transferred: int, _total: int) -> None:
        decile = (transferred * 10) // self._total
        if decile > self._last_decile:
            self._last_decile = decile
            self._ctx.log(f"upload progress: {min(decile * 10, 100)}%")
