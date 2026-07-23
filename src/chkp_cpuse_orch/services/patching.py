"""Management-server patching service (the CPUSE-local subsystem).

Glues inventory + credential store + package store + CPUSE wrapper + job runner
into the operations the web UI exposes per management server:

- **detect**        — live `show installer packages` (source of truth for the UI)
- **import**        — SFTP the package to a temp path on the host, verify its
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
  uploaded filename (e.g. "R82.10 Jumbo Hotfix Accumulator Take 24").
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
from ..errors import CPUSEError, JobError, OrchestratorError, TransportError
from ..hfconfig import HfConfig, extract_hf_config
from ..inventory import Host
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord, ServerStateRow, Store, utcnow
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
    "ClientFactory",
    "EnvironmentRegistry",
    "HostConnector",
    "PatchingService",
    "Transport",
]

JOB_IMPORT = "cpuse.import"
JOB_IMPORT_CLOUD = "cpuse.import_cloud"
JOB_INSTALL = "cpuse.install"

# Generous cap on captured install-log content — CPUSE logs are normally KBs,
# this just bounds a pathological case from bloating the DB / archive file.
_INSTALL_LOG_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class DetectedState:
    """Live CPUSE state of one host, as the UI shows it."""

    host: str
    agent_build: str = ""
    packages: list[PackageState] = field(default_factory=list)


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
        import_verify_attempts: int = 60,
        import_verify_delay: float = 5.0,
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
        # (60 * 5s = 5 minutes) — see the module docstring for why this exists.
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

    # -- queries -----------------------------------------------------------------

    def management_servers(self, environment: str) -> list[Host]:
        return self.registry.get(environment).management_servers()

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
        host = connector.mgmt_host(host_name)
        creds = connector.require_credentials(host, credentials)
        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            agent_build = cpuse.agent_build()
            packages = cpuse.list_packages(PackageScope.ALL)
            self._cache_state(environment, host.name, agent_build, packages)
            return DetectedState(host=host.name, agent_build=agent_build, packages=packages)
        finally:
            client.close()

    def _cache_state(
        self, environment: str, host_name: str, agent_build: str, packages: list[PackageState]
    ) -> None:
        """Derive the UI's summary (version/JHF, packages ready to install)
        from detected packages and persist it — shared by ``detect()`` (an
        explicit Refresh) and both import job handlers (an automatic refresh
        right after a successful import, reusing the same open connection)."""
        summary = summarize_jumbo(packages)
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
            )
        )

    # -- job submission ------------------------------------------------------------

    def submit_import(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> JobRecord:
        """Enqueue: SFTP the stored package to the host + `installer import local`."""
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        self._packages.path_for(package_filename)  # validates record + content file
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_IMPORT,
            params={"package": package_filename},
            credentials=credentials,
        )

    def submit_import_cloud(
        self,
        environment: str,
        host_name: str,
        package_id: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> JobRecord:
        """Enqueue: direct the host to fetch + `installer import` a package from
        Check Point's cloud repository by identifier. No local file or upload —
        the host needs outbound internet access."""
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_IMPORT_CLOUD,
            params={"package_id": package_id},
            credentials=credentials,
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
    ) -> JobRecord:
        """Enqueue verify+install of an imported package. ``confirmed`` must be
        True — installs can reboot a management server; the UI collects an
        explicit operator confirmation, never a default."""
        if not confirmed:
            raise JobError(
                "install requires explicit confirmation — it may reboot the management server"
            )
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_INSTALL,
            params={"package_id": package_id, "verify_first": verify_first},
            credentials=credentials,
        )

    # -- job handlers (async wrappers over blocking SSH work) ----------------------

    async def _import_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_import, ctx)

    async def _import_cloud_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_import_cloud, ctx)

    async def _install_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_install, ctx)

    def _do_import(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.mgmt_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        expected_sha1 = self._packages.get(package).sha1
        hf_config = extract_hf_config(local_path)
        remote_path = posixpath.join(self._staging_dir, package)

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
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
                raise CPUSEError(
                    f"{package} still isn't listed by `show installer packages imported` "
                    f"after waiting — NOT removing the temp copy at {remote_path}; check "
                    "CPUSE state on the host and re-import if needed"
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
            self._cache_state(ctx.job.environment, host_name, agent_build, packages)
            ctx.log("detected state refreshed")
        except CPUSEError as exc:
            ctx.log(f"could not refresh detected state: {exc}", level="warning")

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
        """Poll `show installer packages imported` for the just-uploaded file.
        A candidate matches if *either* its identifier is (or contains the
        stem of) the uploaded filename, *or* — since CPUSE renders some
        package types (JHFs) as a human-readable string unrelated to the
        filename, e.g. "R82.10 Jumbo Hotfix Accumulator Take 24" — its
        identifier's own version+Take equal the ones recorded in the
        package's hf.config. Either check alone can mismatch depending on
        the package type, so both run and either is sufficient."""
        stem = package_filename.rsplit(".", 1)[0]
        expect_version = hf_config.direct_base_version if hf_config else None
        expect_take = hf_config.take_number if hf_config else None
        for attempt in range(1, self._import_verify_attempts + 1):
            imported = cpuse.list_packages(PackageScope.IMPORTED)
            for pkg in imported:
                if pkg.identifier == package_filename or stem in pkg.identifier:
                    return True
                if (
                    expect_version is not None
                    and expect_take is not None
                    and cpuse_extract_version(pkg.identifier) == expect_version
                    and cpuse_extract_take(pkg.identifier) == expect_take
                ):
                    return True
            if attempt < self._import_verify_attempts:
                ctx.log(
                    f"not yet listed as imported (check {attempt}/{self._import_verify_attempts}) "
                    "— waiting"
                )
                time.sleep(self._import_verify_delay)
        return False

    def _do_import_cloud(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.mgmt_host(ctx.job.target or "")
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
        host = connector.mgmt_host(ctx.job.target or "")
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
        repeating it on every poll."""
        client: Transport | None = None
        last_detail = PackageState(package_id, "")
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

                ctx.log(f"status: {detail.status}")
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
        self._store.set_install_log(ctx.job.id, text)
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
