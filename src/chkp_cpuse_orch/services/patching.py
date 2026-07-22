"""Management-server patching service (the CPUSE-local subsystem).

Glues inventory + credential store + package store + CPUSE wrapper + job runner
into the operations the web UI exposes per management server:

- **detect**        — live `show installer packages` (source of truth for the UI)
- **import**        — SFTP the package to a temp path on the host, `installer
  import local`, then remove the temp copy. `installer import local` returns
  before CPUSE has actually finished importing (it processes the file
  asynchronously — "determining package type" → "examining the file" → ...) —
  removing the temp file right after the command returns raced that and
  produced a job that reported success while CPUSE itself then failed with
  "package file is missing" (observed 2026-07-22). So: poll `show installer
  packages imported` until the package actually appears before cleaning up
  and declaring the job successful.
- **import_cloud**  — direct the host to fetch + import a package from Check
  Point's cloud repository by identifier; no local file involved
- **install**        — optional `installer verify`, then `installer install`

Each mutating operation runs as a background job (a web click enqueues and
returns). Blocking SSH work runs in a worker thread via ``asyncio.to_thread``.
Install may reboot the host, so it additionally requires an explicit operator
confirmation flag — full HA-peer gating arrives with checks.py. See
.claude/memory/patching-web-design.md and safety-constraints.md.
"""

from __future__ import annotations

import asyncio
import posixpath
import time
from dataclasses import dataclass, field

from ..cpuse import CPUSE, DEFAULT_STAGING_DIR, GaiaShell, PackageScope, PackageState
from ..credentials import CredentialBundle, JobCredentialVault
from ..errors import CPUSEError, JobError, TransportError
from ..inventory import Host
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord
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

JOB_IMPORT = "mgmt.import"
JOB_IMPORT_CLOUD = "mgmt.import_cloud"
JOB_INSTALL = "mgmt.install"


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
        staging_dir: str = DEFAULT_STAGING_DIR,
        shell: GaiaShell = GaiaShell.EXPERT,
        import_verify_attempts: int = 60,
        import_verify_delay: float = 5.0,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self._packages = packages
        self._vault = vault
        self._staging_dir = staging_dir
        self._shell = shell
        # How long we're willing to poll `show installer packages imported`
        # for the just-uploaded package to actually show up, before giving up
        # (60 * 5s = 5 minutes) — see the module docstring for why this exists.
        self._import_verify_attempts = import_verify_attempts
        self._import_verify_delay = import_verify_delay
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
        from async contexts. Always detected state, never assumed.

        ``credentials`` are used one-shot (never stored) when the environment
        does not persist credentials; ignored when it does."""
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        creds = connector.require_credentials(host, credentials)
        client = connector.connect(host, creds)
        try:
            cpuse = CPUSE(client, shell=self._shell)
            return DetectedState(
                host=host.name,
                agent_build=cpuse.agent_build(),
                packages=cpuse.list_packages(PackageScope.ALL),
            )
        finally:
            client.close()

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

            ctx.raise_if_cancelled()  # last safe stop before mutating CPUSE state
            ctx.log("importing into CPUSE repository (installer import local)")
            cpuse = CPUSE(client, shell=self._shell)
            cpuse.import_local(remote_path)
            ctx.log(
                "import command returned — CPUSE processes it asynchronously, "
                "confirming via `show installer packages imported` before cleanup"
            )

            if not self._wait_until_imported(cpuse, package, ctx):
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
        finally:
            client.close()

    def _wait_until_imported(self, cpuse: CPUSE, package_filename: str, ctx: JobContext) -> bool:
        """Poll `show installer packages imported` for the just-uploaded file.
        Matches by exact identifier or by its filename stem, since CPUSE's
        parsed identifier is usually the filename itself but formatting has
        drifted across Gaia versions (see cpuse.parse_packages)."""
        stem = package_filename.rsplit(".", 1)[0]
        for attempt in range(1, self._import_verify_attempts + 1):
            imported = cpuse.list_packages(PackageScope.IMPORTED)
            if any(p.identifier == package_filename or stem in p.identifier for p in imported):
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
            CPUSE(client, shell=self._shell).import_cloud(package_id)
            ctx.log("import finished")
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
                cpuse.verify(package_id)
                ctx.log("verify passed")
            ctx.raise_if_cancelled()  # last safe stop; install may reboot the host
            ctx.log(f"installing {package_id} — host may reboot when this completes")
            cpuse.install(package_id)
            ctx.log("install command finished — re-detect state to confirm")
        finally:
            client.close()


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
