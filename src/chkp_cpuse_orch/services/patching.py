"""Management-server patching service (the CPUSE-local subsystem).

Glues inventory + credential store + package store + CPUSE wrapper + job runner
into the operations the web UI exposes per management server:

- **detect**  — live `show installer packages` (source of truth for the UI)
- **import**  — SFTP the package to the host, then `installer import local`
- **install** — optional `installer verify`, then `installer install`

Each mutating operation runs as a background job (a web click enqueues and
returns). Blocking SSH work runs in a worker thread via ``asyncio.to_thread``.
Install may reboot the host, so it additionally requires an explicit operator
confirmation flag — full HA-peer gating arrives with checks.py. See
.claude/memory/patching-web-design.md and safety-constraints.md.
"""

from __future__ import annotations

import asyncio
import posixpath
from dataclasses import dataclass, field

from ..cpuse import CPUSE, DEFAULT_STAGING_DIR, GaiaShell, PackageScope, PackageState
from ..credentials import CredentialStore
from ..errors import JobError, TransportError
from ..inventory import Host, Inventory
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord
from .common import ClientFactory, HostConnector, Transport

__all__ = ["JOB_IMPORT", "JOB_INSTALL", "ClientFactory", "PatchingService", "Transport"]

JOB_IMPORT = "mgmt.import"
JOB_INSTALL = "mgmt.install"


@dataclass
class DetectedState:
    """Live CPUSE state of one host, as the UI shows it."""

    host: str
    agent_build: str = ""
    packages: list[PackageState] = field(default_factory=list)


class PatchingService:
    """Per-management-server CPUSE operations over the shared core."""

    def __init__(
        self,
        *,
        inventory: Inventory,
        credentials: CredentialStore | None,
        packages: PackageStore,
        runner: JobRunner,
        staging_dir: str = DEFAULT_STAGING_DIR,
        shell: GaiaShell = GaiaShell.EXPERT,
        client_factory: ClientFactory | None = None,
        connector: HostConnector | None = None,
    ) -> None:
        self.runner = runner
        self.connector = connector or HostConnector(inventory, credentials, client_factory)
        self._packages = packages
        self._staging_dir = staging_dir
        self._shell = shell
        runner.register(JOB_IMPORT, self._import_job)
        runner.register(JOB_INSTALL, self._install_job)

    # -- queries -----------------------------------------------------------------

    def management_servers(self) -> list[Host]:
        return self.connector.management_servers()

    def credential_kinds(self, host_name: str) -> list[str]:
        return self.connector.credential_kinds(host_name)

    def detect(self, host_name: str) -> DetectedState:
        """Live-query CPUSE state. Blocking (SSH) — call via ``asyncio.to_thread``
        from async contexts. Always detected state, never assumed."""
        host = self.connector.mgmt_host(host_name)
        self.connector.require_ssh_credential(host)
        client = self.connector.connect(host)
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

    def submit_import(self, host_name: str, package_filename: str) -> JobRecord:
        """Enqueue: SFTP the stored package to the host + `installer import local`."""
        host = self.connector.mgmt_host(host_name)
        self.connector.require_ssh_credential(host)
        self._packages.path_for(package_filename)  # validates record + content file
        return self.runner.submit(
            JOB_IMPORT, target=host.name, params={"package": package_filename}
        )

    def submit_install(
        self, host_name: str, package_id: str, *, confirmed: bool, verify_first: bool = True
    ) -> JobRecord:
        """Enqueue verify+install of an imported package. ``confirmed`` must be
        True — installs can reboot a management server; the UI collects an
        explicit operator confirmation, never a default."""
        if not confirmed:
            raise JobError(
                "install requires explicit confirmation — it may reboot the management server"
            )
        host = self.connector.mgmt_host(host_name)
        self.connector.require_ssh_credential(host)
        return self.runner.submit(
            JOB_INSTALL,
            target=host.name,
            params={"package_id": package_id, "verify_first": verify_first},
        )

    # -- job handlers (async wrappers over blocking SSH work) ----------------------

    async def _import_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_import, ctx)

    async def _install_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_install, ctx)

    def _do_import(self, ctx: JobContext) -> None:
        host = self.connector.mgmt_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        remote_path = posixpath.join(self._staging_dir, package)

        client = self.connector.connect(host)
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
            CPUSE(client, shell=self._shell).import_local(remote_path)
            ctx.log("import finished")
        finally:
            client.close()

    def _do_install(self, ctx: JobContext) -> None:
        host = self.connector.mgmt_host(ctx.job.target or "")
        package_id = str(ctx.job.params["package_id"])
        verify_first = bool(ctx.job.params.get("verify_first", True))

        client = self.connector.connect(host)
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
