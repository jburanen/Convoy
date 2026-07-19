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
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from ..cpuse import CPUSE, DEFAULT_STAGING_DIR, GaiaShell, PackageScope, PackageState
from ..credentials import Credential, CredentialKind, CredentialStore
from ..errors import CredentialError, InventoryError, JobError, TransportError
from ..inventory import Host, Inventory, Role
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord
from ..transport.ssh import CommandResult, SSHClient

JOB_IMPORT = "mgmt.import"
JOB_INSTALL = "mgmt.install"

_MGMT_ROLES = (Role.MANAGEMENT, Role.MDS)


class Transport(Protocol):
    """What a patching operation needs from a connection. ``SSHClient``
    satisfies it; tests substitute fakes."""

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult: ...

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int: ...

    def close(self) -> None: ...


ClientFactory = Callable[[Host, dict[CredentialKind, Credential]], Transport]


def _default_client_factory(host: Host, creds: dict[CredentialKind, Credential]) -> Transport:
    key = creds.get(CredentialKind.SSH_PRIVATE_KEY)
    password = creds.get(CredentialKind.SSH_PASSWORD)
    client = SSHClient(
        host,
        password=password.reveal() if password else None,
        private_key=key.reveal() if key else None,
    )
    client.connect()
    return client


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
    ) -> None:
        self.inventory = inventory
        self.runner = runner
        self._credentials = credentials
        self._packages = packages
        self._staging_dir = staging_dir
        self._shell = shell
        self._client_factory = client_factory or _default_client_factory
        runner.register(JOB_IMPORT, self._import_job)
        runner.register(JOB_INSTALL, self._install_job)

    # -- queries -----------------------------------------------------------------

    def management_servers(self) -> list[Host]:
        return [h for role in _MGMT_ROLES for h in self.inventory.hosts_by_role(role)]

    def credential_kinds(self, host_name: str) -> list[str]:
        """Which credential kinds are stored for a host (secret-free)."""
        if self._credentials is None:
            return []
        return [info.kind.value for info in self._credentials.list() if info.host == host_name]

    def detect(self, host_name: str) -> DetectedState:
        """Live-query CPUSE state. Blocking (SSH) — call via ``asyncio.to_thread``
        from async contexts. Always detected state, never assumed."""
        host = self._mgmt_host(host_name)
        self._require_ssh_credential(host)
        client = self._connect(host)
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
        host = self._mgmt_host(host_name)
        self._require_ssh_credential(host)
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
        host = self._mgmt_host(host_name)
        self._require_ssh_credential(host)
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
        host = self._mgmt_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        remote_path = posixpath.join(self._staging_dir, package)

        client = self._connect(host)
        try:
            ctx.log(f"uploading {package} ({local_size} bytes) to {host.name}:{remote_path}")
            reporter = _ProgressReporter(ctx, local_size)
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
        host = self._mgmt_host(ctx.job.target or "")
        package_id = str(ctx.job.params["package_id"])
        verify_first = bool(ctx.job.params.get("verify_first", True))

        client = self._connect(host)
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

    # -- plumbing ------------------------------------------------------------------

    def _mgmt_host(self, host_name: str) -> Host:
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role not in _MGMT_ROLES:
            raise InventoryError(
                f"host {host_name!r} is a {host.role.value}, not a management server — "
                "gateways are patched via CDT, not this flow"
            )
        return host

    def _require_ssh_credential(self, host: Host) -> None:
        creds = self._host_credentials(host)
        if CredentialKind.SSH_PASSWORD not in creds and CredentialKind.SSH_PRIVATE_KEY not in creds:
            raise CredentialError(
                f"no SSH credential stored for {host.name!r} — add an ssh_password "
                "or ssh_private_key credential first"
            )

    def _host_credentials(self, host: Host) -> dict[CredentialKind, Credential]:
        if self._credentials is None:
            raise CredentialError(
                "credential store is locked — set the master key and restart the service"
            )
        creds = self._credentials.for_host(host.name)
        if not creds:
            creds = self._credentials.for_host("*")  # fleet-wide default, if any
        return creds

    def _connect(self, host: Host) -> Transport:
        return self._client_factory(host, self._host_credentials(host))


class _ProgressReporter:
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
