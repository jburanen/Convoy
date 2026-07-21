"""Shared plumbing for service-core modules: how to reach a management server.

Both the CPUSE-local subsystem (patching.py) and the CDT subsystem (cdt_ops.py)
connect to management servers the same way: resolve the host from inventory,
require the SSH credential from the named credential set assigned to that server,
and open a transport via a swappable factory (tests inject fakes).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ..credentials import (
    Credential,
    CredentialBundle,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
    ensure_ssh_credential,
)
from ..errors import CredentialError, InventoryError
from ..inventory import MANAGEMENT_PLANE_ROLES, Host, Inventory
from ..jobs import JobRunner
from ..store import JobRecord, new_id
from ..transport.ssh import CommandResult, SSHClient

_MGMT_ROLES = MANAGEMENT_PLANE_ROLES


class Transport(Protocol):
    """What an operation needs from a connection. ``SSHClient`` satisfies it;
    tests substitute fakes."""

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


def default_client_factory(host: Host, creds: dict[CredentialKind, Credential]) -> Transport:
    key = creds.get(CredentialKind.SSH_PRIVATE_KEY)
    password = creds.get(CredentialKind.SSH_PASSWORD)
    client = SSHClient(
        host,
        password=password.reveal() if password else None,
        private_key=key.reveal() if key else None,
    )
    client.connect()
    return client


class HostConnector:
    """Inventory + credentials + factory → connected transports to mgmt servers.
    One connector per environment; credential lookups stay inside it."""

    def __init__(
        self,
        inventory: Inventory,
        credentials: CredentialStore | None,
        client_factory: ClientFactory | None = None,
        environment: str = "default",
        *,
        credential_storage_enabled: bool = True,
        is_mds: bool = False,
    ) -> None:
        self.inventory = inventory
        self.environment = environment
        self.credential_storage_enabled = credential_storage_enabled
        # Declared once per environment (see services/environments.py) — an
        # environment is either an SMS estate or a Multi-Domain one, never both.
        # Command selection (e.g. discovery) reads this instead of guessing from
        # whichever host happens to be the primary.
        self.is_mds = is_mds
        self._credentials = credentials
        self._client_factory = client_factory or default_client_factory

    def management_servers(self) -> list[Host]:
        return [h for role in _MGMT_ROLES for h in self.inventory.hosts_by_role(role)]

    def mgmt_host(self, host_name: str) -> Host:
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role not in _MGMT_ROLES:
            raise InventoryError(
                f"host {host_name!r} is a {host.role.value}, not a management server — "
                "gateways are patched via CDT, not addressed directly"
            )
        return host

    def assigned_credential(self, host_name: str) -> str | None:
        """Name of the credential set assigned to a server (secret-free), or None.
        Always None for a storage-disabled environment — nothing is persisted."""
        if self._credentials is None or not self.credential_storage_enabled:
            return None
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.credential_set_id is None:
            return None
        return self._credentials.set_name(host.credential_set_id)

    def require_ssh_credential(self, host: Host) -> None:
        creds = self.host_credentials(host)  # raises if unassigned / store locked
        if CredentialKind.SSH_PASSWORD not in creds and CredentialKind.SSH_PRIVATE_KEY not in creds:
            raise CredentialError(
                f"the credential set assigned to {host.name!r} has no SSH password or "
                "private key — edit the set on the Provisioning tab"
            )

    def require_credentials(
        self, host: Host, provided: CredentialBundle | None = None
    ) -> CredentialBundle | None:
        """Gate an SSH operation and decide the credential source.

        - storage enabled  → verify a stored SSH credential exists; return None,
          meaning ``connect`` resolves from the store.
        - storage disabled → validate the caller-``provided`` bundle and return
          it, to be passed straight to ``connect`` (never persisted).
        """
        if self.credential_storage_enabled:
            self.require_ssh_credential(host)
            return None
        bundle = provided or {}
        ensure_ssh_credential(bundle, host.name, self.environment)
        return bundle

    def host_credentials(self, host: Host) -> CredentialBundle:
        if self._credentials is None:
            raise CredentialError(
                "credential store is locked — set the master key and restart the service"
            )
        if host.credential_set_id is None:
            raise CredentialError(
                f"no credential assigned to {host.name!r} in environment "
                f"{self.environment!r} — assign a credential set on the Management tab"
            )
        return self._credentials.get_set_bundle(host.credential_set_id, host.name)

    def connect(self, host: Host, creds: CredentialBundle | None = None) -> Transport:
        """Open a transport. ``creds`` supplies explicit credentials (storage-
        disabled path); when omitted they are resolved from the store."""
        if creds is None:
            if not self.credential_storage_enabled:
                raise CredentialError(
                    f"environment {self.environment!r} does not store credentials — "
                    "supply them for this operation"
                )
            creds = self.host_credentials(host)
        return self._client_factory(host, creds)


def submit_host_job(
    runner: JobRunner,
    vault: JobCredentialVault,
    connector: HostConnector,
    host: Host,
    kind: str,
    *,
    params: dict[str, object] | None = None,
    credentials: CredentialBundle | None = None,
) -> JobRecord:
    """Validate credentials for a host job and enqueue it. For storage-disabled
    environments the credentials are stashed in the vault under the job id
    *before* the job is submitted (so the runner can't start it first), and
    removed again if submission fails."""
    creds = connector.require_credentials(host, credentials)
    job_id = new_id()
    if creds is not None:
        vault.put(job_id, creds)
    try:
        return runner.submit(
            kind,
            target=host.name,
            params=params or {},
            environment=connector.environment,
            job_id=job_id,
        )
    except Exception:
        vault.discard(job_id)
        raise


def job_run_credentials(
    connector: HostConnector, vault: JobCredentialVault, job: JobRecord
) -> CredentialBundle | None:
    """Credentials a job handler should ``connect`` with: None (resolve from the
    store) when storage is enabled, else the vault bundle put there at submit."""
    if connector.credential_storage_enabled:
        return None
    return vault.require(job.id)


class EnvironmentRegistry:
    """Named, independent management environments → their connectors.

    Mutable so the web UI can add/edit environments at runtime: services hold a
    long-lived reference and call ``get()`` per request, so a ``rebuild()`` from
    the database is seen immediately without reconstructing the services."""

    def __init__(self) -> None:
        self._envs: dict[str, HostConnector] = {}

    def add(self, name: str, connector: HostConnector) -> None:
        if name in self._envs:
            raise InventoryError(f"environment {name!r} registered twice")
        self._envs[name] = connector

    def rebuild(self, connectors: dict[str, HostConnector]) -> None:
        """Atomically replace all environments (after a DB mutation)."""
        self._envs = dict(connectors)

    def get(self, name: str) -> HostConnector:
        connector = self._envs.get(name)
        if connector is None:
            raise InventoryError(
                f"unknown environment: {name!r} (have: {', '.join(self._envs) or 'none'})"
            )
        return connector

    def names(self) -> list[str]:
        return list(self._envs)
