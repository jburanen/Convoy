"""Shared plumbing for service-core modules: how to reach a management server.

Both the CPUSE-local subsystem (patching.py) and the CDT subsystem (cdt_ops.py)
connect to management servers the same way: resolve the host from inventory,
require an SSH credential (host-specific, falling back to the "*" fleet-wide
default), and open a transport via a swappable factory (tests inject fakes).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ..credentials import Credential, CredentialKind, CredentialStore
from ..errors import CredentialError, InventoryError
from ..inventory import Host, Inventory, Role
from ..transport.ssh import CommandResult, SSHClient

_MGMT_ROLES = (Role.MANAGEMENT, Role.MDS)


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
    ) -> None:
        self.inventory = inventory
        self.environment = environment
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

    def credential_kinds(self, host_name: str) -> list[str]:
        """Which credential kinds are stored for a host (secret-free)."""
        if self._credentials is None:
            return []
        return [
            info.kind.value
            for info in self._credentials.list(environment=self.environment)
            if info.host == host_name
        ]

    def require_ssh_credential(self, host: Host) -> None:
        creds = self.host_credentials(host)
        if CredentialKind.SSH_PASSWORD not in creds and CredentialKind.SSH_PRIVATE_KEY not in creds:
            raise CredentialError(
                f"no SSH credential stored for {host.name!r} in environment "
                f"{self.environment!r} — add an ssh_password or ssh_private_key "
                "credential first"
            )

    def host_credentials(self, host: Host) -> dict[CredentialKind, Credential]:
        if self._credentials is None:
            raise CredentialError(
                "credential store is locked — set the master key and restart the service"
            )
        creds = self._credentials.for_host(host.name, environment=self.environment)
        if not creds:
            # Environment-wide default, if any. Never crosses environments.
            creds = self._credentials.for_host("*", environment=self.environment)
        return creds

    def connect(self, host: Host) -> Transport:
        return self._client_factory(host, self.host_credentials(host))


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
