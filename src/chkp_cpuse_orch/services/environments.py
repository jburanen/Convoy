"""Environment manager — DB-backed, UI-editable management environments.

Environments and their management-server inventories live in the database so the
web UI can add/edit them at runtime (see .claude/memory/patching-web-design.md).
On first startup they are **seeded once** from config.yaml + inventory files;
after that the database is authoritative and the config files are ignored.

Gateways are not stored here — CDT discovers them at deploy time. Credentials
stay in their own per-environment namespace (credentials.py); deleting an
environment also **purges its credentials** so a later same-named environment
can't inherit the old secrets.
"""

from __future__ import annotations

import re
import sqlite3

from ..config import Config
from ..credentials import CredentialStore
from ..errors import InventoryError
from ..inventory import Host, Inventory, Role, Site
from ..reporting import get_logger
from ..store import EnvHostRow, Store
from .common import ClientFactory, EnvironmentRegistry, HostConnector

logger = get_logger(__name__)

# Names may contain upper/lowercase letters, digits, spaces, '_' and '-', and
# must start with a letter or digit (surrounding whitespace is stripped before
# validation, so a name can't end in a space either). Used verbatim as the URL
# path param (the UI percent-encodes it) and as the credential namespace key;
# case-sensitive, so "Corp" and "corp" are distinct environments.
_ENV_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,31}")
_SEEDED_META_KEY = "environments_seeded"

# Roles a management environment's inventory may hold (what this tool connects to).
MANAGEMENT_ROLES = (Role.MANAGEMENT, Role.MDS)


class EnvironmentManager:
    """Owns environment/server persistence and keeps the live registry in sync."""

    def __init__(
        self,
        store: Store,
        registry: EnvironmentRegistry,
        credentials: CredentialStore | None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._store = store
        self._registry = registry
        self._credentials = credentials
        self._client_factory = client_factory

    # -- startup ----------------------------------------------------------------

    def seed_from_config(self, config: Config) -> None:
        """First-run only: import config-defined environments + their inventory
        files into the DB. A meta flag makes this idempotent, so deleting every
        environment in the UI stays deleted across restarts."""
        if self._store.get_meta(_SEEDED_META_KEY):
            return
        for env_def in config.resolved_environments():
            # Config-seeded environments preserve the pre-feature behaviour of
            # storing credentials; only UI-created environments default to off.
            self._store.insert_environment(env_def.name, credential_storage_enabled=True)
            if env_def.inventory.is_file():
                inventory = Inventory.load(env_def.inventory)
                for host in _all_hosts(inventory):
                    if host.role in MANAGEMENT_ROLES:
                        self._store.upsert_env_host(_row_from_host(env_def.name, host))
            else:
                logger.warning(
                    "seed: no inventory file for environment",
                    environment=env_def.name,
                    path=str(env_def.inventory),
                )
        self._store.set_meta(_SEEDED_META_KEY, "1")
        logger.info("environments seeded from config")

    def rebuild(self) -> None:
        """Rebuild the live registry from the database (call after any change)."""
        connectors: dict[str, HostConnector] = {}
        for env in self._store.list_environments():
            hosts = [_host_from_row(r) for r in self._store.list_env_hosts(env.name)]
            inventory = Inventory(sites=[Site(name=env.name, hosts=hosts)])
            connectors[env.name] = HostConnector(
                inventory,
                self._credentials,
                self._client_factory,
                environment=env.name,
                credential_storage_enabled=env.credential_storage_enabled,
            )
        self._registry.rebuild(connectors)

    # -- environment CRUD --------------------------------------------------------

    def create_environment(self, name: str) -> str:
        """Create an environment; returns the normalized (stripped) name."""
        name = name.strip()
        if not _ENV_NAME_RE.fullmatch(name):
            raise InventoryError(
                f"invalid environment name {name!r}: letters, digits, spaces, "
                "'_' and '-', starting with a letter or digit, max 32 chars"
            )
        try:
            self._store.insert_environment(name, credential_storage_enabled=False)
        except sqlite3.IntegrityError:
            raise InventoryError(f"environment {name!r} already exists") from None
        self.rebuild()
        return name

    def set_credential_storage(self, name: str, enabled: bool) -> int:
        """Enable or disable credential storage for an environment.

        Disabling **purges** any stored credential sets for it — the operator opted
        out of keeping secrets on disk, so we don't leave them lying around (and
        they would be unused anyway). Servers are auto-unassigned via the FK.
        Returns the number of credential sets purged."""
        if not self._store.set_environment_credential_storage(name, enabled):
            raise InventoryError(f"unknown environment: {name!r}")
        purged = 0
        if not enabled:
            purged = self._store.delete_environment_credential_sets(name)
            if purged:
                logger.info(
                    "purged credential sets on disabling storage", environment=name, count=purged
                )
        self.rebuild()
        return purged

    def rename_environment(self, old: str, new: str) -> str:
        """Rename an environment; its servers, credentials, and job history move
        with it atomically. Returns the normalized new name.

        A job already RUNNING against the old name keeps its in-memory name and
        will fail its next registry lookup — acceptable: renames are an
        operator action taken outside patching windows."""
        new = new.strip()
        if not _ENV_NAME_RE.fullmatch(new):
            raise InventoryError(
                f"invalid environment name {new!r}: letters, digits, spaces, "
                "'_' and '-', starting with a letter or digit, max 32 chars"
            )
        if new == old:
            return new
        try:
            if not self._store.rename_environment(old, new):
                raise InventoryError(f"unknown environment: {old!r}")
        except sqlite3.IntegrityError:
            raise InventoryError(f"environment {new!r} already exists") from None
        logger.info("renamed environment", old=old, new=new)
        self.rebuild()
        return new

    def delete_environment(self, name: str) -> None:
        if not self._store.delete_environment(name):
            raise InventoryError(f"unknown environment: {name!r}")
        # Purge credential sets too: a same-named environment created later must NOT
        # inherit the deleted one's secrets. env_hosts go via FK cascade.
        purged = self._store.delete_environment_credential_sets(name)
        if purged:
            logger.info(
                "purged credential sets on environment delete", environment=name, count=purged
            )
        self.rebuild()

    # -- credential-set assignment ----------------------------------------------

    def assign_credential(self, environment: str, host_name: str, set_name: str | None) -> None:
        """Assign a credential set (by name) to a management server, or clear the
        assignment with ``None``. Rebuilds the registry so resolution sees it."""
        self._require_env(environment)
        set_id: str | None = None
        if set_name is not None:
            row = self._store.get_credential_set_by_name(environment, set_name)
            if row is None:
                raise InventoryError(
                    f"credential set {set_name!r} not found in environment {environment!r}"
                )
            set_id = row.id
        if not self._store.assign_credential_set(environment, host_name, set_id):
            raise InventoryError(f"server {host_name!r} not found in environment {environment!r}")
        self.rebuild()

    # -- management-server CRUD --------------------------------------------------

    def list_servers(self, environment: str) -> list[EnvHostRow]:
        self._require_env(environment)
        return self._store.list_env_hosts(environment)

    def add_server(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int = 22,
        notes: str | None = None,
    ) -> None:
        """Add or update a management server. Validates via the Host model."""
        self._require_env(environment)
        parsed_role = _parse_management_role(role)
        # Reuse Host for field validation (name/address non-empty, port range).
        host = Host(
            name=name, address=address, role=parsed_role, ssh_port=ssh_port, ssh_user=ssh_user
        )
        self._store.upsert_env_host(
            EnvHostRow(
                environment=environment,
                name=host.name,
                address=host.address,
                role=host.role.value,
                ssh_port=host.ssh_port,
                ssh_user=host.ssh_user,
                notes=notes,
            )
        )
        self.rebuild()

    def remove_server(self, environment: str, name: str) -> None:
        self._require_env(environment)
        if not self._store.delete_env_host(environment, name):
            raise InventoryError(f"server {name!r} not found in environment {environment!r}")
        self.rebuild()

    # -- helpers -----------------------------------------------------------------

    def _require_env(self, environment: str) -> None:
        if not self._store.environment_exists(environment):
            raise InventoryError(f"unknown environment: {environment!r}")


def _all_hosts(inventory: Inventory) -> list[Host]:
    return [h for site in inventory.sites for h in site.hosts]


def _row_from_host(environment: str, host: Host) -> EnvHostRow:
    return EnvHostRow(
        environment=environment,
        name=host.name,
        address=host.address,
        role=host.role.value,
        ssh_port=host.ssh_port,
        ssh_user=host.ssh_user,
        notes=host.notes,
    )


def _host_from_row(row: EnvHostRow) -> Host:
    return Host(
        name=row.name,
        address=row.address,
        role=Role(row.role),
        ssh_port=row.ssh_port,
        ssh_user=row.ssh_user,
        notes=row.notes,
        credential_set_id=row.credential_set_id,
    )


def _parse_management_role(role: str) -> Role:
    try:
        parsed = Role(role)
    except ValueError:
        raise InventoryError(
            f"invalid role {role!r}: management environments hold "
            f"{' or '.join(r.value for r in MANAGEMENT_ROLES)} servers"
        ) from None
    if parsed not in MANAGEMENT_ROLES:
        raise InventoryError(
            f"role {role!r} is not a management server role — gateways are "
            "discovered by CDT, not added here"
        )
    return parsed
