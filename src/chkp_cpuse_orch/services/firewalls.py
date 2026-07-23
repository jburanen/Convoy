"""Firewall manager — DB-backed, UI-editable firewalls patched directly via CPUSE.

A firewall here is a Security Gateway or ClusterXL member the operator wants to
patch one host at a time over SSH, exactly like a management server — distinct
from CDT's bulk gateway-fleet push (services/cdt_ops.py), which discovers its
own targets and never stores them. Firewalls live in their own ``firewalls``
table, in the same per-environment credential namespace as management servers,
and are merged into the same Inventory/HostConnector by
EnvironmentManager.rebuild() (see services/environments.py) — this manager
delegates to it after every mutation so the live registry stays in sync.
"""

from __future__ import annotations

from ..errors import InventoryError
from ..inventory import FIREWALL_ROLES, Host, Role
from ..store import FirewallRow, Store
from .environments import EnvironmentManager

# Roles the UI offers when adding a firewall. Used only to build the
# validation error message.
_OFFERED_ROLES = FIREWALL_ROLES


class FirewallManager:
    """Owns firewall persistence; rebuilds happen through the EnvironmentManager
    so both host kinds are always merged into one connector per environment."""

    def __init__(self, store: Store, env_manager: EnvironmentManager) -> None:
        self._store = store
        self._env_manager = env_manager

    def list_firewalls(self, environment: str) -> list[FirewallRow]:
        self._require_env(environment)
        return self._store.list_firewalls(environment)

    def add_firewall(
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
        """Add or update a firewall. Validates via the Host model. A newly
        added firewall inherits the environment's default credential set (if
        one is set), so manually-added and discovered firewalls are ready to
        use at once."""
        self._require_env(environment)
        parsed_role = _parse_firewall_role(role)
        # Reuse Host for field validation (name/address non-empty, port range).
        host = Host(
            name=name, address=address, role=parsed_role, ssh_port=ssh_port, ssh_user=ssh_user
        )
        is_new = self._store.get_firewall(environment, host.name) is None
        if is_new and self._store.get_env_host(environment, host.name) is not None:
            raise InventoryError(
                f"name {host.name!r} already exists — it is already used by a management "
                f"server in environment {environment!r}; names must be unique across "
                "servers and firewalls"
            )
        self._store.upsert_firewall(
            FirewallRow(
                environment=environment,
                name=host.name,
                address=host.address,
                role=host.role.value,
                ssh_port=host.ssh_port,
                ssh_user=host.ssh_user,
                notes=notes,
            )
        )
        if is_new:
            default = self._store.get_default_credential_set(environment)
            if default is not None:
                self._store.assign_firewall_credential_set(environment, host.name, default.id)
        self._env_manager.rebuild()

    def remove_firewall(self, environment: str, name: str) -> None:
        self._require_env(environment)
        if not self._store.delete_firewall(environment, name):
            raise InventoryError(f"firewall {name!r} not found in environment {environment!r}")
        self._env_manager.rebuild()

    def assign_credential(self, environment: str, host_name: str, set_name: str | None) -> None:
        """Assign a credential set (by name) to a firewall, or clear the
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
        if not self._store.assign_firewall_credential_set(environment, host_name, set_id):
            raise InventoryError(f"firewall {host_name!r} not found in environment {environment!r}")
        self._env_manager.rebuild()

    def _require_env(self, environment: str) -> None:
        if not self._store.environment_exists(environment):
            raise InventoryError(f"unknown environment: {environment!r}")


def _parse_firewall_role(role: str) -> Role:
    try:
        parsed = Role(role)
    except ValueError:
        raise InventoryError(
            f"invalid role {role!r}: firewalls hold {', '.join(r.value for r in _OFFERED_ROLES)}"
        ) from None
    if parsed not in FIREWALL_ROLES:
        raise InventoryError(
            f"role {role!r} is not a firewall role — management servers are added on the "
            "Provisioning tab"
        )
    return parsed


__all__ = ["FirewallManager"]
