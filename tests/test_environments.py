from __future__ import annotations

from pathlib import Path

import pytest

from chkp_cpuse_orch.config import Config, EnvironmentDef, Paths
from chkp_cpuse_orch.errors import InventoryError
from chkp_cpuse_orch.services.common import EnvironmentRegistry
from chkp_cpuse_orch.services.environments import EnvironmentManager
from chkp_cpuse_orch.store import CredentialSetRow, Store


def _set(store: Store, environment: str, name: str = "primary") -> str:
    """Insert a minimal credential set and return its id."""
    store.upsert_credential_set(
        CredentialSetRow(environment=environment, name=name, ssh_password_ct=b"ct")
    )
    row = store.get_credential_set_by_name(environment, name)
    assert row is not None
    return row.id


INVENTORY_YAML = """\
sites:
  - name: dc
    hosts:
      - name: mgmt-01
        address: 192.0.2.10
        role: management
      - name: fw-01
        address: 192.0.2.20
        role: gateway
"""


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


def _manager(store: Store, registry: EnvironmentRegistry) -> EnvironmentManager:
    return EnvironmentManager(store, registry, credentials=None, client_factory=None)


def _config(tmp_path: Path, environments: list[EnvironmentDef] | None = None) -> Config:
    return Config(
        paths=Paths(inventory_path=tmp_path / "inventory.yaml"),
        environments=environments or [],
    )


def test_seed_imports_only_management_hosts(tmp_path: Path, store: Store) -> None:
    (tmp_path / "inventory.yaml").write_text(INVENTORY_YAML, encoding="utf-8")
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.seed_from_config(_config(tmp_path))
    mgr.rebuild()

    # Implicit "default" env seeded; gateway excluded.
    assert [e.name for e in store.list_environments()] == ["default"]
    assert [h.name for h in store.list_env_hosts("default")] == ["mgmt-01"]
    assert [h.name for h in registry.get("default").management_servers()] == ["mgmt-01"]


def test_seed_is_idempotent(tmp_path: Path, store: Store) -> None:
    (tmp_path / "inventory.yaml").write_text(INVENTORY_YAML, encoding="utf-8")
    mgr = _manager(store, EnvironmentRegistry())
    mgr.seed_from_config(_config(tmp_path))
    # Deleting after seed must survive a second seed call (flag set once).
    store.delete_environment("default")
    mgr.seed_from_config(_config(tmp_path))
    assert store.list_environments() == []


def test_create_add_server_rebuilds_registry(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.create_environment("dmz")
    mgr.add_server("dmz", name="mgmt-d", address="10.0.0.1", role="management", ssh_user="svc")

    hosts = registry.get("dmz").management_servers()
    assert [h.name for h in hosts] == ["mgmt-d"]
    assert hosts[0].ssh_user == "svc"


def test_invalid_environment_name_rejected(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    for bad in ("", "   ", "x!", "-leading-dash", "café", "a" * 33):
        with pytest.raises(InventoryError, match="invalid environment name"):
            mgr.create_environment(bad)


def test_environment_name_allows_uppercase_and_spaces(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    # Surrounding whitespace is stripped; the normalized name is returned.
    assert mgr.create_environment("  Corp HQ Berlin ") == "Corp HQ Berlin"
    assert [e.name for e in store.list_environments()] == ["Corp HQ Berlin"]
    assert registry.names() == ["Corp HQ Berlin"]


def test_duplicate_environment_rejected(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("corp")
    with pytest.raises(InventoryError, match="already exists"):
        mgr.create_environment("corp")


def test_gateway_role_server_rejected(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("corp")
    with pytest.raises(InventoryError, match="not a management server role"):
        mgr.add_server("corp", name="fw", address="10.0.0.2", role="gateway", ssh_user="admin")


def test_granular_and_legacy_roles_accepted(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.create_environment("corp")
    roles = [
        "primary_sms",
        "secondary_sms",
        "log_server",
        "primary_mds",
        "secondary_mds",
        "mlm",
        "smartevent",
        "management",  # legacy, still accepted
        "mds",  # legacy, still accepted
    ]
    for i, role in enumerate(roles):
        mgr.add_server("corp", name=f"srv-{i}", address=f"10.0.0.{i}", role=role, ssh_user="admin")
    stored = {h.name: h.role for h in registry.get("corp").management_servers()}
    assert stored["srv-0"] == "primary_sms"
    assert stored["srv-6"] == "smartevent"
    assert len(stored) == len(roles)  # every role landed in the inventory


def test_invalid_role_rejected(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("corp")
    with pytest.raises(InventoryError, match="invalid role"):
        mgr.add_server("corp", name="x", address="10.0.0.9", role="nonsense", ssh_user="admin")


def test_add_server_to_unknown_environment(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    with pytest.raises(InventoryError, match="unknown environment"):
        mgr.add_server("ghost", name="m", address="10.0.0.1", role="management", ssh_user="a")


def test_delete_environment_removes_from_registry(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.create_environment("corp")
    assert registry.names() == ["corp"]
    mgr.delete_environment("corp")
    assert registry.names() == []
    with pytest.raises(InventoryError, match="unknown environment"):
        mgr.delete_environment("corp")


def test_delete_environment_purges_credential_sets(store: Store) -> None:
    # Guard against credential resurrection: a same-named env created later must
    # NOT inherit the deleted environment's secrets.
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("corp")
    _set(store, "corp")
    mgr.create_environment("other")
    _set(store, "other")  # a set in a different environment must survive
    mgr.delete_environment("corp")

    assert store.list_credential_sets("corp") == []
    assert len(store.list_credential_sets("other")) == 1

    # Recreate the name — it starts with no credential sets.
    mgr.create_environment("corp")
    assert store.list_credential_sets("corp") == []


def test_assign_credential_set_to_server(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.create_environment("corp")
    mgr.set_credential_storage("corp", True)
    mgr.add_server("corp", name="m1", address="10.0.0.1", role="management", ssh_user="admin")
    _set(store, "corp", "primary")

    mgr.assign_credential("corp", "m1", "primary")
    assert store.list_env_hosts("corp")[0].credential_set_id is not None
    # The live registry reflects the assignment (Host carries the set id).
    assert registry.get("corp").management_servers()[0].credential_set_id is not None

    # Unknown set / server are rejected.
    with pytest.raises(InventoryError, match="credential set 'nope' not found"):
        mgr.assign_credential("corp", "m1", "nope")
    with pytest.raises(InventoryError, match="server 'ghost' not found"):
        mgr.assign_credential("corp", "ghost", "primary")

    # Clearing the assignment.
    mgr.assign_credential("corp", "m1", None)
    assert store.list_env_hosts("corp")[0].credential_set_id is None


def test_rename_environment_moves_everything(store: Store) -> None:
    registry = EnvironmentRegistry()
    mgr = _manager(store, registry)
    mgr.create_environment("corp")
    mgr.add_server("corp", name="m1", address="10.0.0.1", role="management", ssh_user="admin")
    _set(store, "corp")

    assert mgr.rename_environment("corp", "  Corp HQ ") == "Corp HQ"

    assert [e.name for e in store.list_environments()] == ["Corp HQ"]
    assert [h.name for h in store.list_env_hosts("Corp HQ")] == ["m1"]
    assert len(store.list_credential_sets("Corp HQ")) == 1
    assert store.list_credential_sets("corp") == []
    assert registry.names() == ["Corp HQ"]
    assert [h.name for h in registry.get("Corp HQ").management_servers()] == ["m1"]


def test_rename_environment_errors(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("a")
    mgr.create_environment("b")
    with pytest.raises(InventoryError, match="unknown environment"):
        mgr.rename_environment("ghost", "x")
    with pytest.raises(InventoryError, match="already exists"):
        mgr.rename_environment("a", "b")
    with pytest.raises(InventoryError, match="invalid environment name"):
        mgr.rename_environment("a", "x!")
    assert mgr.rename_environment("a", "a") == "a"  # no-op


def test_remove_server(store: Store) -> None:
    mgr = _manager(store, EnvironmentRegistry())
    mgr.create_environment("corp")
    mgr.add_server("corp", name="m1", address="10.0.0.1", role="management", ssh_user="admin")
    mgr.remove_server("corp", "m1")
    assert store.list_env_hosts("corp") == []
    with pytest.raises(InventoryError, match="not found"):
        mgr.remove_server("corp", "m1")
