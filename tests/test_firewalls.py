from __future__ import annotations

from pathlib import Path

import pytest

from chkp_cpuse_orch.errors import InventoryError
from chkp_cpuse_orch.services.common import EnvironmentRegistry
from chkp_cpuse_orch.services.environments import EnvironmentManager
from chkp_cpuse_orch.services.firewalls import FirewallManager
from chkp_cpuse_orch.store import CredentialSetRow, Store


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


def _managers(
    store: Store, registry: EnvironmentRegistry
) -> tuple[EnvironmentManager, FirewallManager]:
    env_mgr = EnvironmentManager(store, registry, credentials=None, client_factory=None)
    fw_mgr = FirewallManager(store, env_mgr)
    return env_mgr, fw_mgr


def _set(store: Store, environment: str, name: str = "primary") -> str:
    store.upsert_credential_set(
        CredentialSetRow(environment=environment, name=name, ssh_password_ct=b"ct")
    )
    row = store.get_credential_set_by_name(environment, name)
    assert row is not None
    return row.id


def test_add_firewall_rebuilds_registry(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("dmz")
    fw_mgr.add_firewall("dmz", name="fw-d", address="10.0.0.1", role="gateway", ssh_user="svc")

    hosts = registry.get("dmz").firewalls()
    assert [h.name for h in hosts] == ["fw-d"]
    assert hosts[0].ssh_user == "svc"
    # Management-server listing stays empty — the two are disjoint.
    assert registry.get("dmz").management_servers() == []


def test_firewalls_and_servers_merge_into_one_connector(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    env_mgr.add_server(
        "corp", name="mgmt-1", address="10.0.0.1", role="management", ssh_user="admin"
    )
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.2", role="gateway", ssh_user="admin")

    connector = registry.get("corp")
    assert [h.name for h in connector.management_servers()] == ["mgmt-1"]
    assert [h.name for h in connector.firewalls()] == ["fw-1"]
    # Both resolve through the same merged inventory.
    assert connector.inventory.host("mgmt-1").name == "mgmt-1"
    assert connector.inventory.host("fw-1").name == "fw-1"
    assert connector.patchable_host("mgmt-1").name == "mgmt-1"
    assert connector.patchable_host("fw-1").name == "fw-1"


def test_cluster_member_role_accepted(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    fw_mgr.add_firewall(
        "corp", name="fw-a1", address="10.0.0.1", role="cluster_member", ssh_user="admin"
    )
    assert registry.get("corp").firewalls()[0].role.value == "cluster_member"


def test_invalid_firewall_role_rejected(store: Store) -> None:
    env_mgr, fw_mgr = _managers(store, EnvironmentRegistry())
    env_mgr.create_environment("corp")
    with pytest.raises(InventoryError, match="invalid role"):
        fw_mgr.add_firewall("corp", name="x", address="10.0.0.9", role="nonsense", ssh_user="admin")


def test_management_role_rejected_for_firewall(store: Store) -> None:
    env_mgr, fw_mgr = _managers(store, EnvironmentRegistry())
    env_mgr.create_environment("corp")
    with pytest.raises(InventoryError, match="not a firewall role"):
        fw_mgr.add_firewall(
            "corp", name="x", address="10.0.0.9", role="management", ssh_user="admin"
        )


def test_add_firewall_to_unknown_environment(store: Store) -> None:
    _, fw_mgr = _managers(store, EnvironmentRegistry())
    with pytest.raises(InventoryError, match="unknown environment"):
        fw_mgr.add_firewall("ghost", name="f", address="10.0.0.1", role="gateway", ssh_user="a")


def test_name_collision_across_servers_and_firewalls_rejected(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    env_mgr.add_server(
        "corp", name="shared", address="10.0.0.1", role="management", ssh_user="admin"
    )
    with pytest.raises(InventoryError, match="already used by a management server"):
        fw_mgr.add_firewall(
            "corp", name="shared", address="10.0.0.2", role="gateway", ssh_user="admin"
        )

    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.3", role="gateway", ssh_user="admin")
    with pytest.raises(InventoryError, match="already used by a firewall"):
        env_mgr.add_server(
            "corp", name="fw-1", address="10.0.0.4", role="management", ssh_user="admin"
        )


def test_remove_firewall(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="admin")
    fw_mgr.remove_firewall("corp", "fw-1")
    assert registry.get("corp").firewalls() == []
    with pytest.raises(InventoryError, match="not found"):
        fw_mgr.remove_firewall("corp", "fw-1")


def test_assign_credential_set_to_firewall(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    env_mgr.set_credential_storage("corp", True)
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="admin")
    _set(store, "corp", "primary")

    fw_mgr.assign_credential("corp", "fw-1", "primary")
    assert store.list_firewalls("corp")[0].credential_set_id is not None
    assert registry.get("corp").firewalls()[0].credential_set_id is not None

    with pytest.raises(InventoryError, match="credential set 'nope' not found"):
        fw_mgr.assign_credential("corp", "fw-1", "nope")
    with pytest.raises(InventoryError, match="firewall 'ghost' not found"):
        fw_mgr.assign_credential("corp", "ghost", "primary")

    fw_mgr.assign_credential("corp", "fw-1", None)
    assert store.list_firewalls("corp")[0].credential_set_id is None


def test_new_firewall_inherits_the_default_credential_set(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    env_mgr.set_credential_storage("corp", True)
    _set(store, "corp", "primary")
    assert store.set_default_credential_set("corp", "primary") is True

    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="admin")
    default_id = store.get_default_credential_set("corp").id  # type: ignore[union-attr]
    assert store.get_firewall("corp", "fw-1").credential_set_id == default_id  # type: ignore[union-attr]


def test_set_cluster_name(store: Store) -> None:
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="admin")

    fw_mgr.set_cluster_name("corp", "fw-1", "prod-cluster")
    assert store.get_firewall("corp", "fw-1").credential_set_id is None  # untouched
    assert store.get_firewall("corp", "fw-1").cluster_name == "prod-cluster"  # type: ignore[union-attr]

    fw_mgr.set_cluster_name("corp", "fw-1", None)  # clears it
    assert store.get_firewall("corp", "fw-1").cluster_name is None  # type: ignore[union-attr]

    with pytest.raises(InventoryError, match="firewall 'ghost' not found"):
        fw_mgr.set_cluster_name("corp", "ghost", "prod-cluster")


def test_editing_a_firewall_never_clobbers_a_previously_set_cluster_name(store: Store) -> None:
    """upsert_firewall (every ordinary add/edit) must never touch
    cluster_name — only set_cluster_name (a targeted UPDATE) does. Otherwise
    an unrelated edit (e.g. changing the SSH port) would silently wipe out a
    name resolved at discovery time or via "re-check cluster membership"."""
    registry = EnvironmentRegistry()
    env_mgr, fw_mgr = _managers(store, registry)
    env_mgr.create_environment("corp")
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="admin")
    fw_mgr.set_cluster_name("corp", "fw-1", "prod-cluster")

    # An ordinary edit (add_firewall is upsert-by-name) touching unrelated fields.
    fw_mgr.add_firewall("corp", name="fw-1", address="10.0.0.1", role="gateway", ssh_user="other")
    assert store.get_firewall("corp", "fw-1").ssh_user == "other"  # type: ignore[union-attr]
    assert store.get_firewall("corp", "fw-1").cluster_name == "prod-cluster"  # type: ignore[union-attr]
