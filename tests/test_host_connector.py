from __future__ import annotations

from pathlib import Path

import pytest

from convoy.credentials import CredentialStore
from convoy.errors import CredentialError
from convoy.inventory import Host, Inventory, Role, Site
from convoy.services.common import HostConnector
from convoy.store import Store

from .fakes import FakeTransport, make_factory


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment("default", credential_storage_enabled=True)
    return store


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put_set("default", "api-set", api_key="key123")
    cs.put_set(
        "default", "ssh-set", ssh_username="admin", ssh_password="pw", expert_password="expert-pw"
    )
    return cs


@pytest.fixture
def inventory(store: Store, creds: CredentialStore) -> Inventory:
    mgmt = Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS)
    fw = Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY)
    api_set = store.get_credential_set_by_name("default", "api-set")
    ssh_set = store.get_credential_set_by_name("default", "ssh-set")
    assert api_set is not None and ssh_set is not None
    mgmt.credential_set_id = api_set.id
    fw.credential_set_id = ssh_set.id
    return Inventory(sites=[Site(name="t", hosts=[mgmt, fw])])


def _connector(inventory: Inventory, creds: CredentialStore, *, api_only: bool) -> HostConnector:
    return HostConnector(
        inventory,
        creds,
        make_factory(FakeTransport(responses={})),
        api_only=api_only,
    )


def test_api_only_refuses_ssh_to_management_host(
    inventory: Inventory, creds: CredentialStore
) -> None:
    connector = _connector(inventory, creds, api_only=True)
    host = connector.mgmt_host("mgmt-01")
    with pytest.raises(CredentialError, match="API-only"):
        connector.require_credentials(host)
    with pytest.raises(CredentialError, match="API-only"):
        connector.connect(host)


def test_api_only_does_not_affect_firewalls(inventory: Inventory, creds: CredentialStore) -> None:
    connector = _connector(inventory, creds, api_only=True)
    host = connector.firewall_host("fw-01")
    # No exception: firewalls are unaffected by the management server's
    # access mode — SSH to them is unrelated to how mgmt itself is reached.
    connector.require_credentials(host)
    connector.connect(host)


def test_api_only_refuses_management_host_even_storage_disabled(
    inventory: Inventory, creds: CredentialStore
) -> None:
    connector = HostConnector(
        inventory,
        creds,
        make_factory(FakeTransport(responses={})),
        api_only=True,
        credential_storage_enabled=False,
    )
    host = connector.mgmt_host("mgmt-01")
    with pytest.raises(CredentialError, match="API-only"):
        connector.require_credentials(host, provided={})


def test_non_api_only_environment_connects_to_management_host_fine(
    inventory: Inventory, creds: CredentialStore
) -> None:
    connector = _connector(inventory, creds, api_only=False)
    host = connector.mgmt_host("mgmt-01")
    # mgmt-01 only has an API key assigned, not an SSH secret, so the SSH-
    # credential check (unrelated to api_only) is what should fire here.
    with pytest.raises(CredentialError, match="no SSH password or private key"):
        connector.require_credentials(host)
