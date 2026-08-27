"""Smart-1 Cloud connection: URL shape, storage, and the connect flow.

The tenant identifiers here are invented. A real one appears only in the
operator's own portal — never in this repo, which is public-bound.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from convoy.credentials import CredentialStore
from convoy.errors import CredentialError, InventoryError, TransportError
from convoy.inventory import Host, Role
from convoy.services.common import EnvironmentRegistry
from convoy.services.environments import EnvironmentManager
from convoy.services.s1c import (
    S1C_CREDENTIAL_SET,
    S1C_SERVER_NAME,
    Smart1CloudService,
    normalize_maas_host,
)
from convoy.store import Store
from convoy.transport.mgmt_api import ManagementAPIClient

TENANT_PREFIX = "acme-a1b2c3d4"
TENANT_HOST = f"{TENANT_PREFIX}.maas.checkpoint.com"
TENANT_UUID = "00000000-1111-2222-3333-444444444444"
API_KEY = "not-a-real-key"


# -- what the operator pasted -> the tenant's hostname -------------------------


@pytest.mark.parametrize(
    "pasted",
    [
        TENANT_PREFIX,
        f"  {TENANT_PREFIX}  ",
        TENANT_HOST,
        f"https://{TENANT_HOST}/{TENANT_UUID}/web_api/login",
        f"https://{TENANT_HOST}:443/{TENANT_UUID}/web_api",
    ],
)
def test_normalize_maas_host_accepts_every_form_of_the_same_tenant(pasted: str) -> None:
    """The portal shows a whole login URL, so the "prefix" field receives all
    of these in practice. They mean one host."""
    assert normalize_maas_host(pasted) == TENANT_HOST


def test_normalize_maas_host_leaves_another_domain_alone() -> None:
    """Anything already carrying a dot is a complete hostname — don't rewrite a
    tenant that isn't on maas.checkpoint.com."""
    assert normalize_maas_host("mgmt.example.test") == "mgmt.example.test"


def test_normalize_maas_host_rejects_empty() -> None:
    with pytest.raises(InventoryError):
        normalize_maas_host("   ")


# -- the context path is a URL segment, so the model polices it ----------------


def test_host_accepts_a_tenant_uuid() -> None:
    host = Host(
        name="s1c", address=TENANT_HOST, role=Role.PRIMARY_SMS, mgmt_api_context=TENANT_UUID
    )
    assert host.mgmt_api_context == TENANT_UUID


@pytest.mark.parametrize(
    "bad",
    [
        "../../admin",
        "tenant/web_api",
        "https://evil.test/",
        "tenant uuid",
    ],
)
def test_host_rejects_a_context_that_could_repoint_the_api(bad: str) -> None:
    """This is interpolated into the URL the environment's API key is sent to,
    so anything that could steer it elsewhere is refused outright."""
    with pytest.raises(ValueError):
        Host(name="s1c", address=TENANT_HOST, role=Role.PRIMARY_SMS, mgmt_api_context=bad)


def test_host_context_defaults_to_none_for_on_prem() -> None:
    assert Host(name="mgmt", address="192.0.2.10", role=Role.PRIMARY_SMS).mgmt_api_context is None


# -- the one transport change --------------------------------------------------


def test_client_puts_the_tenant_uuid_in_the_base_url() -> None:
    host = Host(
        name="s1c", address=TENANT_HOST, role=Role.PRIMARY_SMS, mgmt_api_context=TENANT_UUID
    )
    client = ManagementAPIClient(host, api_key=API_KEY)
    # Exactly the login URL the tenant's own Settings screen prints.
    assert client._base_url == f"https://{TENANT_HOST}:443/{TENANT_UUID}/web_api"


def test_client_verifies_tls_for_a_tenant_but_not_for_on_prem() -> None:
    """A Smart-1 Cloud tenant is a public Check Point host with a real
    certificate; an on-prem server is self-signed by default."""
    tenant = Host(
        name="s1c", address=TENANT_HOST, role=Role.PRIMARY_SMS, mgmt_api_context=TENANT_UUID
    )
    on_prem = Host(name="mgmt", address="192.0.2.10", role=Role.PRIMARY_SMS)
    assert ManagementAPIClient(tenant, api_key=API_KEY)._verify_tls is True
    assert ManagementAPIClient(on_prem, api_key=API_KEY)._verify_tls is False
    # An explicit flag still wins in both directions.
    assert ManagementAPIClient(tenant, api_key=API_KEY, verify_tls=False)._verify_tls is False


def test_on_prem_base_url_is_unchanged() -> None:
    on_prem = Host(name="mgmt", address="192.0.2.10", role=Role.PRIMARY_SMS)
    client = ManagementAPIClient(on_prem, api_key=API_KEY)
    assert client._base_url == "https://192.0.2.10:443/web_api"


# -- the service ---------------------------------------------------------------


class _FakeClient:
    """Stands in for ManagementAPIClient: entering it is the login."""

    def __init__(self, host: Host, *, fail: bool = False, **kwargs: Any) -> None:
        self.host = host
        self.kwargs = kwargs
        self._fail = fail

    def __enter__(self) -> _FakeClient:
        if self._fail:
            raise TransportError("Management API login failed: 401 Unauthorized")
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


def _service(
    store: Store, *, api_only: bool = True, storage: bool = True, fail_login: bool = False
) -> tuple[Smart1CloudService, EnvironmentRegistry, list[_FakeClient]]:
    registry = EnvironmentRegistry()
    credentials = CredentialStore(store, master_key="correct horse battery staple")
    manager = EnvironmentManager(store, registry, credentials=credentials)
    manager.create_environment("cloud")
    manager.set_environment_type("cloud", is_mds=False, api_only=api_only)
    manager.set_credential_storage("cloud", storage)
    made: list[_FakeClient] = []

    def factory(host: Host, **kwargs: Any) -> _FakeClient:
        client = _FakeClient(host, fail=fail_login, **kwargs)
        made.append(client)
        return client

    service = Smart1CloudService(
        registry=registry,
        env_manager=manager,
        credentials=credentials if storage else None,
        store=store,
        mgmt_client_factory=factory,
    )
    return service, registry, made


def test_connect_stores_the_tenant_as_the_environments_management_server(store: Store) -> None:
    service, registry, made = _service(store)

    job = service.submit_connect(
        "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
    )

    assert job.status == "succeeded", job.error
    # Logged in as the tenant, read-only, with the key — never SSH.
    assert made[0].host.address == TENANT_HOST
    assert made[0].host.mgmt_api_context == TENANT_UUID
    assert made[0].kwargs == {"api_key": API_KEY, "read_only": True}
    # Stored as an ordinary management server, so discovery needs no S1C code.
    servers = registry.get("cloud").management_servers()
    assert [h.name for h in servers] == [S1C_SERVER_NAME]
    assert servers[0].mgmt_api_context == TENANT_UUID
    assert servers[0].credential_set_id is not None


def test_connect_reports_the_stored_connection_without_the_key(store: Store) -> None:
    service, _registry, _made = _service(store)
    service.submit_connect(
        "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
    )

    conn = service.connection("cloud")
    assert conn is not None
    assert conn.maas_host == TENANT_HOST
    assert conn.tenant_uuid == TENANT_UUID
    assert conn.credential_set == S1C_CREDENTIAL_SET
    assert conn.has_api_key is True
    assert conn.login_url == f"https://{TENANT_HOST}/{TENANT_UUID}/web_api/login"
    assert API_KEY not in repr(conn)


def test_no_connection_before_connecting(store: Store) -> None:
    service, _registry, _made = _service(store)
    assert service.connection("cloud") is None


def test_a_rejected_key_leaves_nothing_half_configured(store: Store) -> None:
    """The credentials are proven before anything is written, so a bad key
    doesn't leave a server row for the next job to trip over."""
    service, registry, _made = _service(store, fail_login=True)

    job = service.submit_connect(
        "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
    )

    assert job.status == "failed"
    assert "401" in (job.error or "")
    assert registry.get("cloud").management_servers() == []
    assert service.connection("cloud") is None


def test_connect_refuses_an_environment_that_is_not_smart1_cloud(store: Store) -> None:
    service, _registry, _made = _service(store, api_only=False)
    with pytest.raises(InventoryError):
        service.submit_connect(
            "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
        )
    assert store.list_jobs() == []  # not an operation, so not an audit row


def test_connect_refuses_without_credential_storage(store: Store) -> None:
    """The API key is the only way in — with nowhere to keep it there is
    nothing to connect with."""
    service, _registry, _made = _service(store, storage=False)
    with pytest.raises(CredentialError):
        service.submit_connect(
            "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
        )


def test_connect_rejects_a_malformed_tenant_uuid(store: Store) -> None:
    service, _registry, _made = _service(store)
    with pytest.raises(InventoryError):
        service.submit_connect(
            "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid="../other-tenant", api_key=API_KEY
        )


def test_reconnecting_replaces_the_key_without_duplicating_the_server(store: Store) -> None:
    service, registry, _made = _service(store)
    service.submit_connect(
        "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key=API_KEY
    )
    job = service.submit_connect(
        "cloud", maas_prefix=TENANT_PREFIX, tenant_uuid=TENANT_UUID, api_key="rotated-key"
    )

    assert job.status == "succeeded", job.error
    assert len(registry.get("cloud").management_servers()) == 1
