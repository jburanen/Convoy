from __future__ import annotations

from pydantic import SecretStr

from chkp_cpuse_orch.credentials import Credential, CredentialBundle, CredentialKind
from chkp_cpuse_orch.errors import TransportError
from chkp_cpuse_orch.inventory import Host, Inventory, Role, Site
from chkp_cpuse_orch.services.discovery import (
    DiscoveryService,
    map_gateways_and_servers,
    parse_all_mdss_info,
)

from .fakes import FakeTransport

# ---- Management API object → role mapping (pure) --------------------------------

GATEWAYS_AND_SERVERS = [
    {
        "name": "mgmt-01",
        "type": "CpmiManagementServer",
        "ipv4-address": "192.0.2.10",
        "management-blades": {"network-policy-management": True, "logging-and-status": True},
    },
    {
        "name": "mgmt-02",
        "type": "CpmiManagementServer",
        "ipv4-address": "192.0.2.11",
        "management-blades": {"network-policy-management": True},
    },
    {
        "name": "log-01",
        "type": "CpmiLogServer",
        "ipv4-address": "192.0.2.12",
        "management-blades": {"logging-and-status": True},
    },
    {
        "name": "se-01",
        "type": "smart-event-server",
        "ipv4-address": "192.0.2.13",
        "management-blades": {"smart-event-server": True},
    },
    {"name": "fw-01", "type": "simple-gateway", "ipv4-address": "192.0.2.20"},
    {"name": "cluster-01", "type": "CpmiGatewayCluster", "ipv4-address": "192.0.2.21"},
]


def test_map_gateways_and_servers_roles() -> None:
    servers = map_gateways_and_servers(GATEWAYS_AND_SERVERS, primary_address="192.0.2.10")
    by_name = {s.name: s for s in servers}

    # Gateways and clusters are dropped.
    assert set(by_name) == {"mgmt-01", "mgmt-02", "log-01", "se-01"}

    assert by_name["mgmt-01"].detected_role is Role.PRIMARY_SMS  # matches primary addr
    assert by_name["mgmt-01"].needs_review is False
    assert by_name["mgmt-02"].detected_role is Role.SECONDARY_SMS
    assert by_name["mgmt-02"].needs_review is True  # primary vs secondary is ambiguous
    assert by_name["log-01"].detected_role is Role.LOG_SERVER
    assert by_name["se-01"].detected_role is Role.SMARTEVENT
    assert all(s.source == "api" for s in servers)


# ---- $MDSVERUTIL AllMdssInfo parsing (pure) -------------------------------------

ALL_MDSS_INFO = """\
Name         IP           Type
mds-primary  10.0.0.1     Primary Manager
mds-second   10.0.0.2     Secondary Manager
mlm-01       10.0.0.3     Log Manager (MLM)
"""


def test_parse_all_mdss_info() -> None:
    servers = parse_all_mdss_info(ALL_MDSS_INFO)
    by_name = {s.name: s for s in servers}
    assert set(by_name) == {"mds-primary", "mds-second", "mlm-01"}
    assert by_name["mds-primary"].detected_role is Role.PRIMARY_MDS
    assert by_name["mds-primary"].address == "10.0.0.1"
    assert by_name["mds-second"].detected_role is Role.SECONDARY_MDS
    assert by_name["mlm-01"].detected_role is Role.MLM
    # MDS detection is best-effort — every row is flagged for operator review.
    assert all(s.needs_review and s.source == "ssh" for s in servers)


def test_parse_all_mdss_info_ignores_noise() -> None:
    assert parse_all_mdss_info("\n   \n# comment\nheader only\n") == []


# ---- DiscoveryService orchestration (fakes, no live gear) -----------------------


class _FakeMgmtClient:
    def __init__(self, objects: list[dict[str, object]], **kwargs: object) -> None:
        self._objects = objects
        self.kwargs = kwargs

    def __enter__(self) -> _FakeMgmtClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def show_gateways_and_servers(self, *, details_level: str = "full") -> list[dict[str, object]]:
        return self._objects


class _FakeConnector:
    def __init__(
        self, inventory: Inventory, bundle: CredentialBundle, ssh: FakeTransport | None = None
    ) -> None:
        self.inventory = inventory
        self._bundle = bundle
        self._ssh = ssh

    def mgmt_host(self, name: str) -> Host:
        return self.inventory.host(name)

    def host_credentials(self, host: Host) -> CredentialBundle:
        return self._bundle

    def connect(self, host: Host, creds: object = None) -> FakeTransport:
        if self._ssh is None:
            raise TransportError("no ssh transport in this test")
        return self._ssh


class _FakeRegistry:
    def __init__(self, connector: _FakeConnector) -> None:
        self._connector = connector

    def get(self, environment: str) -> _FakeConnector:
        return self._connector


def _api_bundle() -> CredentialBundle:
    return {
        CredentialKind.API_KEY: Credential(
            host="mgmt-01", kind=CredentialKind.API_KEY, secret=SecretStr("api-key")
        )
    }


def _inventory(*hosts: Host) -> Inventory:
    return Inventory(sites=[Site(name="dc", hosts=list(hosts))])


def test_discover_api_flags_existing_and_maps_roles() -> None:
    inv = _inventory(Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS))
    connector = _FakeConnector(inv, _api_bundle())
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient(GATEWAYS_AND_SERVERS, **kw),
    )

    result = service.discover("default", "mgmt-01")
    by_name = {s.name: s for s in result.servers}

    # The primary itself comes back from the API but is flagged already-in-inventory.
    assert by_name["mgmt-01"].already_in_inventory is True
    assert by_name["mgmt-02"].already_in_inventory is False
    assert by_name["mgmt-02"].detected_role is Role.SECONDARY_SMS
    assert by_name["log-01"].detected_role is Role.LOG_SERVER
    assert not result.warnings


def test_discover_api_failure_becomes_warning() -> None:
    inv = _inventory(Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS))

    def boom(host: object, **kw: object) -> _FakeMgmtClient:
        raise TransportError("connection refused")

    service = DiscoveryService(
        _FakeRegistry(_FakeConnector(inv, _api_bundle())),  # type: ignore[arg-type]
        mgmt_client_factory=boom,
    )
    result = service.discover("default", "mgmt-01")
    assert result.servers == []
    assert any("Management API discovery failed" in w for w in result.warnings)


def test_discover_mds_over_ssh() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    ssh = FakeTransport(responses={"MDSVERUTIL AllMdssInfo": ALL_MDSS_INFO})
    connector = _FakeConnector(inv, _api_bundle(), ssh=ssh)
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient([], **kw),
    )

    result = service.discover("default", "mds-primary")
    by_name = {s.name: s for s in result.servers}
    # The primary MDS is flagged existing; the peers are importable.
    assert by_name["mds-primary"].already_in_inventory is True
    assert by_name["mds-second"].detected_role is Role.SECONDARY_MDS
    assert by_name["mlm-01"].detected_role is Role.MLM
    assert ssh.closed is True  # transport is always closed
