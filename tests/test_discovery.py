from __future__ import annotations

from pydantic import SecretStr

from chkp_cpuse_orch.credentials import Credential, CredentialBundle, CredentialKind
from chkp_cpuse_orch.errors import InventoryError, TransportError
from chkp_cpuse_orch.inventory import FIREWALL_ROLES, Host, Inventory, Role, Site
from chkp_cpuse_orch.services.discovery import (
    DiscoveryService,
    map_gateways_and_servers,
    map_gateways_only,
    parse_mdsquerydb_mdss,
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


def test_map_gateways_only_roles() -> None:
    firewalls = map_gateways_only(GATEWAYS_AND_SERVERS)
    by_name = {s.name: s for s in firewalls}

    # Management-plane objects are dropped — the mirror image of the servers test.
    assert set(by_name) == {"fw-01", "cluster-01"}
    assert by_name["fw-01"].detected_role is Role.GATEWAY
    assert by_name["cluster-01"].detected_role is Role.CLUSTER_MEMBER
    assert all(s.source == "api" for s in firewalls)
    assert all(s.needs_review is False for s in firewalls)


# ---- `mdsquerydb MDSs` parsing (pure) --------------------------------------------

ALL_MDSS_INFO = """\
Name         IP
mds-primary  10.0.0.1
mds-second   10.0.0.2
mlm-01       10.0.0.3
"""


def test_parse_mdsquerydb_mdss() -> None:
    servers = parse_mdsquerydb_mdss(ALL_MDSS_INFO, primary_address="10.0.0.1")
    by_name = {s.name: s for s in servers}
    assert set(by_name) == {"mds-primary", "mds-second", "mlm-01"}
    # Only the peer matching the address we connected to is inferred as primary.
    assert by_name["mds-primary"].detected_role is Role.PRIMARY_MDS
    assert by_name["mds-primary"].needs_review is False
    assert by_name["mds-primary"].address == "10.0.0.1"
    # mdsquerydb doesn't report role — every other peer needs operator review.
    assert by_name["mds-second"].detected_role is Role.SECONDARY_MDS
    assert by_name["mds-second"].needs_review is True
    assert by_name["mlm-01"].detected_role is Role.SECONDARY_MDS
    assert by_name["mlm-01"].needs_review is True
    assert all(s.source == "ssh" for s in servers)


def test_parse_mdsquerydb_mdss_ignores_noise() -> None:
    noise = "\n   \n# comment\nheader only\n"
    assert parse_mdsquerydb_mdss(noise, primary_address="10.0.0.1") == []


# ---- DiscoveryService orchestration (fakes, no live gear) -----------------------


class _FakeMgmtClient:
    def __init__(
        self,
        objects: list[dict[str, object]],
        domains: list[dict[str, object]] | None = None,
        **kwargs: object,
    ) -> None:
        self._objects = objects
        self._domains = domains or []
        self.kwargs = kwargs

    def __enter__(self) -> _FakeMgmtClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def show_gateways_and_servers(self, *, details_level: str = "full") -> list[dict[str, object]]:
        return self._objects

    def show_domains(self) -> list[dict[str, object]]:
        return self._domains


class _FakeConnector:
    def __init__(
        self,
        inventory: Inventory,
        bundle: CredentialBundle,
        ssh: FakeTransport | None = None,
        *,
        is_mds: bool = False,
    ) -> None:
        self.inventory = inventory
        self.is_mds = is_mds
        self._bundle = bundle
        self._ssh = ssh

    def mgmt_host(self, name: str) -> Host:
        return self.inventory.host(name)

    def primary_mgmt_host(self) -> Host:
        for site in self.inventory.sites:
            for h in site.hosts:
                if h.role in (Role.PRIMARY_SMS, Role.PRIMARY_MDS):
                    return h
        raise InventoryError("no Primary SMS or Primary MDS server configured")

    def firewalls(self) -> list[Host]:
        return [h for s in self.inventory.sites for h in s.hosts if h.role in FIREWALL_ROLES]

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


def test_discover_mds_uses_global_domain_for_api_call() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    connector = _FakeConnector(inv, _api_bundle(), ssh=FakeTransport(), is_mds=True)
    seen_kwargs: list[dict[str, object]] = []

    def factory(host: object, **kw: object) -> _FakeMgmtClient:
        seen_kwargs.append(kw)
        return _FakeMgmtClient([], **kw)

    service = DiscoveryService(_FakeRegistry(connector), mgmt_client_factory=factory)  # type: ignore[arg-type]
    service.discover("default", "mds-primary")
    assert seen_kwargs[0]["domain"] == "Global"


def test_discover_sms_omits_domain_for_api_call() -> None:
    inv = _inventory(Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS))
    connector = _FakeConnector(inv, _api_bundle())
    seen_kwargs: list[dict[str, object]] = []

    def factory(host: object, **kw: object) -> _FakeMgmtClient:
        seen_kwargs.append(kw)
        return _FakeMgmtClient([], **kw)

    service = DiscoveryService(_FakeRegistry(connector), mgmt_client_factory=factory)  # type: ignore[arg-type]
    service.discover("default", "mgmt-01")
    assert "domain" not in seen_kwargs[0]


def test_discover_mds_over_ssh() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    ssh = FakeTransport(responses={"mdsquerydb": ALL_MDSS_INFO})
    connector = _FakeConnector(inv, _api_bundle(), ssh=ssh, is_mds=True)
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient([], **kw),
    )

    result = service.discover("default", "mds-primary")
    by_name = {s.name: s for s in result.servers}
    # The primary MDS is flagged existing; the peers are importable.
    assert by_name["mds-primary"].already_in_inventory is True
    assert by_name["mds-second"].detected_role is Role.SECONDARY_MDS
    assert by_name["mlm-01"].detected_role is Role.SECONDARY_MDS
    # Locates MDSDIR on disk itself rather than depending on it being pre-set —
    # a plain SSH exec loads none of the Check Point environment.
    sent = ssh.commands[-1]
    assert "ls -d /opt/CPmds-R*" in sent
    assert '"$MDSDIR/scripts/mdsquerydb" MDSs' in sent
    assert ssh.closed is True  # transport is always closed


def test_discover_firewalls_flags_existing_and_maps_roles() -> None:
    inv = _inventory(
        Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS),
        Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY),
    )
    connector = _FakeConnector(inv, _api_bundle())
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient(GATEWAYS_AND_SERVERS, **kw),
    )

    # No source server is passed — an environment has exactly one primary, so
    # it's resolved via primary_mgmt_host() instead of an operator-picked name.
    result = service.discover_firewalls("default")
    by_name = {s.name: s for s in result.servers}

    assert set(by_name) == {"fw-01", "cluster-01"}
    assert by_name["fw-01"].already_in_inventory is True  # already a firewall in inventory
    assert by_name["cluster-01"].already_in_inventory is False
    assert by_name["cluster-01"].detected_role is Role.CLUSTER_MEMBER
    assert not result.warnings


def test_discover_firewalls_mds_without_domain_asks_operator_to_pick_one() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    connector = _FakeConnector(inv, _api_bundle(), is_mds=True)
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient([], **kw),
    )

    result = service.discover_firewalls("default")
    assert result.servers == []
    assert any("select a Domain" in w for w in result.warnings)


def test_discover_firewalls_mds_scans_the_chosen_domain() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    connector = _FakeConnector(inv, _api_bundle(), is_mds=True)
    seen_kwargs: list[dict[str, object]] = []

    def factory(host: object, **kw: object) -> _FakeMgmtClient:
        seen_kwargs.append(kw)
        return _FakeMgmtClient(GATEWAYS_AND_SERVERS, **kw)

    service = DiscoveryService(_FakeRegistry(connector), mgmt_client_factory=factory)  # type: ignore[arg-type]
    result = service.discover_firewalls("default", domain="Domain1")

    assert seen_kwargs[0]["domain"] == "Domain1"
    by_name = {s.name: s for s in result.servers}
    assert set(by_name) == {"fw-01", "cluster-01"}
    assert not result.warnings


def test_list_domains_logs_in_without_a_domain_and_returns_names() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    connector = _FakeConnector(inv, _api_bundle(), is_mds=True)
    seen_kwargs: list[dict[str, object]] = []
    domains = [{"name": "Domain2"}, {"name": "Domain1"}]

    def factory(host: object, **kw: object) -> _FakeMgmtClient:
        seen_kwargs.append(kw)
        return _FakeMgmtClient([], domains=domains, **kw)

    service = DiscoveryService(_FakeRegistry(connector), mgmt_client_factory=factory)  # type: ignore[arg-type]
    result = service.list_domains("default")

    assert "domain" not in seen_kwargs[0]  # show-domains needs the MDS system context
    assert result.domains == ["Domain1", "Domain2"]  # sorted
    assert not result.warnings


def test_list_domains_api_failure_becomes_warning() -> None:
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    connector = _FakeConnector(inv, _api_bundle(), is_mds=True)

    def boom(host: object, **kw: object) -> _FakeMgmtClient:
        raise TransportError("connection refused")

    service = DiscoveryService(_FakeRegistry(connector), mgmt_client_factory=boom)  # type: ignore[arg-type]
    result = service.list_domains("default")
    assert result.domains == []
    assert any("Management API domain lookup failed" in w for w in result.warnings)


def test_discover_mds_nonzero_exit_surfaces_command_and_status() -> None:
    # This exact command has been wrong multiple times already — the warning
    # must carry enough of the real failure (command, exit status, stderr) that
    # the next miss is diagnosable from the UI alone, not another guess.
    inv = _inventory(Host(name="mds-primary", address="10.0.0.1", role=Role.PRIMARY_MDS))
    ssh = FakeTransport(fail_rc=127)
    connector = _FakeConnector(inv, _api_bundle(), ssh=ssh, is_mds=True)
    service = DiscoveryService(
        _FakeRegistry(connector),  # type: ignore[arg-type]
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient([], **kw),
    )

    result = service.discover("default", "mds-primary")
    assert any("$MDSDIR/scripts/mdsquerydb" in w and "127" in w for w in result.warnings)
