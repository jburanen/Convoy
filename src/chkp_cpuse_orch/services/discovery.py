"""Estate discovery — enumerate the management plane from the primary server.

Given one management server the operator has already defined, connect to it and
discover the *rest* of the estate so they don't have to type every box in by hand.
Which command variants run is decided by the environment's declared kind
(``HostConnector.is_mds`` — set once per environment, see services/environments.py),
not by the primary's own role: an environment is always entirely SMS or entirely
Multi-Domain, never a mix.

- **SMS side** via the Check Point **Management API** (``show-gateways-and-servers``):
  other management servers, dedicated Log Servers, and SmartEvent servers.
- **MDS side, Global domain** via the same API call, logged into the ``Global``
  domain instead of a specific Domain/CMA: SmartEvent servers shared across the
  Multi-Domain deployment live there rather than in any one Domain.
- **MDS side, peer MDS/MLM boxes** via SSH on a Multi-Domain Server. A plain SSH
  exec on Gaia loads **none** of the Check Point environment — not ``PATH``,
  not ``$MDSDIR``, not even base utilities like ``cpprod_util`` (confirmed
  2026-07-22 from a live failure's stderr). So the command locates the MDS
  install directory on disk via a glob (``/opt/CPmds-R*`` — versioned, hence
  no hardcoded path) and exports ``$MDSDIR`` itself before invoking
  ``scripts/mdsquerydb MDSs``, rather than depending on anything being
  pre-set. The other MDS/MLM peers come back by name + IP. The API does not
  expose these, and
  ``mdsquerydb`` itself doesn't report Primary/Secondary/MLM role — only the peer
  matching the address we connected to is inferred as primary; every other MDS peer
  is flagged ``needs_review`` for the operator to classify.

This layer only *maps* discovered objects to roles and marks what is already in the
inventory; it never writes. The web layer presents the result in an editable review
table and the operator confirms before anything is imported (reusing the normal
add-server path). Detection is best-effort — especially primary-vs-secondary — so
ambiguous rows are flagged ``needs_review`` for the operator to correct. See
.claude/memory/architecture.md (thin wrappers, decisions in services).

Firewall discovery (``discover_firewalls``) never takes a source-server argument —
an environment has exactly one primary (SMS or MDS), so ``HostConnector.primary_mgmt_host``
resolves it instead of asking the operator to pick. On an MDS, gateways live inside a
specific Domain/CMA, so the operator picks one first via ``list_domains`` (``show-domains``,
logged in with no ``domain`` — that's the MDS system context, above any single Domain or
``Global``) and the UI passes it back in as ``domain``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Protocol

from ..credentials import CredentialKind
from ..errors import CredentialError, OrchestratorError, TransportError
from ..inventory import Host, Role
from ..reporting import get_logger
from ..transport.mgmt_api import ManagementAPIClient
from .common import EnvironmentRegistry, HostConnector

logger = get_logger(__name__)


@dataclass
class DiscoveredServer:
    """One server the discovery scan found, with its best-guess role."""

    name: str
    address: str
    detected_role: Role
    source: str  # "api" | "ssh"
    already_in_inventory: bool = False
    needs_review: bool = False
    note: str | None = None
    # Real SmartConsole cluster object name, resolved via the Management API
    # (show-simple-clusters) at discovery time — see find_cluster_for_gateway.
    # None when not a cluster member, or when the lookup wasn't possible.
    cluster_name: str | None = None


@dataclass
class DiscoveryResult:
    servers: list[DiscoveredServer] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class DomainsResult:
    domains: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class MgmtClientContext(Protocol):
    """The slice of ManagementAPIClient discovery uses (as a context manager)."""

    def __enter__(self) -> Any: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
    def show_gateways_and_servers(self, *, details_level: str = ...) -> list[dict[str, Any]]: ...
    def show_simple_clusters(self, *, details_level: str = ...) -> list[dict[str, Any]]: ...
    def show_domains(self) -> list[dict[str, Any]]: ...


# Factory so tests can inject a fake API client without a live server.
MgmtClientFactory = Callable[..., MgmtClientContext]


def _default_mgmt_client_factory(host: Host, **kwargs: Any) -> MgmtClientContext:
    return ManagementAPIClient(host, **kwargs)


class DiscoveryService:
    """Discover the management estate reachable from a primary server."""

    def __init__(
        self,
        registry: EnvironmentRegistry,
        *,
        mgmt_client_factory: MgmtClientFactory | None = None,
    ) -> None:
        self._registry = registry
        self._mgmt_client_factory = mgmt_client_factory or _default_mgmt_client_factory

    def discover_firewalls(self, environment: str, *, domain: str | None = None) -> DiscoveryResult:
        """Scan the estate from the environment's primary management server for
        firewalls (gateways/cluster members) instead of management-plane
        servers — same Management API call, opposite half of the object list.
        Only the API side applies (mdsquerydb only enumerates MDS peers, not
        gateways).

        An environment has exactly one primary (SMS or MDS), so the caller
        never names a source server here — ``primary_mgmt_host`` resolves it.
        On an MDS, gateways live inside a specific Domain/CMA rather than the
        Global domain, so the caller must supply which ``domain`` to scan
        (see ``list_domains``)."""
        connector = self._registry.get(environment)
        primary = connector.primary_mgmt_host()
        bundle = connector.host_credentials(primary)

        result = DiscoveryResult()
        existing = connector.firewalls()
        existing_names = {h.name for h in existing}
        existing_addrs = {h.address for h in existing}

        is_mds = connector.is_mds
        if is_mds:
            if not domain:
                result.warnings.append(
                    "This is a Multi-Domain environment — select a Domain to discover "
                    "firewalls from."
                )
                return result
            self._discover_firewalls_via_api(primary, bundle, result, domain=domain)
        else:
            self._discover_firewalls_via_api(primary, bundle, result, domain=None)

        deduped: list[DiscoveredServer] = []
        seen: set[str] = set()
        for srv in result.servers:
            key = srv.address or srv.name
            if key in seen:
                continue
            seen.add(key)
            srv.already_in_inventory = srv.name in existing_names or srv.address in existing_addrs
            deduped.append(srv)
        result.servers = deduped
        return result

    def list_domains(self, environment: str) -> DomainsResult:
        """Enumerate the Domains (CMAs) a Multi-Domain environment's primary
        MDS knows about, so the operator can pick which one to scope firewall
        discovery into. Logs in with no ``domain`` in the payload — that's
        reserved for a specific Domain or the ``Global`` domain, while
        ``show-domains`` operates at the MDS system level, above either."""
        connector = self._registry.get(environment)
        primary = connector.primary_mgmt_host()
        bundle = connector.host_credentials(primary)

        result = DomainsResult()
        try:
            auth = _api_auth(bundle)
        except CredentialError as exc:
            result.warnings.append(str(exc))
            return result
        try:
            with self._mgmt_client_factory(primary, **auth) as client:
                objects = client.show_domains()
        except TransportError as exc:
            result.warnings.append(f"Management API domain lookup failed: {exc}")
            return result
        result.domains = sorted({str(o.get("name") or "").strip() for o in objects} - {""})
        return result

    def _discover_firewalls_via_api(
        self,
        primary: Host,
        bundle: dict[CredentialKind, Any],
        result: DiscoveryResult,
        *,
        domain: str | None = None,
    ) -> None:
        try:
            auth = _api_auth(bundle)
        except CredentialError as exc:
            result.warnings.append(str(exc))
            return
        if domain is not None:
            auth = {**auth, "domain": domain}
        try:
            with self._mgmt_client_factory(primary, **auth) as client:
                objects = client.show_gateways_and_servers(details_level="full")
                # Best-effort: cluster names are a nice-to-have on top of the
                # gateway list, so a failure here (unsupported command on an
                # older management version, etc.) warns rather than discarding
                # the gateways just fetched.
                try:
                    clusters = client.show_simple_clusters(details_level="full")
                except TransportError as exc:
                    result.warnings.append(
                        f"Management API cluster lookup failed (cluster names won't be "
                        f"pre-filled): {exc}"
                    )
                    clusters = []
        except TransportError as exc:
            result.warnings.append(f"Management API discovery failed: {exc}")
            return
        servers = map_gateways_only(objects)
        for srv in servers:
            srv.cluster_name = find_cluster_for_gateway(clusters, srv.name)
        result.servers.extend(servers)

    def find_cluster_name(
        self, environment: str, gateway_name: str, *, domain: str | None = None
    ) -> str | None:
        """Best-effort live lookup of one gateway's real cluster object name
        via the Management API — backs the Firewalls panel's "re-check
        cluster membership" button for firewalls that weren't picked up
        automatically at discovery time (manually added, or added before this
        shipped). Never raises: no primary configured, no usable credentials,
        an unreachable API, or the gateway genuinely not being a cluster
        member all just resolve to None, same as "not a cluster member".

        MDS environments need a Domain to log into to see any clusters at
        all, and which Domain a given firewall lives in isn't tracked
        per-firewall today — callers there should pass ``domain`` if they
        know it; without one this always returns None rather than guessing."""
        connector = self._registry.get(environment)
        try:
            primary = connector.primary_mgmt_host()
            bundle = connector.host_credentials(primary)
            auth = _api_auth(bundle)
        except OrchestratorError:
            return None
        if domain is not None:
            auth = {**auth, "domain": domain}
        try:
            with self._mgmt_client_factory(primary, **auth) as client:
                clusters = client.show_simple_clusters(details_level="full")
        except TransportError:
            return None
        return find_cluster_for_gateway(clusters, gateway_name)

    def discover(self, environment: str, primary_host_name: str) -> DiscoveryResult:
        connector = self._registry.get(environment)
        primary = connector.mgmt_host(primary_host_name)  # validates it's a mgmt role
        # Credentials must be resolvable up front — a locked store or an unassigned
        # server is an actionable operator error, not a partial-scan warning.
        bundle = connector.host_credentials(primary)

        result = DiscoveryResult()
        existing = [h for site in connector.inventory.sites for h in site.hosts]
        existing_names = {h.name for h in existing}
        existing_addrs = {h.address for h in existing}

        # The environment declares SMS vs MDS once (services/environments.py) —
        # that, not the primary's own role, decides which command variants apply.
        is_mds = connector.is_mds
        # On an MDS, SmartEvent (and other shared) servers live in the Global
        # domain, not the per-Domain view — log in there instead of the default.
        self._discover_via_api(primary, bundle, result, domain="Global" if is_mds else None)
        if is_mds:
            self._discover_mds_via_ssh(connector, primary, result)
        # else: an SMS scan can't see MDS peers; nothing more to do.

        # Drop the primary itself; flag rows already in the inventory.
        deduped: list[DiscoveredServer] = []
        seen: set[str] = set()
        for srv in result.servers:
            key = srv.address or srv.name
            if key in seen:
                continue
            seen.add(key)
            srv.already_in_inventory = srv.name in existing_names or srv.address in existing_addrs
            deduped.append(srv)
        result.servers = deduped
        return result

    # -- Management API side (SMS domain, or MDS Global domain) ------------------

    def _discover_via_api(
        self,
        primary: Host,
        bundle: dict[CredentialKind, Any],
        result: DiscoveryResult,
        *,
        domain: str | None = None,
    ) -> None:
        try:
            auth = _api_auth(bundle)
        except CredentialError as exc:
            result.warnings.append(str(exc))
            return
        if domain is not None:
            auth = {**auth, "domain": domain}
        try:
            with self._mgmt_client_factory(primary, **auth) as client:
                objects = client.show_gateways_and_servers(details_level="full")
        except TransportError as exc:
            result.warnings.append(f"Management API discovery failed: {exc}")
            return
        result.servers.extend(map_gateways_and_servers(objects, primary.address))

    # -- MDS side (SSH) ----------------------------------------------------------

    def _discover_mds_via_ssh(
        self, connector: HostConnector, primary: Host, result: DiscoveryResult
    ) -> None:
        try:
            client = connector.connect(primary)
        except (CredentialError, TransportError) as exc:
            result.warnings.append(f"MDS SSH discovery skipped: {exc}")
            return
        # Nothing Check Point-specific is loaded in this session at all — not
        # PATH, not $MDSDIR, not even the base `cpprod_util` (confirmed 2026-07-22
        # from a live failure's stderr: `$MDSDIR/scripts/mdsquerydb` resolved to
        # bare `/scripts/mdsquerydb`, i.e. $MDSDIR was empty). So don't depend on
        # any pre-set env var — locate the MDS install dir on disk (versioned,
        # hence the glob) and export it ourselves for just this command, in case
        # the script needs $MDSDIR internally once invoked.
        command = (
            "MDSDIR=$(ls -d /opt/CPmds-R* 2>/dev/null | head -1); "
            'export MDSDIR; "$MDSDIR/scripts/mdsquerydb" MDSs'
        )
        try:
            out = client.run(command)
        except TransportError as exc:
            result.warnings.append(f"MDS enumeration failed: {exc}")
            return
        finally:
            client.close()
        if out.exit_status != 0:
            # Surface the real exit status + stderr instead of a generic message —
            # this exact command has been wrong twice already (see
            # .claude/memory/mds-discovery-command.md); guessing a third fix
            # without seeing the actual failure isn't worth shipping again.
            stderr = out.stderr.strip() or "(no stderr)"
            result.warnings.append(
                f"MDS enumeration returned no data: `{command}` exited {out.exit_status}: {stderr}"
            )
            return
        rows = parse_mdsquerydb_mdss(out.stdout, primary.address)
        if not rows:
            result.warnings.append("Could not parse mdsquerydb MDSs output")
        result.servers.extend(rows)


# ---- pure mapping helpers (unit-tested without live gear) -----------------------

# Object types that are gateways / cluster members — never management-plane servers.
_GATEWAY_HINTS = ("gateway", "cluster", "vsx", "vs-cluster", "gateway-cluster")


def map_gateways_and_servers(
    objects: list[dict[str, Any]], primary_address: str
) -> list[DiscoveredServer]:
    """Map ``show-gateways-and-servers`` objects to management-plane servers.

    Gateways and cluster members are dropped (CDT discovers those). The first
    management server matching the primary's address is treated as Primary SMS; any
    other management server is flagged Secondary SMS + needs_review, since telling
    primary from secondary reliably needs the HA object."""
    out: list[DiscoveredServer] = []
    for obj in objects:
        role, needs_review, note = _role_for_object(obj, primary_address)
        if role is None:
            continue
        name = str(obj.get("name") or "").strip()
        address = str(obj.get("ipv4-address") or obj.get("ipv6-address") or "").strip()
        if not name and not address:
            continue
        out.append(
            DiscoveredServer(
                name=name or address,
                address=address,
                detected_role=role,
                source="api",
                needs_review=needs_review,
                note=note,
            )
        )
    return out


def _role_for_object(
    obj: dict[str, Any], primary_address: str
) -> tuple[Role | None, bool, str | None]:
    type_ = str(obj.get("type") or "").lower()
    blades = obj.get("management-blades") or {}
    if not isinstance(blades, dict):
        blades = {}

    # Gateways / clusters are out of scope (management server types never carry
    # these tokens).
    if any(h in type_ for h in _GATEWAY_HINTS) and "management" not in type_:
        return None, False, None

    is_mgmt = _truthy_any(blades, ("network-policy-management", "management")) or (
        "management" in type_ or "cpmihostckp" in type_ or "checkpoint-host" in type_
    )
    is_log = "log" in type_ or _truthy_any(blades, ("logging-and-status",))
    is_smartevent = (
        "smart-event" in type_
        or "smartevent" in type_
        or _truthy_any(blades, ("smart-event-server", "smart-event-correlation"))
    )

    address = str(obj.get("ipv4-address") or obj.get("ipv6-address") or "").strip()

    # Dedicated SmartEvent / Log servers are boxes that aren't primarily management.
    if is_smartevent and not is_mgmt:
        return Role.SMARTEVENT, False, "SmartEvent server"
    if is_log and not is_mgmt:
        return Role.LOG_SERVER, False, "Log Server"
    if is_mgmt:
        if address and address == primary_address:
            return Role.PRIMARY_SMS, False, None
        note = "SmartEvent enabled" if is_smartevent else None
        return Role.SECONDARY_SMS, True, note or "confirm primary vs secondary"
    return None, False, None


def map_gateways_only(objects: list[dict[str, Any]]) -> list[DiscoveredServer]:
    """Map ``show-gateways-and-servers`` objects to firewalls (gateways/cluster
    members) — the mirror image of map_gateways_and_servers, which drops these
    same objects because they're never management-plane servers."""
    out: list[DiscoveredServer] = []
    for obj in objects:
        type_ = str(obj.get("type") or "").lower()
        # Same test map_gateways_and_servers uses to *drop* these objects,
        # kept here to *keep* them instead.
        if not (any(h in type_ for h in _GATEWAY_HINTS) and "management" not in type_):
            continue
        name = str(obj.get("name") or "").strip()
        address = str(obj.get("ipv4-address") or obj.get("ipv6-address") or "").strip()
        if not name and not address:
            continue
        is_cluster = any(h in type_ for h in ("cluster", "vs-cluster", "gateway-cluster"))
        role = Role.CLUSTER_MEMBER if is_cluster else Role.GATEWAY
        note = "VSX" if "vsx" in type_ else None
        out.append(
            DiscoveredServer(
                name=name or address,
                address=address,
                detected_role=role,
                source="api",
                needs_review=False,
                note=note,
            )
        )
    return out


def _truthy_any(blades: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(bool(blades.get(k)) for k in keys)


def _cluster_member_names(cluster: dict[str, Any]) -> list[str]:
    """Names out of one `show-simple-clusters` object's ``members`` field.
    The exact member shape isn't confirmed against live gear (Check Point's
    own docs describe it only as a "typical" pattern), so this tolerates
    both a bare list of name strings and a list of ``{"name": ...}`` objects
    — same defensive approach as cpuse.py's output parsing."""
    members = cluster.get("members")
    if not isinstance(members, list):
        return []
    names: list[str] = []
    for m in members:
        if isinstance(m, dict):
            name = m.get("name")
            if name:
                names.append(str(name))
        elif isinstance(m, str) and m:
            names.append(m)
    return names


def find_cluster_for_gateway(clusters: list[dict[str, Any]], gateway_name: str) -> str | None:
    """Which cluster (by its real SmartConsole name) a gateway/cluster-member
    belongs to, given `show-simple-clusters` objects. Matched case-
    insensitively against each cluster's member names. None if no cluster
    lists this gateway as a member."""
    target = gateway_name.strip().lower()
    if not target:
        return None
    for cluster in clusters:
        if any(name.strip().lower() == target for name in _cluster_member_names(cluster)):
            cname = cluster.get("name")
            return str(cname).strip() or None if cname else None
    return None


# `mdsenv; mdsquerydb MDSs` returns each MDS as a name + IP pair (tab/space
# delimited) — it does not report Primary/Secondary/MLM role, so we can only
# infer the primary (it's the address we're already connected to) and flag
# every other peer needs_review for the operator to classify.
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_mdsquerydb_mdss(text: str, primary_address: str) -> list[DiscoveredServer]:
    servers: list[DiscoveredServer] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ip_match = _IP_RE.search(line)
        if not ip_match:
            continue  # header/banner noise — a data row always has an IP
        address = ip_match.group(1)
        name = _first_field(line) or address
        is_primary = address == primary_address
        note = None if is_primary else "mdsquerydb doesn't report role — confirm Secondary vs MLM"
        servers.append(
            DiscoveredServer(
                name=name,
                address=address,
                detected_role=Role.PRIMARY_MDS if is_primary else Role.SECONDARY_MDS,
                source="ssh",
                needs_review=not is_primary,
                note=note,
            )
        )
    return servers


def _first_field(line: str) -> str:
    # The first token that isn't an IP address — usually the MDS object name.
    for token in re.split(r"[\s,]+", line):
        if token and not _IP_RE.fullmatch(token):
            return token
    return ""


def _api_auth(bundle: dict[CredentialKind, Any]) -> dict[str, Any]:
    """Build Management API auth kwargs from a credential bundle: prefer an API key,
    else the SSH username/password (the Gaia admin usually doubles as the API user)."""
    api_key_cred = bundle.get(CredentialKind.API_KEY)
    if api_key_cred is not None:
        return {"api_key": api_key_cred.reveal()}
    pw_cred = bundle.get(CredentialKind.SSH_PASSWORD)
    if pw_cred is not None and pw_cred.username:
        return {"username": pw_cred.username, "password": pw_cred.reveal()}
    raise CredentialError(
        "the credential set assigned to the primary has no API key or "
        "username/password — add one on the Provisioning tab to run discovery"
    )


__all__ = [
    "DiscoveredServer",
    "DiscoveryResult",
    "DiscoveryService",
    "DomainsResult",
    "find_cluster_for_gateway",
    "map_gateways_and_servers",
    "map_gateways_only",
    "parse_mdsquerydb_mdss",
]
