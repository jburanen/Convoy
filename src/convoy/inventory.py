"""Inventory models: the estate of management servers, firewalls, and clusters.

Real inventory files name production infrastructure and are git-ignored; only
``*.example.yaml`` templates are tracked. See .claude/memory/security-hygiene.md.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from .errors import InventoryError

# One DNS label: alphanumeric, inner hyphens allowed, no leading/trailing hyphen.
_HOSTNAME_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\Z")


def _valid_hostname(value: str) -> bool:
    """True if ``value`` is a syntactically valid hostname/FQDN (RFC 1123),
    optionally fully qualified with a trailing dot."""
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > 253:
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in candidate.split("."))


class Role(StrEnum):
    # Management-plane roles — Gaia hosts this tool connects to and patches locally
    # via CPUSE. All seven are offered in the UI role picker.
    PRIMARY_SMS = "primary_sms"  # Primary Security Management Server
    SECONDARY_SMS = "secondary_sms"  # Secondary (HA) Security Management Server
    LOG_SERVER = "log_server"  # dedicated Log Server
    PRIMARY_MDS = "primary_mds"  # Primary Multi-Domain Server
    SECONDARY_MDS = "secondary_mds"  # Secondary (HA) Multi-Domain Server
    MLM = "mlm"  # Multi-Domain Log Module
    SMARTEVENT = "smartevent"  # dedicated SmartEvent server
    # Legacy coarse roles — kept so pre-existing DB rows still load. Not offered in
    # the UI picker anymore; treated as management-plane for gating.
    MANAGEMENT = "management"  # legacy: Security Management Server → see PRIMARY_SMS
    MDS = "mds"  # legacy: Multi-Domain Server → see PRIMARY_MDS
    # Firewalls, patched directly via CPUSE (one host at a time — see
    # FIREWALL_ROLES/firewalls.py). CDT's bulk firewall-fleet push is a separate
    # subsystem that discovers its own targets and never stores them here.
    # FIREWALL is the plain standalone case; the other two below are firewalls
    # as well, which is why FIREWALL_ROLES exists and this member is not the
    # whole category.
    FIREWALL = "firewall"  # standalone firewall, not part of a cluster
    CLUSTER_MEMBER = "cluster_member"  # firewall that is part of a ClusterXL/HA cluster
    # Quantum Spark (SMB) appliance, detected via operating-system == "Gaia
    # Embedded" (see services/discovery.py). Patched directly via CPUSE like
    # any other firewall (services/common.py) — still NOT wired into CDT
    # bulk-deploy (orchestrator.py), which is a separate subsystem firewalls
    # opt into via Role.FIREWALL/CLUSTER_MEMBER only.
    SPARK_FIREWALL = "spark_firewall"  # Quantum Spark (SMB) appliance

    @classmethod
    def _missing_(cls, value: object) -> Role | None:
        """Resolve retired role spellings to the member that replaced them, so
        inventory YAML and DB rows written by an older build keep loading.
        Every construction path — pydantic validation, ``Role(row["role"])`` in
        store.py, the UI's role picker — goes through here."""
        if isinstance(value, str):
            replacement = _RETIRED_ROLE_VALUES.get(value.strip().lower())
            if replacement is not None:
                return cls(replacement)
        return None


# Role values this tool used to write, mapped to the member that replaced them.
# "gateway" was renamed to "firewall" in v1.1.0 when the estate-wide "Security
# Gateway" wording was dropped; store.py's v30 migration rewrites the stored
# rows, and this covers everything the migration cannot reach — inventory YAML
# on disk, and a role string that arrives from an older client.
_RETIRED_ROLE_VALUES: dict[str, str] = {"gateway": "firewall"}


# Roles that make a host a "management-plane" box this tool connects to and patches
# locally via CPUSE (as opposed to firewalls, which CDT discovers at deploy time).
# The seven granular roles are offered in the UI; the two legacy coarse roles are
# still accepted so pre-existing inventory/DB rows keep loading.
MANAGEMENT_PLANE_ROLES: tuple[Role, ...] = (
    Role.PRIMARY_SMS,
    Role.SECONDARY_SMS,
    Role.LOG_SERVER,
    Role.PRIMARY_MDS,
    Role.SECONDARY_MDS,
    Role.MLM,
    Role.SMARTEVENT,
    Role.MANAGEMENT,  # legacy
    Role.MDS,  # legacy
)

# Roles for firewalls patched directly via CPUSE (one host at a time — distinct
# from CDT's bulk firewall-fleet push, which discovers its own targets and never
# stores them here).
FIREWALL_ROLES: tuple[Role, ...] = (
    Role.FIREWALL,
    Role.CLUSTER_MEMBER,
    Role.SPARK_FIREWALL,
)


class Host(BaseModel):
    """A single Gaia host reachable over SSH / Gaia API."""

    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=253)  # hostname or IP; resolved at connect time
    role: Role
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = "admin"
    # Credentials are never stored in inventory — they live in the encrypted
    # CredentialStore as named "login sets". A management server references the set
    # assigned to it (credential_sets.id); None when unassigned. Populated from the
    # DB (env_hosts) at registry build time, not from inventory YAML.
    credential_set_id: str | None = None
    notes: str | None = None
    # Smart-1 Cloud only: the tenant UUID that sits between the host and
    # /web_api in that estate's Management API URL —
    # https://<prefix>.maas.checkpoint.com/<tenant-uuid>/web_api. None for every
    # on-prem server, where the API is served straight off the host itself.
    mgmt_api_context: str | None = None

    @field_validator("mgmt_api_context", mode="before")
    @classmethod
    def _check_mgmt_api_context(cls, value: object) -> object:
        """This is interpolated straight into a URL path, so it is held to the
        shape Smart-1 Cloud actually issues — a bare identifier. Anything
        carrying a slash, a scheme, or whitespace could point the Management API
        somewhere other than what the row says, and the API key assigned to this
        row goes wherever that URL leads."""
        if not isinstance(value, str):
            return value
        context = value.strip().strip("/")
        if not context:
            return None
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", context):
            raise ValueError(
                f"{value!r} is not a valid Management API context — it must be a bare "
                "identifier (the tenant UUID), with no scheme, slashes, or whitespace"
            )
        return context

    @field_validator("name", "ssh_user", mode="before")
    @classmethod
    def _strip_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("address", mode="before")
    @classmethod
    def _check_address(cls, value: object) -> object:
        """``address`` is the only field tying an inventory row to a specific
        real device — every SSH connection, every stored-credential handoff,
        and (via services/firewall_bootstrap.py) the confirmation that a
        Management API target is the box we think it is, all rest on it. An
        unvalidated free-form string here means a row can be pointed at an
        arbitrary host, so require a syntactically real IP or hostname and
        reject URL-shaped, whitespace-bearing, or empty values outright."""
        if not isinstance(value, str):
            return value
        address = value.strip()
        if not address:
            raise ValueError("address must not be empty")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            if not _valid_hostname(address):
                raise ValueError(
                    f"{address!r} is not a valid IP address or hostname — an address must "
                    "be a bare host (no scheme, port, path, credentials, or whitespace)"
                ) from None
        return address


class Cluster(BaseModel):
    """A ClusterXL / HA cluster. Member order matters for safe rollout."""

    name: str
    members: list[str] = Field(min_length=1)  # Host.name references, in patch order
    # Patch order is standby-first; the orchestrator confirms live roles at runtime
    # rather than trusting this list blindly. See .claude/memory/safety-constraints.md.


class Site(BaseModel):
    """A logical grouping (data center / region) of hosts and clusters."""

    name: str
    hosts: list[Host] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)


class Inventory(BaseModel):
    """The full estate."""

    sites: list[Site] = Field(default_factory=list)

    def host(self, name: str) -> Host:
        for site in self.sites:
            for h in site.hosts:
                if h.name == name:
                    return h
        raise InventoryError(f"host not found in inventory: {name!r}")

    def hosts_by_role(self, role: Role) -> list[Host]:
        return [h for s in self.sites for h in s.hosts if h.role == role]

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        p = Path(path)
        if not p.is_file():
            raise InventoryError(f"inventory file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - passthrough
            raise InventoryError(f"invalid YAML in {p}: {exc}") from exc
        return cls.model_validate(data)
