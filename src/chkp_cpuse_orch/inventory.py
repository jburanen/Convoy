"""Inventory models: the estate of management servers, gateways, and clusters.

Real inventory files name production infrastructure and are git-ignored; only
``*.example.yaml`` templates are tracked. See .claude/memory/security-hygiene.md.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .errors import InventoryError


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
    # Gateways are discovered by CDT at deploy time, never added to this inventory.
    GATEWAY = "gateway"  # Security Gateway (patched via CDT)
    CLUSTER_MEMBER = "cluster_member"  # Gateway that is part of a ClusterXL/HA cluster


# Roles that make a host a "management-plane" box this tool connects to and patches
# locally via CPUSE (as opposed to gateways, which CDT discovers at deploy time).
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


class Host(BaseModel):
    """A single Gaia host reachable over SSH / Gaia API."""

    name: str
    address: str  # hostname or IP; resolved at connect time
    role: Role
    ssh_port: int = 22
    ssh_user: str = "admin"
    # Credentials are never stored in inventory — they live in the encrypted
    # CredentialStore as named "login sets". A management server references the set
    # assigned to it (credential_sets.id); None when unassigned. Populated from the
    # DB (env_hosts) at registry build time, not from inventory YAML.
    credential_set_id: str | None = None
    notes: str | None = None


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
