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
    MANAGEMENT = "management"  # Security Management Server (patched via CPUSE)
    MDS = "mds"  # Multi-Domain Server
    GATEWAY = "gateway"  # Security Gateway (patched via CDT)
    CLUSTER_MEMBER = "cluster_member"  # Gateway that is part of a ClusterXL/HA cluster


class Host(BaseModel):
    """A single Gaia host reachable over SSH / Gaia API."""

    name: str
    address: str  # hostname or IP; resolved at connect time
    role: Role
    ssh_port: int = 22
    ssh_user: str = "admin"
    # Credentials are never stored in inventory — they live in the encrypted
    # CredentialStore (added via the web UI), keyed by host + environment.
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
