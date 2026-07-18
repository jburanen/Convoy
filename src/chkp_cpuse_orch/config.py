"""Global tool configuration.

Secrets (SSH passwords, API keys) are NEVER stored here or in tracked files — they
are resolved at runtime from the environment or an external secrets store. This
module only carries non-sensitive defaults and paths. See
.claude/memory/security-hygiene.md.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .errors import ConfigError


class DeploymentDefaults(BaseModel):
    """Conservative defaults for a deployment run. Overridable per-run."""

    dry_run: bool = True
    """Mutating operations preview by default; real execution is opt-in."""

    max_concurrent_gateways: int = Field(default=2, ge=1)
    """Blast-radius cap: how many gateways CDT may target at once."""

    reboot_after_install: bool = True
    stop_on_first_failure: bool = True
    snapshot_before_install: bool = True


class Paths(BaseModel):
    """Filesystem locations for runtime output (all git-ignored)."""

    reports_dir: Path = Path("reports")
    logs_dir: Path = Path("logs")
    state_dir: Path = Path("state")
    # SQLite DB for jobs / credential ciphertext / package metadata. In the
    # container this lives on the bind-mounted /data volume (git-ignored).
    db_path: Path = Path("state") / "orch.db"
    # Uploaded package files (JHFs, upgrades). Also git-ignored / on /data.
    packages_dir: Path = Path("packages")


class Config(BaseModel):
    """Top-level tool configuration."""

    defaults: DeploymentDefaults = DeploymentDefaults()
    paths: Paths = Paths()

    # Name of the maintenance window policy to enforce (looked up elsewhere).
    maintenance_window: str | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load config from YAML, falling back to built-in defaults.

        Resolution order: explicit ``path`` → ``$CHKP_CPUSE_CONFIG`` → defaults.
        """
        candidate = path or os.environ.get("CHKP_CPUSE_CONFIG")
        if candidate is None:
            return cls()
        p = Path(candidate)
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - passthrough
            raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
        return cls.model_validate(data)


def resolve_secret(name: str) -> str:
    """Resolve a secret by name from the environment (never from tracked files).

    Swap this for a real secrets-store client (Vault, cyberark, etc.) as needed.
    """
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"secret {name!r} not found in environment. "
            "Secrets must come from the environment or a secrets store, not files."
        )
    return value
