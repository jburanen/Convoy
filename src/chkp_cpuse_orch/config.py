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

# Uploaded packages are auto-deleted this many days after upload unless the
# operator pins them ("store indefinitely"). The default is overridable at
# runtime via this environment variable (see Config.load); 0 disables expiry.
PACKAGE_RETENTION_ENV = "CHKP_CPUSE_PACKAGE_RETENTION_DAYS"
DEFAULT_PACKAGE_RETENTION_DAYS = 30


class DeploymentDefaults(BaseModel):
    """Conservative defaults for a deployment run. Overridable per-run."""

    dry_run: bool = True
    """Mutating operations preview by default; real execution is opt-in."""

    max_concurrent_gateways: int = Field(default=2, ge=1)
    """Blast-radius cap: how many gateways CDT may target at once."""

    # NOTE: reboot_after_install / stop_on_first_failure / snapshot_before_install
    # used to be declared here and shipped in config.example.yaml. Nothing ever
    # read them, so operators could reasonably believe a rollback snapshot was
    # being taken when none was — a shipped-but-inert safety setting is worse
    # than an absent one. Removed rather than commented; re-add them together
    # with the code that honours them.


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
    # Flat-file archive of job records + progress logs (and any captured CPUSE
    # install-log text) purged from the DB after they age out — see archive.py.
    # Also git-ignored / on /data.
    job_archive_path: Path = Path("state") / "job_archive.log"
    # Estate inventory (real file is git-ignored; see examples/inventory.example.yaml).
    inventory_path: Path = Path("inventory.yaml")


class EnvironmentDef(BaseModel):
    """One independent management environment: its own inventory of management
    servers (and thus its own CDT-discovered gateways) and its own credential
    namespace. Packages and the underlying database stay shared."""

    name: str = Field(pattern=r"[a-z0-9][a-z0-9_-]{0,31}")
    inventory: Path


DEFAULT_ENVIRONMENT = "default"


class Config(BaseModel):
    """Top-level tool configuration."""

    defaults: DeploymentDefaults = DeploymentDefaults()
    paths: Paths = Paths()

    # Uploaded packages are auto-deleted after this many days unless the operator
    # pins one to keep it indefinitely. 0 disables automatic expiry entirely.
    # Overridable at runtime via $CHKP_CPUSE_PACKAGE_RETENTION_DAYS (see load()).
    package_retention_days: int = Field(default=DEFAULT_PACKAGE_RETENTION_DAYS, ge=0)

    # Independent management environments. Empty → one implicit "default"
    # environment backed by paths.inventory_path (backward compatible).
    environments: list[EnvironmentDef] = Field(default_factory=list)

    # NOTE: maintenance_window was declared here and shipped in the example
    # config, but no code ever consulted it — no run was ever gated on a window.
    # Removed for the same reason as the defaults above; re-add it with the
    # enforcement, not before.

    def resolved_environments(self) -> list[EnvironmentDef]:
        if self.environments:
            names = [e.name for e in self.environments]
            if len(names) != len(set(names)):
                raise ConfigError(f"duplicate environment names in config: {names}")
            return self.environments
        return [EnvironmentDef(name=DEFAULT_ENVIRONMENT, inventory=self.paths.inventory_path)]

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load config from YAML, falling back to built-in defaults.

        Resolution order: explicit ``path`` → ``$CHKP_CPUSE_CONFIG`` → defaults.
        ``$CHKP_CPUSE_PACKAGE_RETENTION_DAYS`` overrides the retention window on
        top of whichever config was loaded.

        Relative ``paths.*`` / ``environments[].inventory`` entries are anchored
        to the config file's own directory, not the process's current working
        directory — a relative ``db_path: state/orch.db`` in ``/data/config.yaml``
        means ``/data/state/orch.db``, regardless of where the process was
        started from. Without this, the *same* relative path is only safe by
        accident: it resolves against whatever the CWD happens to be (e.g. a
        container's ``WORKDIR``, which is root-owned and unwritable by the
        non-root user the container actually runs as — observed 2026-07-24 on a
        fresh deploy using examples/config.example.yaml's relative paths
        unmodified). Absolute paths are left untouched either way.
        """
        candidate = path or os.environ.get("CHKP_CPUSE_CONFIG")
        if candidate is None:
            cfg = cls()
        else:
            p = Path(candidate)
            if not p.is_file():
                raise ConfigError(f"config file not found: {p}")
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:  # pragma: no cover - passthrough
                raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
            cfg = cls.model_validate(data)
            _anchor_relative_paths(cfg, base_dir=p.resolve().parent)
        _apply_retention_override(cfg)
        return cfg


def _anchor(value: Path, base_dir: Path) -> Path:
    return value if value.is_absolute() else base_dir / value


def _anchor_relative_paths(cfg: Config, *, base_dir: Path) -> None:
    """Mutate ``cfg`` in place so every relative path field resolves against
    the config file's own directory (``base_dir``) instead of the CWD."""
    paths = cfg.paths
    cfg.paths = Paths(
        reports_dir=_anchor(paths.reports_dir, base_dir),
        logs_dir=_anchor(paths.logs_dir, base_dir),
        state_dir=_anchor(paths.state_dir, base_dir),
        db_path=_anchor(paths.db_path, base_dir),
        packages_dir=_anchor(paths.packages_dir, base_dir),
        job_archive_path=_anchor(paths.job_archive_path, base_dir),
        inventory_path=_anchor(paths.inventory_path, base_dir),
    )
    cfg.environments = [
        EnvironmentDef(name=e.name, inventory=_anchor(e.inventory, base_dir))
        for e in cfg.environments
    ]


def _apply_retention_override(cfg: Config) -> None:
    """Let ``$CHKP_CPUSE_PACKAGE_RETENTION_DAYS`` override the config value."""
    raw = os.environ.get(PACKAGE_RETENTION_ENV)
    if raw is None:
        return
    try:
        days = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{PACKAGE_RETENTION_ENV} must be an integer, got {raw!r}") from exc
    if days < 0:
        raise ConfigError(f"{PACKAGE_RETENTION_ENV} must be >= 0, got {days}")
    cfg.package_retention_days = days
