from __future__ import annotations

from pathlib import Path

import pytest

from convoy.config import (
    DEFAULT_PACKAGE_RETENTION_DAYS,
    PACKAGE_RETENTION_ENV,
    Config,
)
from convoy.errors import ConfigError


def test_retention_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PACKAGE_RETENTION_ENV, raising=False)
    assert Config.load().package_retention_days == DEFAULT_PACKAGE_RETENTION_DAYS


def test_retention_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PACKAGE_RETENTION_ENV, "7")
    assert Config.load().package_retention_days == 7


def test_retention_env_zero_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PACKAGE_RETENTION_ENV, "0")
    assert Config.load().package_retention_days == 0


def test_retention_env_rejects_non_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PACKAGE_RETENTION_ENV, "thirty")
    with pytest.raises(ConfigError, match="must be an integer"):
        Config.load()


def test_retention_env_rejects_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PACKAGE_RETENTION_ENV, "-5")
    with pytest.raises(ConfigError, match="must be >= 0"):
        Config.load()


# -- relative paths anchor to the config file's directory, not the CWD ------------


def test_relative_paths_anchor_to_config_file_directory(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "paths:\n"
        "  reports_dir: reports\n"
        "  logs_dir: logs\n"
        "  state_dir: state\n"
        "  db_path: state/orch.db\n"
        "  packages_dir: packages\n"
        "  inventory_path: inventory.yaml\n",
        encoding="utf-8",
    )
    cfg = Config.load(tmp_path / "config.yaml")
    assert cfg.paths.reports_dir == tmp_path / "reports"
    assert cfg.paths.db_path == tmp_path / "state" / "orch.db"
    assert cfg.paths.packages_dir == tmp_path / "packages"
    assert cfg.paths.inventory_path == tmp_path / "inventory.yaml"


def test_relative_paths_anchor_regardless_of_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "config.yaml").write_text("paths:\n  db_path: state/orch.db\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    cfg = Config.load(tmp_path / "config.yaml")
    assert cfg.paths.db_path == tmp_path / "state" / "orch.db"


def test_absolute_paths_are_left_untouched(tmp_path: Path) -> None:
    abs_db = tmp_path / "elsewhere" / "orch.db"
    (tmp_path / "config.yaml").write_text(
        f"paths:\n  db_path: {abs_db.as_posix()}\n", encoding="utf-8"
    )
    cfg = Config.load(tmp_path / "config.yaml")
    assert cfg.paths.db_path == abs_db


def test_environment_inventory_paths_also_anchor(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "environments:\n  - name: corp\n    inventory: inventories/corp.yaml\n",
        encoding="utf-8",
    )
    cfg = Config.load(tmp_path / "config.yaml")
    assert cfg.environments[0].inventory == tmp_path / "inventories" / "corp.yaml"


def test_bare_defaults_stay_relative_to_cwd_without_a_config_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CONVOY_CONFIG", raising=False)
    cfg = Config.load()
    assert cfg.paths.db_path == Path("state") / "orch.db"
