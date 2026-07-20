from __future__ import annotations

import pytest

from chkp_cpuse_orch.config import (
    DEFAULT_PACKAGE_RETENTION_DAYS,
    PACKAGE_RETENTION_ENV,
    Config,
)
from chkp_cpuse_orch.errors import ConfigError


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
