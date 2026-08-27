from __future__ import annotations

import logging

import pytest

from convoy.errors import ConfigError
from convoy.reporting import LOG_LEVEL_ENV, resolve_log_level
from convoy.web.__main__ import SSL_CERTFILE_ENV, SSL_KEYFILE_ENV, resolve_ssl


def test_resolve_ssl_none_when_unconfigured() -> None:
    assert resolve_ssl({}) == (None, None)


def test_resolve_ssl_partial_config_fails_loud() -> None:
    with pytest.raises(ConfigError):
        resolve_ssl({SSL_CERTFILE_ENV: "/data/certs/fullchain.pem"})
    with pytest.raises(ConfigError):
        resolve_ssl({SSL_KEYFILE_ENV: "/data/certs/privkey.pem"})


def test_resolve_ssl_returns_both_paths_when_set() -> None:
    assert resolve_ssl(
        {
            SSL_CERTFILE_ENV: "/data/certs/fullchain.pem",
            SSL_KEYFILE_ENV: "/data/certs/privkey.pem",
        }
    ) == ("/data/certs/fullchain.pem", "/data/certs/privkey.pem")


def test_resolve_log_level_defaults_to_warning() -> None:
    assert resolve_log_level({}) == logging.WARNING


def test_resolve_log_level_reads_env() -> None:
    assert resolve_log_level({LOG_LEVEL_ENV: "debug"}) == logging.DEBUG
    assert resolve_log_level({LOG_LEVEL_ENV: "ERROR"}) == logging.ERROR


def test_resolve_log_level_rejects_unknown_name() -> None:
    with pytest.raises(ConfigError, match=LOG_LEVEL_ENV):
        resolve_log_level({LOG_LEVEL_ENV: "chatty"})
