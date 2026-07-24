from __future__ import annotations

import pytest

from chkp_cpuse_orch.errors import ConfigError
from chkp_cpuse_orch.web.__main__ import SSL_CERTFILE_ENV, SSL_KEYFILE_ENV, resolve_ssl


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
