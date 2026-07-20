from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chkp_cpuse_orch.config import Config, Paths
from chkp_cpuse_orch.credentials import MASTER_KEY_ENV
from chkp_cpuse_orch.errors import AuthError, ConfigError
from chkp_cpuse_orch.store import utcnow
from chkp_cpuse_orch.web.app import create_app
from chkp_cpuse_orch.web.auth import (
    LDAP_REQUIRED_GROUP_ENV,
    LDAP_URL_ENV,
    SESSION_COOKIE_NAME,
    AuthSettings,
    LDAPAuthenticator,
    hash_token,
    load_auth_settings,
    new_session_token,
)

from .fakes import FakeAuthenticator

USER = "operator"
PW = "correct horse battery"
SETTINGS = AuthSettings(
    url="ldap://test",
    required_group="cn=admins",
    user_dn_template="{username}",
    cookie_secure=False,
    idle_minutes=30,
)


def _fake() -> FakeAuthenticator:
    return FakeAuthenticator({USER: PW})


def _config(tmp_path: Path) -> Config:
    return Config(
        paths=Paths(
            reports_dir=tmp_path / "reports",
            logs_dir=tmp_path / "logs",
            state_dir=tmp_path / "state",
            db_path=tmp_path / "state" / "orch.db",
            packages_dir=tmp_path / "packages",
            inventory_path=tmp_path / "missing.yaml",  # no file → one empty "default" env
        )
    )


def _app(tmp_path: Path, authenticator: FakeAuthenticator | None) -> object:
    return create_app(
        _config(tmp_path),
        authenticator=authenticator,
        auth_settings=SETTINGS if authenticator is not None else None,
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MASTER_KEY_ENV, "auth test master key")
    monkeypatch.delenv(LDAP_URL_ENV, raising=False)
    monkeypatch.delenv(LDAP_REQUIRED_GROUP_ENV, raising=False)


def _login(c: TestClient, username: str = USER, password: str = PW) -> None:
    assert c.post("/api/auth/login", json={"username": username, "password": password}).status_code


# -- request gating ----------------------------------------------------------------


def test_api_requires_session_when_auth_enabled(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        assert c.get("/api/status").status_code == 401


def test_html_navigation_redirects_to_login(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        resp = c.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login.html"
        # The login page and its config endpoint are reachable without a session.
        assert c.get("/login.html", follow_redirects=False).status_code == 200
        assert c.get("/api/auth/config").json() == {"auth_enabled": True, "idle_minutes": 30}


def test_login_wrong_password_is_401(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        assert (
            c.post("/api/auth/login", json={"username": USER, "password": "nope"}).status_code
            == 401
        )
        assert c.get("/api/status").status_code == 401  # still no session


def test_login_grants_access_and_me(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        assert c.post("/api/auth/login", json={"username": USER, "password": PW}).status_code == 200
        assert c.get("/api/status").status_code == 200
        me = c.get("/api/auth/me").json()
        assert me == {"auth_enabled": True, "authenticated": True, "username": USER}


def test_logout_ends_the_session(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        _login(c)
        assert c.get("/api/status").status_code == 200
        assert c.post("/api/auth/logout").status_code == 200
        assert c.get("/api/status").status_code == 401


def test_idle_timeout_expires_session(tmp_path: Path) -> None:
    app = _app(tmp_path, _fake())
    with TestClient(app) as c:
        _login(c)
        token = c.cookies.get(SESSION_COOKIE_NAME)
        assert token is not None
        store = app.state.store  # type: ignore[attr-defined]
        # Back-date last activity beyond the idle window.
        store.touch_session(hash_token(token), now=utcnow() - timedelta(hours=2))
        assert c.get("/api/status").status_code == 401
        # The expired session row is removed, not just rejected.
        assert store.get_session(hash_token(token)) is None


# -- auth-optional + credential-storage gate ---------------------------------------


def test_auth_optional_runs_open_when_unconfigured(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, None)) as c:
        status = c.get("/api/status").json()  # no login required
        assert status["auth_enabled"] is False


def test_credential_storage_blocked_without_auth(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, None)) as c:
        c.post("/api/environments", json={"name": "corp"})
        assert (
            c.post("/api/environments/corp/credential-storage", json={"enabled": True}).status_code
            == 409
        )
        assert (
            c.put(
                "/api/env/corp/credentials",
                json={"host": "h", "kind": "ssh_password", "secret": "x"},
            ).status_code
            == 409
        )


def test_credential_storage_allowed_with_auth(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        _login(c)
        c.post("/api/environments", json={"name": "corp"})
        assert (
            c.post("/api/environments/corp/credential-storage", json={"enabled": True}).status_code
            == 200
        )
        assert (
            c.put(
                "/api/env/corp/credentials",
                json={"host": "h", "kind": "ssh_password", "secret": "x"},
            ).status_code
            == 201
        )


# -- settings loading --------------------------------------------------------------


def test_load_auth_settings_none_when_unconfigured() -> None:
    assert load_auth_settings({}) is None


def test_load_auth_settings_partial_config_fails_loud() -> None:
    with pytest.raises(ConfigError):
        load_auth_settings({LDAP_URL_ENV: "ldaps://dc:636"})  # no required group


def test_load_auth_settings_needs_a_user_dn_method() -> None:
    with pytest.raises(ConfigError):
        load_auth_settings({LDAP_URL_ENV: "ldaps://dc:636", LDAP_REQUIRED_GROUP_ENV: "cn=g"})


def test_load_auth_settings_service_account(tmp_path: Path) -> None:
    pw_file = tmp_path / "bindpw"
    pw_file.write_text("s3cret\n", encoding="utf-8")
    settings = load_auth_settings(
        {
            LDAP_URL_ENV: "ldaps://dc1:636, ldaps://dc2:636",
            LDAP_REQUIRED_GROUP_ENV: "cn=admins",
            "CHKP_CPUSE_LDAP_BIND_DN": "cn=svc",
            "CHKP_CPUSE_LDAP_BIND_PASSWORD_FILE": str(pw_file),
            "CHKP_CPUSE_LDAP_USER_BASE_DN": "ou=users,dc=corp",
            "CHKP_CPUSE_LDAP_START_TLS": "true",
            "CHKP_CPUSE_SESSION_IDLE_MINUTES": "15",
            "CHKP_CPUSE_SESSION_COOKIE_SECURE": "false",
        }
    )
    assert settings is not None
    assert settings.bind_password == "s3cret"
    assert settings.urls == ["ldaps://dc1:636", "ldaps://dc2:636"]
    assert settings.start_tls is True
    assert settings.idle_minutes == 15
    assert settings.cookie_secure is False


# -- LDAP group gating (pure logic, no directory) ----------------------------------


def test_ldap_group_check_is_case_and_space_insensitive() -> None:
    settings = SETTINGS.model_copy(update={"required_group": "CN=Admins,OU=Groups,DC=corp,DC=com"})
    auth = LDAPAuthenticator(settings)
    # Same DN, different casing/spacing → member.
    auth._check_group(["cn=admins, ou=groups, dc=corp, dc=com"], USER)
    with pytest.raises(AuthError):
        auth._check_group(["CN=Other,DC=corp,DC=com"], USER)


def test_ldap_rejects_empty_password() -> None:
    auth = LDAPAuthenticator(SETTINGS)
    with pytest.raises(AuthError):
        auth.authenticate(USER, "")


# -- token helpers -----------------------------------------------------------------


def test_session_tokens_are_unique_and_hashed() -> None:
    a, b = new_session_token(), new_session_token()
    assert a != b
    assert hash_token(a) == hash_token(a) != a
    assert len(hash_token(a)) == 64  # sha256 hex
