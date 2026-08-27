from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from convoy import __version__
from convoy.config import Config, Paths
from convoy.credentials import MASTER_KEY_ENV
from convoy.errors import AuthError, ConfigError
from convoy.store import Store, utcnow
from convoy.web.app import create_app
from convoy.web.auth import (
    ALLOW_NO_AUTH_ENV,
    BASIC_AUTH_DISABLE_ENV,
    BASIC_AUTH_PASSWORD_ENV,
    BASIC_AUTH_USER_ENV,
    LDAP_REQUIRED_GROUP_ENV,
    LDAP_URL_ENV,
    LOGIN_BACKOFF_BASE_SECONDS,
    LOGIN_BACKOFF_MAX_SECONDS,
    LOGIN_FREE_ATTEMPTS,
    NATIVE_TLS_CERTFILE_ENV,
    NATIVE_TLS_KEYFILE_ENV,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SECURE_ENV,
    AuthSettings,
    BasicAuthenticator,
    LDAPAuthenticator,
    LoginThrottle,
    hash_token,
    load_active_auth_settings,
    load_auth_settings,
    load_basic_auth_settings,
    login_backoff_seconds,
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
            job_archive_path=tmp_path / "state" / "job_archive.log",
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
        cfg = c.get("/api/auth/config").json()
        assert cfg["auth_enabled"] is True
        assert cfg["idle_minutes"] == 30
        assert cfg["version"] == __version__


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
        assert me == {
            "auth_enabled": True,
            "authenticated": True,
            "username": USER,
            "backend": "ldap",  # FakeAuthenticator isn't a BasicAuthenticator
        }


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
                json={"name": "primary", "ssh_password": "x"},
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
                json={"name": "primary", "ssh_password": "x"},
            ).status_code
            == 200
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
            "CONVOY_LDAP_BIND_DN": "cn=svc",
            "CONVOY_LDAP_BIND_PASSWORD_FILE": str(pw_file),
            "CONVOY_LDAP_USER_BASE_DN": "ou=users,dc=corp",
            "CONVOY_LDAP_START_TLS": "true",
            "CONVOY_SESSION_IDLE_MINUTES": "15",
            "CONVOY_SESSION_COOKIE_SECURE": "false",
        }
    )
    assert settings is not None
    assert settings.bind_password == "s3cret"
    assert settings.urls == ["ldaps://dc1:636", "ldaps://dc2:636"]
    assert settings.start_tls is True
    assert settings.idle_minutes == 15
    assert settings.cookie_secure is False


# -- session cookie Secure default (2026-07-25) ------------------------------------
# A Secure cookie set over plain HTTP is silently dropped by the browser — login
# "succeeds" server-side but every request after that looks unauthenticated. The
# default now tracks whether native TLS is actually configured; an explicit
# CONVOY_SESSION_COOKIE_SECURE always overrides the guess either way.


def test_cookie_secure_defaults_false_without_native_tls() -> None:
    basic = load_basic_auth_settings({})
    assert basic is not None
    assert basic.cookie_secure is False

    ldap = load_auth_settings(
        {
            LDAP_URL_ENV: "ldap://test",
            LDAP_REQUIRED_GROUP_ENV: "cn=g",
            "CONVOY_LDAP_USER_DN_TEMPLATE": "{username}",
        }
    )
    assert ldap is not None
    assert ldap.cookie_secure is False


def test_cookie_secure_defaults_true_with_native_tls_configured() -> None:
    tls_env = {
        NATIVE_TLS_CERTFILE_ENV: "/data/certs/fullchain.pem",
        NATIVE_TLS_KEYFILE_ENV: "/data/certs/privkey.pem",
    }
    basic = load_basic_auth_settings(tls_env)
    assert basic is not None
    assert basic.cookie_secure is True


def test_cookie_secure_explicit_value_always_wins() -> None:
    # Native TLS configured, but explicitly forced off.
    forced_off = load_basic_auth_settings(
        {
            NATIVE_TLS_CERTFILE_ENV: "/data/certs/fullchain.pem",
            NATIVE_TLS_KEYFILE_ENV: "/data/certs/privkey.pem",
            SESSION_COOKIE_SECURE_ENV: "false",
        }
    )
    assert forced_off is not None
    assert forced_off.cookie_secure is False

    # No native TLS (e.g. a reverse proxy terminates it instead), but explicitly
    # forced on.
    forced_on = load_basic_auth_settings({SESSION_COOKIE_SECURE_ENV: "true"})
    assert forced_on is not None
    assert forced_on.cookie_secure is True


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


# -- basic auth: settings + backend precedence -------------------------------------
# conftest.py's autouse fixture sets BASIC_AUTH_DISABLE=true for every test (so
# pre-existing tests keep assuming "no authenticator -> auth off"); these tests
# re-enable it explicitly to exercise the default-on backend.


def test_basic_auth_is_on_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    settings = load_basic_auth_settings({})
    assert settings is not None
    assert settings.username == "admin"
    assert load_active_auth_settings({}) is not None  # same, via the combined loader


def test_basic_auth_disable_env_turns_it_off() -> None:
    """Running open takes BOTH keys — see ALLOW_NO_AUTH_ENV."""
    env = {BASIC_AUTH_DISABLE_ENV: "true", ALLOW_NO_AUTH_ENV: "1"}
    assert load_basic_auth_settings(env) is None
    assert load_active_auth_settings(env) is None


def test_basic_auth_disable_alone_keeps_the_login_gate_up() -> None:
    """Fail closed: BASIC_AUTH_DISABLE is easy to set while thinking it only
    relaxes a login prompt, so on its own it must not expose every destructive
    route. The second, explicitly-named acknowledgement is required."""
    env = {BASIC_AUTH_DISABLE_ENV: "true"}
    settings = load_basic_auth_settings(env)
    assert settings is not None
    assert settings.username == "admin"
    assert load_active_auth_settings(env) is not None


def test_allow_no_auth_alone_does_nothing() -> None:
    assert load_basic_auth_settings({ALLOW_NO_AUTH_ENV: "1"}) is not None


def test_ldap_takes_priority_over_basic_auth_when_both_configured() -> None:
    env = {
        LDAP_URL_ENV: "ldap://test",
        LDAP_REQUIRED_GROUP_ENV: "cn=admins",
        "CONVOY_LDAP_USER_DN_TEMPLATE": "{username}",
        BASIC_AUTH_DISABLE_ENV: "false",
    }
    assert isinstance(load_active_auth_settings(env), AuthSettings)


# -- basic auth: authenticator logic (pure, no HTTP) -------------------------------


def test_basic_authenticator_default_credentials(tmp_path: Path) -> None:
    store = Store(tmp_path / "auth.db")
    settings = load_basic_auth_settings({})
    assert settings is not None
    auth = BasicAuthenticator(store, settings)
    user = auth.authenticate("admin", "admin")
    assert user.username == "admin"
    with pytest.raises(AuthError):
        auth.authenticate("admin", "wrong")
    with pytest.raises(AuthError):
        auth.authenticate("someone-else", "admin")
    with pytest.raises(AuthError):
        auth.authenticate("admin", "")


def test_basic_authenticator_change_password_persists_across_restart(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "auth.db"
    settings = load_basic_auth_settings({})
    assert settings is not None

    store = Store(db_path)
    auth = BasicAuthenticator(store, settings)
    auth.change_password("admin", "new password")
    assert auth.authenticate("admin", "new password").username == "admin"
    with pytest.raises(AuthError):
        auth.authenticate("admin", "admin")  # old default no longer works

    # A fresh authenticator built from the same store/settings (as after a
    # restart) must pick up the persisted hash, not the env-var default.
    restarted = BasicAuthenticator(Store(db_path), settings)
    assert restarted.authenticate("admin", "new password").username == "admin"
    with pytest.raises(AuthError):
        restarted.authenticate("admin", "admin")


def test_basic_authenticator_change_password_wrong_current(tmp_path: Path) -> None:
    store = Store(tmp_path / "auth.db")
    settings = load_basic_auth_settings({})
    assert settings is not None
    auth = BasicAuthenticator(store, settings)
    with pytest.raises(AuthError):
        auth.change_password("not the current password", "new password")
    assert auth.authenticate("admin", "admin").username == "admin"  # unchanged


# -- basic auth: end-to-end over HTTP ----------------------------------------------


def _app_basic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    """The real default-on backend, not a fake — exercises load_active_auth_settings
    end to end. Caller must have re-enabled it (conftest disables it by default).
    Cookie defaults to Secure, which TestClient's plain-http scheme won't round-trip
    — same reason the LDAP tests' SETTINGS fixture sets cookie_secure=False."""
    monkeypatch.setenv(SESSION_COOKIE_SECURE_ENV, "false")
    return create_app(_config(tmp_path))


def test_default_basic_auth_login_and_credential_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        assert c.get("/api/status").status_code == 401  # on by default, no login yet
        assert (
            c.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
            == 200
        )
        me = c.get("/api/auth/me").json()
        assert me == {
            "auth_enabled": True,
            "authenticated": True,
            "username": "admin",
            "backend": "basic",
        }
        # Basic auth "counts as auth" for credential storage, same as LDAP.
        c.post("/api/environments", json={"name": "corp"})
        assert (
            c.post("/api/environments/corp/credential-storage", json={"enabled": True}).status_code
            == 200
        )


def test_basic_auth_custom_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    monkeypatch.setenv(BASIC_AUTH_USER_ENV, "svc-cpuse")
    monkeypatch.setenv(BASIC_AUTH_PASSWORD_ENV, "s3cret-enough")
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        assert (
            c.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
            == 401
        )
        assert (
            c.post(
                "/api/auth/login",
                json={"username": "svc-cpuse", "password": "s3cret-enough"},
            ).status_code
            == 200
        )


def test_basic_auth_disable_env_runs_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # conftest's autouse fixture already sets this — asserted explicitly here.
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        status = c.get("/api/status").json()
        assert status["auth_enabled"] is False


def test_change_password_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        assert (
            c.post(
                "/api/auth/password",
                json={"current_password": "admin", "new_password": "a new password"},
            ).status_code
            == 200
        )
        c.post("/api/auth/logout")
        assert (
            c.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
            == 401
        )
        assert (
            c.post(
                "/api/auth/login",
                json={"username": "admin", "password": "a new password"},
            ).status_code
            == 200
        )


def test_change_password_wrong_current_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        assert (
            c.post(
                "/api/auth/password",
                json={"current_password": "not it", "new_password": "a new password"},
            ).status_code
            == 400
        )


def test_change_password_rejected_under_ldap(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path, _fake())) as c:
        _login(c)
        assert (
            c.post(
                "/api/auth/password",
                json={"current_password": PW, "new_password": "a new password"},
            ).status_code
            == 400
        )


# -- login throttling (H4) ---------------------------------------------------------
#
# Nothing else slows password guessing against a tool that can reboot production
# firewalls, and the shipped default is admin/admin. See LoginThrottle.


def test_login_backoff_curve_is_free_then_exponential_then_capped() -> None:
    assert login_backoff_seconds(1) == 0.0
    # all LOGIN_FREE_ATTEMPTS attempts are genuinely free; the next one waits
    assert login_backoff_seconds(LOGIN_FREE_ATTEMPTS - 1) == 0.0
    assert login_backoff_seconds(LOGIN_FREE_ATTEMPTS) == LOGIN_BACKOFF_BASE_SECONDS
    assert login_backoff_seconds(LOGIN_FREE_ATTEMPTS + 1) == LOGIN_BACKOFF_BASE_SECONDS * 2
    # capped, so a lockout can't become a permanent denial of service
    assert login_backoff_seconds(999) == LOGIN_BACKOFF_MAX_SECONDS


def test_throttle_blocks_after_free_attempts_and_clears_on_success(tmp_path: Path) -> None:
    store = Store(tmp_path / "throttle.db")
    throttle = LoginThrottle(store)
    scopes = LoginThrottle.scopes("admin", "192.0.2.5")

    for _ in range(LOGIN_FREE_ATTEMPTS):
        assert throttle.retry_after(scopes) == 0.0
        throttle.record_failure(scopes)
    assert throttle.retry_after(scopes) > 0.0

    throttle.record_success(scopes)
    assert throttle.retry_after(scopes) == 0.0


def test_throttle_survives_a_restart(tmp_path: Path) -> None:
    """Persisted, not in-memory — otherwise restarting the container is a
    lockout bypass."""
    db = tmp_path / "throttle.db"
    scopes = LoginThrottle.scopes("admin", "192.0.2.5")
    first = LoginThrottle(Store(db))
    for _ in range(LOGIN_FREE_ATTEMPTS + 1):
        first.record_failure(scopes)

    assert LoginThrottle(Store(db)).retry_after(scopes) > 0.0


def test_throttle_scopes_username_and_ip_independently(tmp_path: Path) -> None:
    """Neither rotating usernames from one host nor spraying one username from
    many hosts should slip through."""
    store = Store(tmp_path / "throttle.db")
    throttle = LoginThrottle(store)
    for _ in range(LOGIN_FREE_ATTEMPTS + 1):
        throttle.record_failure(LoginThrottle.scopes("admin", "192.0.2.5"))

    # same IP, brand-new username -> still throttled by the ip: scope
    assert throttle.retry_after(LoginThrottle.scopes("someone-else", "192.0.2.5")) > 0.0
    # same username, brand-new IP -> still throttled by the user: scope
    assert throttle.retry_after(LoginThrottle.scopes("admin", "198.51.100.9")) > 0.0
    # unrelated on both axes -> free
    assert throttle.retry_after(LoginThrottle.scopes("someone-else", "198.51.100.9")) == 0.0


def test_login_route_returns_429_once_throttled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    with TestClient(_app_basic(tmp_path, monkeypatch)) as c:
        for _ in range(LOGIN_FREE_ATTEMPTS):
            assert (
                c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
            ).status_code == 401
        blocked = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
        # and the CORRECT password is refused too while throttled — otherwise
        # the throttle would only slow down the guesses that were going to fail
        assert (
            c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        ).status_code == 429


# -- default-password warning (H3) -------------------------------------------------


def test_uses_default_password_is_true_out_of_the_box(tmp_path: Path) -> None:
    store = Store(tmp_path / "auth.db")
    settings = load_basic_auth_settings({})
    assert settings is not None
    assert BasicAuthenticator(store, settings).uses_default_password is True


def test_uses_default_password_is_false_when_env_sets_one(tmp_path: Path) -> None:
    store = Store(tmp_path / "auth.db")
    settings = load_basic_auth_settings({BASIC_AUTH_PASSWORD_ENV: "something-else"})
    assert settings is not None
    assert BasicAuthenticator(store, settings).uses_default_password is False


def test_uses_default_password_is_false_after_a_runtime_change(tmp_path: Path) -> None:
    """A UI password change persists its own hash, so the warning must stop
    even though the env var is still unset."""
    store = Store(tmp_path / "auth.db")
    settings = load_basic_auth_settings({})
    assert settings is not None
    auth = BasicAuthenticator(store, settings)
    auth.change_password("admin", "a much better password")
    assert auth.uses_default_password is False
    # and it stays false across a restart, since the hash is in the DB
    assert BasicAuthenticator(store, settings).uses_default_password is False


# -- password change revokes other sessions (M13) ----------------------------------


def test_password_change_revokes_other_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing a password is how an operator revokes access someone else may
    already have — a session token must not outlive it."""
    monkeypatch.delenv(BASIC_AUTH_DISABLE_ENV, raising=False)
    app = _app_basic(tmp_path, monkeypatch)
    with TestClient(app) as attacker, TestClient(app) as operator:
        for client in (attacker, operator):
            assert (
                client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
            ).status_code == 200
        assert attacker.get("/api/status").status_code == 200

        changed = operator.post(
            "/api/auth/password",
            json={"current_password": "admin", "new_password": "a much better password"},
        )
        assert changed.status_code == 200

        # the other session is dead...
        assert attacker.get("/api/status").status_code == 401
        # ...but the tab that made the change keeps working
        assert operator.get("/api/status").status_code == 200
