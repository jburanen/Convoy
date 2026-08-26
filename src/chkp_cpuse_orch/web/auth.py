"""Web authentication — LDAP/Active Directory or local basic-auth login behind a
small backend-agnostic interface, plus session-token helpers.

Configured entirely from the environment (see ``.env.example``). Presence of
``CHKP_CPUSE_LDAP_URL`` **and** ``CHKP_CPUSE_LDAP_REQUIRED_GROUP`` enables LDAP auth.
When LDAP isn't configured, a local basic-auth backend is used instead —
**on by default** (``BASIC_AUTH_USER``/``BASIC_AUTH_PASSWORD``, default
``admin``/``admin``) unless ``BASIC_AUTH_DISABLE`` is set. Only when LDAP is
unconfigured *and* basic auth is disabled does ``load_active_auth_settings`` return
``None`` and the web app run fully open (auth-optional — but credential storage is
then forbidden; see web/app.py). An LDAP URL set with an incomplete rest-of-config
fails loudly, never silently open.

The ``Authenticator`` protocol keeps the design open to multiple backends behind the
same session layer. ``LDAPAuthenticator`` implements search-then-bind against AD or
any LDAP directory and gates access on direct ``memberOf`` membership of a configured
group. ``BasicAuthenticator`` checks a single configured username/password (the
password is changeable at runtime via ``/api/auth/password`` and persisted — as an
argon2 hash — in the ``meta`` table, overriding the env-var default).

Only non-secret settings and transient in-memory secrets live here; session tokens
(and the basic-auth password hash, once changed) are stored hashed (see store.py).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import ssl
from datetime import datetime, timedelta
from typing import Any, Protocol

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import BaseModel, Field

from ..errors import AuthError, ConfigError
from ..reporting import get_logger
from ..store import SessionRow, Store, utcnow

logger = get_logger(__name__)

# -- env var names -----------------------------------------------------------------
LDAP_URL_ENV = "CHKP_CPUSE_LDAP_URL"
LDAP_REQUIRED_GROUP_ENV = "CHKP_CPUSE_LDAP_REQUIRED_GROUP"
LDAP_BIND_DN_ENV = "CHKP_CPUSE_LDAP_BIND_DN"
LDAP_BIND_PASSWORD_ENV = "CHKP_CPUSE_LDAP_BIND_PASSWORD"
LDAP_BIND_PASSWORD_FILE_ENV = "CHKP_CPUSE_LDAP_BIND_PASSWORD_FILE"
LDAP_USER_BASE_DN_ENV = "CHKP_CPUSE_LDAP_USER_BASE_DN"
LDAP_USER_FILTER_ENV = "CHKP_CPUSE_LDAP_USER_FILTER"
LDAP_USER_DN_TEMPLATE_ENV = "CHKP_CPUSE_LDAP_USER_DN_TEMPLATE"
LDAP_MEMBER_OF_ATTR_ENV = "CHKP_CPUSE_LDAP_MEMBER_OF_ATTR"
LDAP_START_TLS_ENV = "CHKP_CPUSE_LDAP_START_TLS"
LDAP_TLS_VERIFY_ENV = "CHKP_CPUSE_LDAP_TLS_VERIFY"
LDAP_CA_CERT_ENV = "CHKP_CPUSE_LDAP_CA_CERT"
SESSION_IDLE_MINUTES_ENV = "CHKP_CPUSE_SESSION_IDLE_MINUTES"
SESSION_COOKIE_SECURE_ENV = "CHKP_CPUSE_SESSION_COOKIE_SECURE"
# Native HTTPS (web/__main__.py) — read here (as plain strings, not imported, to
# avoid pulling in uvicorn just to check two env vars) only to pick
# SESSION_COOKIE_SECURE_ENV's default; an explicit value for that var always wins.
NATIVE_TLS_CERTFILE_ENV = "CHKP_CPUSE_SSL_CERTFILE"
NATIVE_TLS_KEYFILE_ENV = "CHKP_CPUSE_SSL_KEYFILE"

# Local basic-auth backend — the default when LDAP isn't configured.
BASIC_AUTH_USER_ENV = "BASIC_AUTH_USER"
BASIC_AUTH_PASSWORD_ENV = "BASIC_AUTH_PASSWORD"
BASIC_AUTH_DISABLE_ENV = "BASIC_AUTH_DISABLE"
# Running with NO authentication exposes every destructive route — credential
# bootstrap onto gateways, CDT execute, environment deletion — to anyone who can
# reach the port. BASIC_AUTH_DISABLE alone is too easy to set while thinking it
# only relaxes a login prompt, so it must be paired with this second, explicitly
# named acknowledgement. Set only one and the login gate stays up (fail closed),
# with a warning explaining what to do.
ALLOW_NO_AUTH_ENV = "CHKP_CPUSE_ALLOW_NO_AUTH"
DEFAULT_BASIC_AUTH_USER = "admin"
DEFAULT_BASIC_AUTH_PASSWORD = "admin"
# meta table key (store.py) for a password changed at runtime via the UI; overrides
# the env-var default without needing a restart.
BASIC_AUTH_PASSWORD_HASH_META_KEY = "basic_auth_password_hash"

# Default user filter targets Active Directory; override for other directories
# (e.g. "(uid={username})" for OpenLDAP/posix).
DEFAULT_USER_FILTER = "(sAMAccountName={username})"
DEFAULT_MEMBER_OF_ATTR = "memberOf"
DEFAULT_IDLE_MINUTES = 30
SESSION_COOKIE_NAME = "chkp_session"


class AuthenticatedUser(BaseModel):
    """The identity established by a successful login."""

    username: str
    display_name: str
    dn: str


class Authenticator(Protocol):
    """A pluggable authentication backend. Raises ``AuthError`` on any failure
    (bad credentials, not in the required group, directory unreachable); the
    message is safe to log but never disclosed verbatim to the client."""

    def authenticate(self, username: str, password: str) -> AuthenticatedUser: ...


class SessionSettings(Protocol):
    """The subset of a backend's settings ``AuthManager`` needs for session/cookie
    behaviour — implemented by both ``AuthSettings`` (LDAP) and ``BasicAuthSettings``."""

    idle_minutes: int
    cookie_secure: bool


class AuthSettings(BaseModel):
    """Non-secret LDAP + session configuration, resolved from the environment.

    ``bind_password`` is the one transient secret held here (in memory only). Either
    a service account (``bind_dn`` + ``user_base_dn``) or a ``user_dn_template`` must
    be provided so the user's DN can be resolved for the verifying bind.
    """

    url: str
    required_group: str
    bind_dn: str | None = None
    bind_password: str | None = None
    user_base_dn: str | None = None
    user_filter: str = DEFAULT_USER_FILTER
    user_dn_template: str | None = None
    member_of_attr: str = DEFAULT_MEMBER_OF_ATTR
    start_tls: bool = False
    tls_verify: bool = True
    ca_cert: str | None = None
    idle_minutes: int = Field(default=DEFAULT_IDLE_MINUTES, ge=1)
    cookie_secure: bool = True

    @property
    def urls(self) -> list[str]:
        return [u.strip() for u in self.url.split(",") if u.strip()]


def _env_bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _load_idle_minutes(env: dict[str, str]) -> int:
    idle_raw = env.get(SESSION_IDLE_MINUTES_ENV)
    try:
        return int(idle_raw) if idle_raw else DEFAULT_IDLE_MINUTES
    except ValueError as exc:
        raise ConfigError(
            f"{SESSION_IDLE_MINUTES_ENV} must be an integer, got {idle_raw!r}"
        ) from exc


def _default_cookie_secure(env: dict[str, str]) -> bool:
    """Secure-by-default only when native TLS (CHKP_CPUSE_SSL_CERTFILE/KEYFILE) is
    actually configured. A ``Secure`` cookie set over plain HTTP is silently
    dropped by the browser — login "succeeds" (the server sets it) but every
    request after that looks unauthenticated, bouncing straight back to the login
    page with no visible error (observed 2026-07-25 on a TLS-less dev host). Behind
    a reverse proxy that terminates TLS (native certs correctly unset here, but the
    browser only ever sees https), set CHKP_CPUSE_SESSION_COOKIE_SECURE=true
    explicitly — it always overrides this guess."""
    return bool(env.get(NATIVE_TLS_CERTFILE_ENV)) and bool(env.get(NATIVE_TLS_KEYFILE_ENV))


class BasicAuthSettings(BaseModel):
    """A single local username/password, plus the same session settings LDAP uses.

    ``password_hash`` is the argon2 hash of the env-var-configured (or default)
    password — computed once at load time. ``BasicAuthenticator`` prefers a
    DB-persisted hash (set via a runtime password change) over this one.
    """

    username: str
    password_hash: str
    idle_minutes: int = Field(default=DEFAULT_IDLE_MINUTES, ge=1)
    cookie_secure: bool = True
    # True when BASIC_AUTH_PASSWORD was unset (or set to the shipped default),
    # so startup can warn about it. Only meaningful together with the absence
    # of a DB-persisted password change — see BasicAuthenticator.uses_default_password.
    is_default_password: bool = False


def load_basic_auth_settings(
    environ: os._Environ[str] | dict[str, str] | None = None,
) -> BasicAuthSettings | None:
    """Build local basic-auth settings from the environment, or ``None`` when
    ``BASIC_AUTH_DISABLE`` **and** ``CHKP_CPUSE_ALLOW_NO_AUTH`` are both set
    (see ALLOW_NO_AUTH_ENV — one alone keeps the login gate up).
    Unset ``BASIC_AUTH_USER``/``BASIC_AUTH_PASSWORD``
    default to ``admin``/``admin`` — this backend is **on by default** so a fresh
    deployment isn't left wide open; operators are expected to change the password
    (or configure LDAP, or set ``BASIC_AUTH_DISABLE``) promptly."""
    env = dict(os.environ if environ is None else environ)
    if _env_bool(env, BASIC_AUTH_DISABLE_ENV, False):
        if _env_bool(env, ALLOW_NO_AUTH_ENV, False):
            return None
        logger.warning(
            f"{BASIC_AUTH_DISABLE_ENV} is set but {ALLOW_NO_AUTH_ENV} is not — "
            "keeping the login gate up rather than running this service open",
            hint=(
                f"running with no authentication exposes every destructive route; "
                f"set {ALLOW_NO_AUTH_ENV}=1 as well if that is genuinely intended"
            ),
        )
    username = (env.get(BASIC_AUTH_USER_ENV) or DEFAULT_BASIC_AUTH_USER).strip()
    password = env.get(BASIC_AUTH_PASSWORD_ENV) or DEFAULT_BASIC_AUTH_PASSWORD
    return BasicAuthSettings(
        username=username,
        password_hash=PasswordHasher().hash(password),
        idle_minutes=_load_idle_minutes(env),
        cookie_secure=_env_bool(env, SESSION_COOKIE_SECURE_ENV, _default_cookie_secure(env)),
        is_default_password=password == DEFAULT_BASIC_AUTH_PASSWORD,
    )


def load_active_auth_settings(
    environ: os._Environ[str] | dict[str, str] | None = None,
) -> AuthSettings | BasicAuthSettings | None:
    """Resolve whichever backend is active: LDAP takes priority when configured;
    otherwise local basic-auth, unless disabled; otherwise ``None`` (fully open —
    and credential storage is then forbidden, see web/app.py)."""
    ldap_settings = load_auth_settings(environ)
    if ldap_settings is not None:
        return ldap_settings
    return load_basic_auth_settings(environ)


def load_auth_settings(
    environ: os._Environ[str] | dict[str, str] | None = None,
) -> AuthSettings | None:
    """Build settings from the environment, or ``None`` when auth is not configured.

    Auth is "configured" when both ``CHKP_CPUSE_LDAP_URL`` and
    ``CHKP_CPUSE_LDAP_REQUIRED_GROUP`` are set. A URL set without a usable user-DN
    resolution method (service account or DN template) raises ``ConfigError`` so a
    half-finished config fails loudly rather than leaving the UI open.
    """
    env = dict(os.environ if environ is None else environ)
    url = (env.get(LDAP_URL_ENV) or "").strip()
    group = (env.get(LDAP_REQUIRED_GROUP_ENV) or "").strip()
    if not url and not group:
        return None
    if not url or not group:
        raise ConfigError(
            f"incomplete LDAP config: set both {LDAP_URL_ENV} and {LDAP_REQUIRED_GROUP_ENV} "
            "to enable authentication, or neither to run without it"
        )

    bind_password = env.get(LDAP_BIND_PASSWORD_ENV)
    if not bind_password:
        pw_file = env.get(LDAP_BIND_PASSWORD_FILE_ENV)
        if pw_file:
            try:
                with open(pw_file, encoding="utf-8") as fh:
                    bind_password = fh.read().strip()
            except OSError as exc:
                raise ConfigError(
                    f"cannot read {LDAP_BIND_PASSWORD_FILE_ENV} {pw_file!r}: {exc}"
                ) from exc

    bind_dn = env.get(LDAP_BIND_DN_ENV) or None
    user_base_dn = env.get(LDAP_USER_BASE_DN_ENV) or None
    user_dn_template = env.get(LDAP_USER_DN_TEMPLATE_ENV) or None
    if not user_dn_template and not (bind_dn and user_base_dn):
        raise ConfigError(
            "LDAP config needs a way to resolve the user DN: set a service account "
            f"({LDAP_BIND_DN_ENV} + {LDAP_USER_BASE_DN_ENV}) or {LDAP_USER_DN_TEMPLATE_ENV}"
        )

    idle = _load_idle_minutes(env)

    return AuthSettings(
        url=url,
        required_group=group,
        bind_dn=bind_dn,
        bind_password=bind_password,
        user_base_dn=user_base_dn,
        user_filter=env.get(LDAP_USER_FILTER_ENV) or DEFAULT_USER_FILTER,
        user_dn_template=user_dn_template,
        member_of_attr=env.get(LDAP_MEMBER_OF_ATTR_ENV) or DEFAULT_MEMBER_OF_ATTR,
        start_tls=_env_bool(env, LDAP_START_TLS_ENV, False),
        tls_verify=_env_bool(env, LDAP_TLS_VERIFY_ENV, True),
        ca_cert=env.get(LDAP_CA_CERT_ENV) or None,
        idle_minutes=idle,
        cookie_secure=_env_bool(env, SESSION_COOKIE_SECURE_ENV, _default_cookie_secure(env)),
    )


# -- session token helpers ---------------------------------------------------------


def new_session_token() -> str:
    """A fresh opaque session token (goes in the cookie; only its hash is stored)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 of a session token — what the DB stores. Constant work, no salt
    needed: the token is 256 bits of entropy, not a low-entropy password."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# -- login throttling --------------------------------------------------------------
#
# There is otherwise nothing at all slowing down password guessing against this
# tool, and the shipped default is admin/admin. Two independent scopes are
# tracked per attempt — the username being guessed and the source address doing
# the guessing — and the stricter of the two governs, so neither rotating
# usernames from one host nor spraying one username from many hosts slips
# through. State lives in SQLite (store.login_attempts) so restarting the
# container isn't a lockout bypass.

# Free attempts before any delay applies; then the backoff doubles per failure.
LOGIN_FREE_ATTEMPTS = 5
LOGIN_BACKOFF_BASE_SECONDS = 2.0
LOGIN_BACKOFF_MAX_SECONDS = 900.0  # 15 min ceiling — locking out forever is a DoS
# Untouched throttle records are swept after this long (also the point at which
# a quiet attacker's counter effectively resets).
LOGIN_ATTEMPT_TTL = timedelta(hours=24)


def login_backoff_seconds(failures: int) -> float:
    """Delay required after ``failures`` consecutive failures.

    Zero until LOGIN_FREE_ATTEMPTS have actually been spent, so ordinary typos
    cost nothing: with the default of 5, attempts 1-5 are free and the 6th is
    the first to be made to wait."""
    excess = failures - LOGIN_FREE_ATTEMPTS + 1
    if excess <= 0:
        return 0.0
    delay: float = LOGIN_BACKOFF_BASE_SECONDS * float(2 ** (excess - 1))
    return min(delay, LOGIN_BACKOFF_MAX_SECONDS)


class LoginThrottle:
    """Persistent failed-login backoff, keyed by arbitrary scope strings."""

    def __init__(self, store: Store) -> None:
        self._store = store

    @staticmethod
    def scopes(username: str, source_ip: str | None) -> list[str]:
        scopes = [f"user:{username.strip().lower()}"]
        if source_ip:
            scopes.append(f"ip:{source_ip}")
        return scopes

    def retry_after(self, scopes: list[str], now: datetime | None = None) -> float:
        """Seconds the caller must still wait, or 0.0 if it may proceed. The
        strictest scope wins."""
        moment = now or utcnow()
        worst = 0.0
        for scope in scopes:
            record = self._store.get_login_attempts(scope)
            if record is None:
                continue
            failures, last_failed = record
            if moment - last_failed > LOGIN_ATTEMPT_TTL:
                continue
            required = login_backoff_seconds(failures)
            elapsed = (moment - last_failed).total_seconds()
            worst = max(worst, required - elapsed)
        return max(worst, 0.0)

    def record_failure(self, scopes: list[str]) -> None:
        for scope in scopes:
            self._store.record_login_failure(scope)

    def record_success(self, scopes: list[str]) -> None:
        for scope in scopes:
            self._store.clear_login_attempts(scope)


class AuthManager:
    """Bundles an ``Authenticator`` with server-side session storage and the auth
    settings that drive cookie/idle behaviour. The single object the web layer
    holds when authentication is enabled (``app.state.auth``)."""

    def __init__(
        self, store: Store, authenticator: Authenticator, settings: SessionSettings
    ) -> None:
        self._store = store
        self._authenticator = authenticator
        self.settings = settings

    @property
    def idle(self) -> timedelta:
        return timedelta(minutes=self.settings.idle_minutes)

    @property
    def backend(self) -> str:
        """``"basic"`` when the local username/password backend is active, else
        ``"ldap"`` — the UI uses this to decide whether to offer a password-change
        control (only basic-auth passwords are ours to change)."""
        return "basic" if isinstance(self._authenticator, BasicAuthenticator) else "ldap"

    def change_password(self, username: str, current_password: str, new_password: str) -> None:
        """Change the basic-auth password. Raises ``AuthError`` when this backend
        isn't basic-auth, the username doesn't match, or ``current_password`` is
        wrong."""
        if not isinstance(self._authenticator, BasicAuthenticator):
            raise AuthError("password changes are only supported with basic auth")
        if username != self._authenticator.settings.username:
            raise AuthError(f"unknown user {username!r}")
        self._authenticator.change_password(current_password, new_password)

    def login(self, username: str, password: str) -> tuple[str, AuthenticatedUser]:
        """Authenticate and open a session. Raises ``AuthError`` on any failure.
        Returns the raw session token (for the cookie) and the user."""
        user = self._authenticator.authenticate(username, password)
        token = new_session_token()
        self._store.create_session(
            SessionRow(
                token_hash=hash_token(token),
                username=user.username,
                display_name=user.display_name,
            )
        )
        return token, user

    def validate(self, token: str) -> SessionRow | None:
        """Return the live session for a cookie token, or ``None`` if it's unknown
        or idle-expired. Enforces the sliding idle window: expired sessions are
        deleted; valid ones have their ``last_seen_at`` refreshed."""
        row = self._store.get_session(hash_token(token))
        if row is None:
            return None
        if utcnow() - row.last_seen_at > self.idle:
            self._store.delete_session(row.token_hash)
            return None
        self._store.touch_session(row.token_hash)
        return row

    def logout(self, token: str) -> None:
        self._store.delete_session(hash_token(token))

    def purge_idle(self) -> int:
        return self._store.purge_idle_sessions(utcnow() - self.idle)

    def purge_login_attempts(self, cutoff: datetime) -> int:
        """Sweep stale failed-login throttle records — see LoginThrottle."""
        return self._store.purge_login_attempts(cutoff)


# -- LDAP backend ------------------------------------------------------------------


def _normalize_dn(dn: str) -> str:
    """Fold a DN for case/space-insensitive comparison (directories vary in the
    whitespace after RDN separators)."""
    return ",".join(part.strip() for part in dn.split(",")).casefold()


class LDAPAuthenticator:
    """Search-then-bind LDAP/AD authentication, gated on direct group membership.

    Flow: resolve the user's DN (service-account search, or a DN template) → bind as
    that DN with the supplied password to verify it → confirm the required group is
    present in the user's ``memberOf`` attribute. Any directory/bind error becomes a
    generic ``AuthError`` (the real cause is logged, never returned to the client).
    """

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self._server = self._build_server()

    def _build_server(self) -> Any:
        from ldap3 import ALL, Server, ServerPool, Tls

        tls = None
        if self.settings.start_tls or any(
            u.lower().startswith("ldaps") for u in self.settings.urls
        ):
            validate = ssl.CERT_REQUIRED if self.settings.tls_verify else ssl.CERT_NONE
            if not self.settings.tls_verify:
                # Deliberately auditable: disabling verification exposes the bind
                # (which carries the user's password) to MITM. Prefer trusting the
                # directory's CA via CHKP_CPUSE_LDAP_CA_CERT.
                logger.warning(
                    "LDAPS certificate verification DISABLED "
                    "(CHKP_CPUSE_LDAP_TLS_VERIFY=false) — connection is not MITM-safe",
                    urls=self.settings.urls,
                )
            tls = Tls(validate=validate, ca_certs_file=self.settings.ca_cert or None)
        servers = [Server(u, tls=tls, get_info=ALL) for u in self.settings.urls]
        if len(servers) == 1:
            return servers[0]
        return ServerPool(servers, active=True, exhaust=True)

    def _connection(self, user: str, password: str) -> Any:
        from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, SIMPLE, Connection
        from ldap3.core.exceptions import LDAPException

        auto_bind = AUTO_BIND_TLS_BEFORE_BIND if self.settings.start_tls else AUTO_BIND_NO_TLS
        try:
            return Connection(
                self._server,
                user=user,
                password=password,
                authentication=SIMPLE,
                auto_bind=auto_bind,
                read_only=True,
            )
        except LDAPException as exc:
            # Covers bad credentials and unreachable/failed-TLS directories alike.
            raise AuthError(f"LDAP bind failed for {user!r}: {exc}") from exc

    def authenticate(self, username: str, password: str) -> AuthenticatedUser:
        # An empty password can yield an unauthenticated/anonymous bind that
        # "succeeds" on many servers — reject it outright.
        if not password:
            raise AuthError("empty password")

        if self.settings.bind_dn:
            user_dn, groups, display = self._search_user(username)
            self._connection(user_dn, password).unbind()  # verify the password
        else:
            assert self.settings.user_dn_template is not None  # guaranteed by load_auth_settings
            user_dn = self.settings.user_dn_template.format(username=username)
            conn = self._connection(user_dn, password)
            groups, display = self._read_self(conn, user_dn)
            conn.unbind()

        self._check_group(groups, username)
        return AuthenticatedUser(username=username, display_name=display or username, dn=user_dn)

    def _search_user(self, username: str) -> tuple[str, list[str], str | None]:
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars

        assert self.settings.bind_dn is not None and self.settings.user_base_dn is not None
        filt = self.settings.user_filter.format(username=escape_filter_chars(username))
        conn = self._connection(self.settings.bind_dn, self.settings.bind_password or "")
        try:
            conn.search(
                self.settings.user_base_dn,
                filt,
                attributes=[self.settings.member_of_attr, "displayName", "cn"],
            )
            entries = conn.entries
        except LDAPException as exc:
            raise AuthError(f"LDAP user search failed: {exc}") from exc
        finally:
            conn.unbind()
        if not entries:
            raise AuthError(f"user {username!r} not found in directory")
        entry = entries[0]
        return entry.entry_dn, _attr_values(entry, self.settings.member_of_attr), _display(entry)

    def _read_self(self, conn: Any, user_dn: str) -> tuple[list[str], str | None]:
        from ldap3 import BASE
        from ldap3.core.exceptions import LDAPException

        try:
            conn.search(
                user_dn,
                "(objectClass=*)",
                search_scope=BASE,
                attributes=[self.settings.member_of_attr, "displayName", "cn"],
            )
            entries = conn.entries
        except LDAPException as exc:
            raise AuthError(f"LDAP self-read failed: {exc}") from exc
        if not entries:
            return [], None
        return _attr_values(entries[0], self.settings.member_of_attr), _display(entries[0])

    def _check_group(self, groups: list[str], username: str) -> None:
        required = _normalize_dn(self.settings.required_group)
        if required not in {_normalize_dn(g) for g in groups}:
            logger.warning(
                "login denied: not in required group",
                username=username,
                required_group=self.settings.required_group,
            )
            raise AuthError(f"user {username!r} is not a member of the required group")


def _attr_values(entry: Any, attr: str) -> list[str]:
    """Read a possibly-multivalued attribute off an ldap3 entry as a list of str."""
    try:
        raw = entry[attr].values
    except (KeyError, LookupError):
        return []
    return [str(v) for v in raw]


def _display(entry: Any) -> str | None:
    for attr in ("displayName", "cn"):
        try:
            values = entry[attr].values
        except (KeyError, LookupError):
            continue
        if values:
            return str(values[0])
    return None


# -- basic-auth backend -------------------------------------------------------------


class BasicAuthenticator:
    """A single configured username/password — the default backend when LDAP isn't
    configured. The password is changeable at runtime (the User Settings modal,
    basic-auth only): a change is verified against the current password, then hashed
    and persisted to the ``meta`` table so it survives a restart, overriding the
    env-var default from then on."""

    def __init__(self, store: Store, settings: BasicAuthSettings) -> None:
        self._store = store
        self.settings = settings
        self._hasher = PasswordHasher()
        stored_hash = store.get_meta(BASIC_AUTH_PASSWORD_HASH_META_KEY)
        self._password_hash = stored_hash or settings.password_hash
        # A runtime password change persists its own hash and overrides the
        # env-var default, so "still on admin/admin" needs both halves.
        self._uses_default_password = settings.is_default_password and stored_hash is None

    @property
    def uses_default_password(self) -> bool:
        """True while this deployment still accepts the built-in default
        password. Drives the startup warning in web/app.py — a tool that can
        reboot production firewalls should not sit on admin/admin quietly."""
        return self._uses_default_password

    def authenticate(self, username: str, password: str) -> AuthenticatedUser:
        if not password:
            raise AuthError("empty password")
        if username != self.settings.username:
            raise AuthError(f"unknown user {username!r}")
        try:
            self._hasher.verify(self._password_hash, password)
        except VerifyMismatchError as exc:
            raise AuthError("invalid password") from exc
        return AuthenticatedUser(username=username, display_name=username, dn=username)

    def change_password(self, current_password: str, new_password: str) -> None:
        if not current_password:
            raise AuthError("empty password")
        try:
            self._hasher.verify(self._password_hash, current_password)
        except VerifyMismatchError as exc:
            raise AuthError("current password is incorrect") from exc
        new_hash = self._hasher.hash(new_password)
        self._store.set_meta(BASIC_AUTH_PASSWORD_HASH_META_KEY, new_hash)
        self._password_hash = new_hash
        self._uses_default_password = False
        # Changing the password is how an operator responds to "someone else may
        # have my credentials" — so it has to end any session that credential
        # already established, not just stop new logins. The caller re-issues a
        # session for the user who made the change.
        self._store.delete_sessions_for_user(self.settings.username)
