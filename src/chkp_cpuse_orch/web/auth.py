"""Web authentication — LDAP/Active Directory login behind a small backend-agnostic
interface, plus session-token helpers.

Configured entirely from the environment (see ``.env.example``). Presence of
``CHKP_CPUSE_LDAP_URL`` **and** ``CHKP_CPUSE_LDAP_REQUIRED_GROUP`` enables auth; when
either is absent, ``load_auth_settings`` returns ``None`` and the web app runs open
(auth-optional — but credential storage is then forbidden; see web/app.py). A URL set
with an incomplete rest-of-config fails loudly, never silently open.

The ``Authenticator`` protocol keeps the design open to other backends (local
basic-auth, etc.) landing behind the same session layer later. ``LDAPAuthenticator``
implements search-then-bind against AD or any LDAP directory and gates access on
direct ``memberOf`` membership of a configured group.

Only non-secret settings and transient in-memory secrets live here; session tokens
are stored hashed (see store.py).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import ssl
from datetime import timedelta
from typing import Any, Protocol

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

    idle_raw = env.get(SESSION_IDLE_MINUTES_ENV)
    try:
        idle = int(idle_raw) if idle_raw else DEFAULT_IDLE_MINUTES
    except ValueError as exc:
        raise ConfigError(
            f"{SESSION_IDLE_MINUTES_ENV} must be an integer, got {idle_raw!r}"
        ) from exc

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
        cookie_secure=_env_bool(env, SESSION_COOKIE_SECURE_ENV, True),
    )


# -- session token helpers ---------------------------------------------------------


def new_session_token() -> str:
    """A fresh opaque session token (goes in the cookie; only its hash is stored)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 of a session token — what the DB stores. Constant work, no salt
    needed: the token is 256 bits of entropy, not a low-entropy password."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthManager:
    """Bundles an ``Authenticator`` with server-side session storage and the auth
    settings that drive cookie/idle behaviour. The single object the web layer
    holds when authentication is enabled (``app.state.auth``)."""

    def __init__(self, store: Store, authenticator: Authenticator, settings: AuthSettings) -> None:
        self._store = store
        self._authenticator = authenticator
        self.settings = settings

    @property
    def idle(self) -> timedelta:
        return timedelta(minutes=self.settings.idle_minutes)

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
