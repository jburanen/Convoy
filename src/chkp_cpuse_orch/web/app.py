"""FastAPI application — JSON API + static, hand-editable UI.

The UI is plain HTML/CSS/JS served from ``web/static/`` (no build step, no
templating — see .claude/memory/patching-web-design.md). Routes here stay thin:
business logic lives in ``services/``.

Run: ``uvicorn chkp_cpuse_orch.web.app:app --host 0.0.0.0 --port 8080``.

Startup wiring (lifespan): config → Store → PackageStore → CredentialStore
(if the master key env is set — otherwise credential/patching endpoints return
503 and everything else still works) → JobRunner + PatchingService → recover
orphaned jobs → start the runner loop.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import RequestResponseEndpoint

from .. import __version__
from ..cdt import CandidatesFile
from ..config import Config
from ..credentials import (
    Credential,
    CredentialBundle,
    CredentialKind,
    CredentialSetInfo,
    CredentialStore,
    JobCredentialVault,
    load_master_key,
)
from ..errors import (
    AuthError,
    CDTError,
    CredentialError,
    InventoryError,
    JobError,
    OrchestratorError,
    PackageError,
    StoreError,
    TransportError,
)
from ..jobs import JobRunner
from ..packages import PackageStore
from ..reporting import configure_logging, get_logger
from ..services.cdt_ops import CDTService
from ..services.common import ClientFactory, EnvironmentRegistry
from ..services.discovery import DiscoveryService, MgmtClientFactory
from ..services.environments import EnvironmentManager
from ..services.patching import PatchingService
from ..services.provisioning import (
    DEFAULT_UID,
    MGMT_API_NOTES,
    PROVISIONING_NOTES,
    render_gaia_user_commands,
    render_mgmt_api_commands,
)
from ..store import JobEvent, JobRecord, PackageRecord, Store
from .auth import (
    SESSION_COOKIE_NAME,
    Authenticator,
    AuthManager,
    AuthSettings,
    LDAPAuthenticator,
    load_auth_settings,
)

logger = get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

# How often the background reaper sweeps for expired packages.
_REAP_INTERVAL_SECONDS = 3600.0
# How often idle web sessions are swept from the DB.
_SESSION_REAP_INTERVAL_SECONDS = 600.0

# Paths reachable without a valid session (login page + its assets, health, and
# the auth endpoints login needs). Everything else is guarded when auth is on.
_PUBLIC_PATHS = frozenset(
    {
        "/health",
        "/login.html",
        "/js/login.js",
        "/css/app.css",
        "/api/auth/login",
        "/api/auth/config",
        "/favicon.ico",
    }
)


async def _reap_expired_packages(
    packages: PackageStore, interval: float = _REAP_INTERVAL_SECONDS
) -> None:
    """Periodically delete packages past their retention deadline. Runs an
    immediate sweep on startup, then every ``interval`` seconds. Never raises
    out of the loop — a failed sweep is logged and retried next tick."""
    while True:
        try:
            purged = await asyncio.to_thread(packages.purge_expired)
            if purged:
                logger.info("purged expired packages", count=len(purged), files=purged)
        except Exception as exc:  # keep the reaper alive across transient errors
            logger.warning("package reaper sweep failed", error=str(exc))
        await asyncio.sleep(interval)


async def _reap_idle_sessions(
    auth: AuthManager, interval: float = _SESSION_REAP_INTERVAL_SECONDS
) -> None:
    """Periodically delete idle-expired web sessions. Idle expiry is also enforced
    inline on every request; this just keeps the table from accumulating stale
    rows for users who simply close the tab."""
    while True:
        await asyncio.sleep(interval)
        try:
            removed = await asyncio.to_thread(auth.purge_idle)
            if removed:
                logger.info("purged idle sessions", count=removed)
        except Exception as exc:
            logger.warning("session reaper sweep failed", error=str(exc))


# -- request/response bodies -------------------------------------------------------


class CredentialSetIn(BaseModel):
    """Create/replace a named login set. Exactly one SSH secret (password or
    private key) is expected; expert password and API key are optional."""

    name: str = Field(min_length=1)
    ssh_username: str | None = None
    ssh_password: SecretStr | None = None
    ssh_private_key: SecretStr | None = None
    expert_password: SecretStr | None = None
    api_key: SecretStr | None = None
    # Make this the environment's default set, but only if none is set yet. Used by
    # the bootstrap flow so the first credentials become the default automatically.
    default_if_none: bool = False


class CredentialAssignmentIn(BaseModel):
    """Assign a credential set (by name) to a server, or clear it with null."""

    set: str | None = None


class JobCredentialIn(BaseModel):
    """One credential supplied inline for a single operation in a storage-
    disabled environment. Never persisted — used in memory only."""

    kind: CredentialKind
    username: str | None = None
    secret: str = Field(min_length=1)


class OperationCredentials(BaseModel):
    """Mixin: optional inline credentials carried by SSH-backed requests. Empty
    for environments that store credentials; required for those that don't."""

    credentials: list[JobCredentialIn] = Field(default_factory=list)


class ImportRequest(OperationCredentials):
    package: str  # filename in the package store


class ImportCloudRequest(OperationCredentials):
    package_id: str  # CPUSE identifier as published in Check Point's cloud repo


class InstallRequest(OperationCredentials):
    package_id: str  # CPUSE identifier as shown by detect
    confirmed: bool = False  # UI must send True after an explicit operator confirm
    verify_first: bool = True


class RetentionRequest(BaseModel):
    pinned: bool  # True → keep indefinitely; False → apply the retention window


class StageRequest(OperationCredentials):
    package: str  # filename in the package store


class GenerateRequest(OperationCredentials):
    pass  # credentials only


class PrepareRequest(OperationCredentials):
    extended: bool = False  # extended also updates CPUSE + imports on targets


class ExecuteRequest(OperationCredentials):
    confirmed: bool = False  # UI must send True after an explicit operator confirm


class QueryRequest(OperationCredentials):
    pass  # live-state query bodies carry only (optional) credentials


class CandidatesIn(OperationCredentials):
    header: list[str]
    rows: list[list[str]]  # row order == deployment order


class CredentialStorageIn(BaseModel):
    enabled: bool


class LoginIn(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ProvisionRequest(BaseModel):
    username: str
    password: str = Field(min_length=1)  # only hashed, never stored or echoed
    uid: int = DEFAULT_UID
    # Also emit the expert-mode commands that grant this account Management API
    # access (an API-key admin) — needed for estate auto-discovery.
    mgmt_api: bool = True


class EnvironmentIn(BaseModel):
    name: str
    # Ignored by the rename endpoint (name-only); create uses it to declare the
    # environment's kind up front. See EnvironmentKindIn for changing it later.
    is_mds: bool = False


class EnvironmentKindIn(BaseModel):
    is_mds: bool


class EnvServerIn(BaseModel):
    name: str
    address: str
    # One of the seven management-plane roles (see inventory.Role); legacy
    # management/mds still accepted for back-compat.
    role: str = "primary_sms"
    ssh_user: str = "admin"
    ssh_port: int = 22
    notes: str | None = None


class DiscoverIn(BaseModel):
    primary: str  # name of the already-defined management server to scan from


# -- app factory -------------------------------------------------------------------


def create_app(
    config: Config | None = None,
    *,
    client_factory: ClientFactory | None = None,
    mgmt_client_factory: MgmtClientFactory | None = None,
    authenticator: Authenticator | None = None,
    auth_settings: AuthSettings | None = None,
) -> FastAPI:
    """Build the app. Tests pass a custom ``config`` (tmp paths), a fake
    ``client_factory``, and — to exercise auth without a live directory — a fake
    ``authenticator`` (with optional ``auth_settings`` to tune idle/cookie
    behaviour). Production leaves those ``None`` and resolves LDAP config from the
    environment at startup (auth stays off when it isn't configured)."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        cfg = config or Config.load()
        store = Store(cfg.paths.db_path)
        packages = PackageStore(
            store, cfg.paths.packages_dir, retention_days=cfg.package_retention_days
        )
        # In-memory credentials for jobs in storage-disabled environments.
        vault = JobCredentialVault()

        credentials: CredentialStore | None = None
        try:
            credentials = CredentialStore(store, load_master_key())
        except CredentialError as exc:
            # Boot anyway: health/packages/jobs still work; credential-dependent
            # endpoints return 503 with this reason.
            logger.warning("credential store locked", reason=str(exc))
            app.state.credentials_error = str(exc)

        # Authentication. When a fake authenticator is injected (tests), use it
        # with the given (or a permissive default) settings. Otherwise resolve
        # LDAP config from the environment: a valid config builds an LDAP backend,
        # an absent one leaves auth off (auth-optional), and a half-finished one
        # raises ConfigError from load_auth_settings and aborts startup.
        auth: AuthManager | None = None
        active_auth = authenticator
        settings = auth_settings
        if active_auth is None:
            settings = load_auth_settings()
            if settings is not None:
                active_auth = LDAPAuthenticator(settings)
        if active_auth is not None:
            if settings is None:
                # Injected authenticator without explicit settings: permissive
                # defaults suitable for a test client over plain HTTP.
                settings = AuthSettings(
                    url="injected", required_group="injected", cookie_secure=False
                )
            auth = AuthManager(store, active_auth, settings)
        app.state.auth = auth

        # Independent management environments — DB-backed and UI-editable. Seeded
        # once from config/inventory files, then the DB is authoritative (see
        # services/environments.py and .claude/memory/patching-web-design.md).
        registry = EnvironmentRegistry()
        env_manager = EnvironmentManager(store, registry, credentials, client_factory)
        env_manager.seed_from_config(cfg)
        env_manager.rebuild()

        # Without authentication, persisting credentials is not permitted. Enabling
        # storage is blocked at the API, but a pre-existing (e.g. config-seeded)
        # environment may still have it on — warn loudly rather than silently
        # exposing secrets. (Non-destructive: the operator decides how to remediate.)
        if auth is None:
            open_envs = [e.name for e in store.list_environments() if e.credential_storage_enabled]
            if open_envs:
                logger.warning(
                    "credential storage enabled without authentication configured",
                    environments=open_envs,
                    hint="configure LDAP auth (CHKP_CPUSE_LDAP_*) or disable storage for these",
                )

        # Purge a job's in-memory credentials the moment it reaches any terminal
        # state (success/failure/cancel), guaranteed by the runner.
        runner = JobRunner(store, on_job_finished=vault.discard)
        service = PatchingService(
            registry=registry, packages=packages, runner=runner, vault=vault, store=store
        )
        cdt_service = CDTService(registry=registry, packages=packages, runner=runner, vault=vault)
        discovery = DiscoveryService(registry=registry, mgmt_client_factory=mgmt_client_factory)

        app.state.store = store
        app.state.packages = packages
        app.state.credentials = credentials
        app.state.vault = vault
        app.state.registry = registry
        app.state.env_manager = env_manager
        app.state.runner = runner
        app.state.service = service
        app.state.cdt = cdt_service
        app.state.discovery = discovery

        interrupted = runner.recover()
        if interrupted:
            logger.warning("jobs interrupted by previous shutdown", count=len(interrupted))
        serve_task = asyncio.create_task(runner.serve())
        reaper_task = asyncio.create_task(_reap_expired_packages(packages))
        bg_tasks = [reaper_task]
        if auth is not None:
            bg_tasks.append(asyncio.create_task(_reap_idle_sessions(auth)))
        try:
            yield
        finally:
            runner.stop()
            for task in bg_tasks:
                task.cancel()
            for task in bg_tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await serve_task

    app = FastAPI(
        title="chkp-cpuse-orch",
        version=__version__,
        summary="Orchestration API for Check Point CDT/CPUSE deployments.",
        lifespan=lifespan,
    )
    _register_auth_middleware(app)
    _register_routes(app)
    return app


def _register_auth_middleware(app: FastAPI) -> None:
    """Guard every route (API + static UI) behind a valid session when auth is on.
    A no-op when ``app.state.auth`` is ``None`` (auth-optional / not configured)."""

    @app.middleware("http")
    async def _auth_guard(request: Request, call_next: RequestResponseEndpoint) -> Response:
        auth: AuthManager | None = getattr(request.app.state, "auth", None)
        if auth is None or request.url.path in _PUBLIC_PATHS:
            return await call_next(request)
        token = request.cookies.get(SESSION_COOKIE_NAME)
        session = await run_in_threadpool(auth.validate, token) if token else None
        if session is None:
            if request.url.path.startswith("/api/"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login.html", status_code=302)
        request.state.user = session.username
        return await call_next(request)


def _service(request: Request) -> PatchingService:
    service: PatchingService = request.app.state.service
    return service


def _build_credentials(
    items: list[JobCredentialIn], host_name: str, environment: str
) -> CredentialBundle:
    """Turn inline request credentials into an in-memory bundle. Possibly empty;
    the service validates it (ignored when the environment stores credentials)."""
    return {
        item.kind: Credential(
            host=host_name,
            kind=item.kind,
            username=item.username,
            secret=SecretStr(item.secret),
            environment=environment,
        )
        for item in items
    }


def _op_creds(
    body: OperationCredentials | None, host_name: str, environment: str
) -> CredentialBundle:
    """Bundle from an optional request body (empty when body/credentials absent).
    Used by endpoints whose body — carrying only credentials — may be omitted."""
    return _build_credentials(body.credentials if body is not None else [], host_name, environment)


def _registry(request: Request) -> EnvironmentRegistry:
    registry: EnvironmentRegistry = request.app.state.registry
    return registry


def _require_env(request: Request, env: str) -> None:
    """404 (via _map_error) when the environment doesn't exist."""
    try:
        _registry(request).get(env)
    except InventoryError as exc:
        raise _map_error(exc) from exc


def _credentials_or_503(request: Request) -> CredentialStore:
    credentials: CredentialStore | None = request.app.state.credentials
    if credentials is None:
        reason = getattr(request.app.state, "credentials_error", "credential store is locked")
        raise HTTPException(status_code=503, detail=reason)
    return credentials


def _map_error(exc: OrchestratorError) -> HTTPException:
    """Typed core errors → HTTP statuses. Fail with the real message — this is
    an internal operator tool, not a public API."""
    status = 400
    if isinstance(exc, InventoryError | PackageError):
        text = str(exc)
        if "already exists" in text:
            status = 409
        elif any(s in text for s in ("not found", "no such", "unknown environment")):
            status = 404
        else:
            status = 400
    elif isinstance(exc, CredentialError):
        text = str(exc)
        if "locked" in text:
            status = 503  # credential store needs the master key
        elif any(s in text for s in ("provide", "supply", "in-memory")):
            status = 400  # caller didn't supply required inline credentials
        else:
            status = 409
    elif isinstance(exc, CDTError):
        status = 409 if "running" in str(exc) else 400
    elif isinstance(exc, TransportError):
        status = 502
    elif isinstance(exc, StoreError):
        status = 404 if "not found" in str(exc) else 400
    elif isinstance(exc, JobError):
        status = 400
    return HTTPException(status_code=status, detail=str(exc))


def _register_routes(app: FastAPI) -> None:
    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness/readiness probe. Cheap, no external dependencies."""
        return {"status": "ok", "version": __version__}

    @app.get("/api/status")
    def status(request: Request) -> dict[str, Any]:
        service = _service(request)
        return {
            "version": __version__,
            "credentials_unlocked": request.app.state.credentials is not None,
            "auth_enabled": request.app.state.auth is not None,
            "environments": _registry(request).names(),
            "management_servers": sum(
                len(service.management_servers(env)) for env in _registry(request).names()
            ),
            "packages": len(request.app.state.packages.list()),
        }

    # -- authentication ---------------------------------------------------------

    def _auth(request: Request) -> AuthManager | None:
        manager: AuthManager | None = request.app.state.auth
        return manager

    @app.get("/api/auth/config")
    def auth_config(request: Request) -> dict[str, Any]:
        """Public: the login page and the client idle-timer read this before a
        session exists, so it must stay reachable without one."""
        auth = _auth(request)
        if auth is None:
            return {"auth_enabled": False, "idle_minutes": 0, "version": __version__}
        return {
            "auth_enabled": True,
            "idle_minutes": auth.settings.idle_minutes,
            "version": __version__,
        }

    @app.get("/api/auth/me")
    def auth_me(request: Request) -> dict[str, Any]:
        auth = _auth(request)
        if auth is None:
            return {"auth_enabled": False, "authenticated": False, "username": None}
        # Guarded by the middleware, so a request that reaches here is authenticated.
        return {
            "auth_enabled": True,
            "authenticated": True,
            "username": getattr(request.state, "user", None),
        }

    @app.post("/api/auth/login")
    async def auth_login(body: LoginIn, request: Request, response: Response) -> dict[str, str]:
        auth = _auth(request)
        if auth is None:
            raise HTTPException(status_code=400, detail="authentication is not configured")
        try:
            token, user = await run_in_threadpool(auth.login, body.username, body.password)
        except AuthError as exc:
            # Deliberately generic — don't disclose which check failed.
            logger.info("login failed", username=body.username, reason=str(exc))
            raise HTTPException(
                status_code=401, detail="invalid credentials or insufficient group membership"
            ) from exc
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            httponly=True,
            samesite="strict",
            secure=auth.settings.cookie_secure,
            path="/",
        )
        return {"username": user.username, "display_name": user.display_name}

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request, response: Response) -> dict[str, bool]:
        auth = _auth(request)
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if auth is not None and token:
            await run_in_threadpool(auth.logout, token)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return {"ok": True}

    # -- environments (create/edit; DB-backed, UI-managed) ----------------------

    def _envmgr(request: Request) -> EnvironmentManager:
        manager: EnvironmentManager = request.app.state.env_manager
        return manager

    @app.get("/api/environments")
    def environments(request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        return [
            {
                "name": env,
                "management_servers": len(service.management_servers(env)),
                "credential_storage_enabled": _registry(request)
                .get(env)
                .credential_storage_enabled,
                "is_mds": _registry(request).get(env).is_mds,
            }
            for env in _registry(request).names()
        ]

    @app.post("/api/environments", status_code=201)
    def create_environment(body: EnvironmentIn, request: Request) -> dict[str, str]:
        try:
            name = _envmgr(request).create_environment(body.name, is_mds=body.is_mds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"name": name}

    @app.post("/api/environments/{env}/rename")
    def rename_environment(env: str, body: EnvironmentIn, request: Request) -> dict[str, str]:
        """Servers, credentials, and job history move with the new name."""
        try:
            name = _envmgr(request).rename_environment(env, body.name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"name": name}

    @app.delete("/api/environments/{env}")
    def delete_environment(env: str, request: Request) -> dict[str, bool]:
        try:
            _envmgr(request).delete_environment(env)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"deleted": True}

    @app.post("/api/environments/{env}/credential-storage")
    def set_credential_storage(
        env: str, body: CredentialStorageIn, request: Request
    ) -> dict[str, Any]:
        """Enable or disable credential storage. Disabling purges any stored
        credentials for the environment (they'd be unused, and the operator
        opted out of on-disk secrets)."""
        if body.enabled and request.app.state.auth is None:
            raise HTTPException(
                status_code=409,
                detail="credential storage requires authentication — configure LDAP "
                "(CHKP_CPUSE_LDAP_*) before enabling storage for any environment",
            )
        try:
            purged = _envmgr(request).set_credential_storage(env, body.enabled)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"enabled": body.enabled, "purged_credentials": purged}

    @app.post("/api/environments/{env}/kind")
    def set_environment_kind(env: str, body: EnvironmentKindIn, request: Request) -> dict[str, Any]:
        """Declare an environment SMS or Multi-Domain (MDS) — decides which
        command variants discovery (and future MDS-vs-SMS-specific tasks) use."""
        try:
            _envmgr(request).set_environment_kind(env, body.is_mds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"is_mds": body.is_mds}

    @app.get("/api/environments/{env}/servers")
    def env_servers(env: str, request: Request) -> list[dict[str, Any]]:
        """Full editable server list for the environment editor."""
        try:
            return [
                {
                    "name": h.name,
                    "address": h.address,
                    "role": h.role,
                    "ssh_user": h.ssh_user,
                    "ssh_port": h.ssh_port,
                }
                for h in _envmgr(request).list_servers(env)
            ]
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/environments/{env}/servers", status_code=201)
    def add_env_server(env: str, body: EnvServerIn, request: Request) -> dict[str, str]:
        try:
            _envmgr(request).add_server(
                env,
                name=body.name,
                address=body.address,
                role=body.role,
                ssh_user=body.ssh_user,
                ssh_port=body.ssh_port,
                notes=body.notes,
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"name": body.name}

    @app.delete("/api/environments/{env}/servers/{name}")
    def remove_env_server(env: str, name: str, request: Request) -> dict[str, bool]:
        try:
            _envmgr(request).remove_server(env, name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"deleted": True}

    @app.post("/api/environments/{env}/discover")
    def discover_servers(env: str, body: DiscoverIn, request: Request) -> dict[str, Any]:
        """Scan the estate from an already-defined primary and return candidate
        servers (with a best-guess role) for the operator to review and import.
        Read-only: nothing is added here — the UI posts confirmed rows back to the
        add-server endpoint."""
        discovery: DiscoveryService = request.app.state.discovery
        try:
            result = discovery.discover(env, body.primary)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {
            "servers": [
                {
                    "name": s.name,
                    "address": s.address,
                    "role": s.detected_role.value,
                    "source": s.source,
                    "already_in_inventory": s.already_in_inventory,
                    "needs_review": s.needs_review,
                    "note": s.note,
                }
                for s in result.servers
            ],
            "warnings": result.warnings,
        }

    # -- service-account provisioning (pure rendering; nothing stored) ---------

    @app.post("/api/provision")
    def provision(body: ProvisionRequest) -> dict[str, list[str]]:
        try:
            commands = render_gaia_user_commands(body.username, body.password, uid=body.uid)
            api_commands = render_mgmt_api_commands(body.username) if body.mgmt_api else []
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {
            "commands": commands,
            "notes": PROVISIONING_NOTES,
            "api_commands": api_commands,
            "api_notes": MGMT_API_NOTES if body.mgmt_api else [],
        }

    # -- servers (environment-scoped) ------------------------------------------

    @app.get("/api/env/{env}/servers")
    def servers(env: str, request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        store: Store = request.app.state.store
        try:
            result = []
            for h in service.management_servers(env):
                cached = store.get_server_state(env, h.name)
                result.append(
                    {
                        "name": h.name,
                        "address": h.address,
                        "role": h.role.value,
                        "ssh_user": h.ssh_user,
                        "credential_set": service.assigned_credential(env, h.name),
                        "version": cached.version if cached else None,
                        "jhf": cached.jhf if cached else None,
                        "agent_build": cached.agent_build if cached else None,
                        "checked_at": cached.checked_at.isoformat() if cached else None,
                        "installable": cached.installable if cached else [],
                    }
                )
            return result
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/servers/{name}/state")
    async def server_state(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> dict[str, Any]:
        """Live CPUSE state (POST so storage-disabled environments can carry
        one-shot credentials in the body; the body is empty otherwise). Cached
        so the servers list can always show the last-known state."""
        creds = _op_creds(body, name, env)
        service = _service(request)
        try:
            detected = await asyncio.to_thread(service.detect, env, name, credentials=creds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        # detect() already persisted the summary/installable list — read it
        # back rather than recomputing, so the response matches exactly what
        # was cached (same timestamp too).
        store: Store = request.app.state.store
        cached = store.get_server_state(env, name)
        assert cached is not None  # detect() just persisted it
        return {
            "host": detected.host,
            "agent_build": detected.agent_build,
            "version": cached.version,
            "jhf": cached.jhf,
            "checked_at": cached.checked_at.isoformat(),
            "installable": cached.installable,
            "packages": [
                {
                    "identifier": p.identifier,
                    "status": p.status,
                    "description": p.description,
                    "is_installed": p.is_installed,
                    "is_imported": p.is_imported,
                }
                for p in detected.packages
            ],
        }

    @app.post("/api/env/{env}/servers/{name}/import", status_code=202)
    def server_import(env: str, name: str, body: ImportRequest, request: Request) -> JobRecord:
        try:
            return _service(request).submit_import(
                env, name, body.package, credentials=_build_credentials(body.credentials, name, env)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/servers/{name}/import-cloud", status_code=202)
    def server_import_cloud(
        env: str, name: str, body: ImportCloudRequest, request: Request
    ) -> JobRecord:
        try:
            return _service(request).submit_import_cloud(
                env,
                name,
                body.package_id,
                credentials=_build_credentials(body.credentials, name, env),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/servers/{name}/install", status_code=202)
    def server_install(env: str, name: str, body: InstallRequest, request: Request) -> JobRecord:
        try:
            return _service(request).submit_install(
                env,
                name,
                body.package_id,
                confirmed=body.confirmed,
                verify_first=body.verify_first,
                credentials=_build_credentials(body.credentials, name, env),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- packages ------------------------------------------------------------

    @app.get("/api/packages")
    def list_packages(request: Request) -> list[PackageRecord]:
        packages: PackageStore = request.app.state.packages
        return packages.list()

    @app.post("/api/packages", status_code=201)
    async def upload_package(file: UploadFile, request: Request) -> PackageRecord:
        packages: PackageStore = request.app.state.packages
        if not file.filename:
            raise HTTPException(status_code=400, detail="upload is missing a filename")
        try:
            # Streamed to disk while hashing — never buffered in memory.
            return await asyncio.to_thread(packages.add_stream, file.filename, file.file)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/packages/{filename}/retention")
    def set_package_retention(
        filename: str, body: RetentionRequest, request: Request
    ) -> PackageRecord:
        """Pin a package to keep it indefinitely, or un-pin it so the retention
        window applies again."""
        packages: PackageStore = request.app.state.packages
        try:
            return packages.set_pinned(filename, body.pinned)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/packages/{filename}")
    def delete_package(filename: str, request: Request) -> dict[str, bool]:
        packages: PackageStore = request.app.state.packages
        try:
            return {"deleted": packages.delete(filename)}
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- credential sets (named login objects; environment-scoped) --------------

    @app.get("/api/env/{env}/credentials")
    def list_credential_sets(env: str, request: Request) -> list[CredentialSetInfo]:
        _require_env(request, env)
        return _credentials_or_503(request).list_sets(env)

    @app.put("/api/env/{env}/credentials", status_code=201)
    def put_credential_set(env: str, body: CredentialSetIn, request: Request) -> CredentialSetInfo:
        _require_env(request, env)
        if request.app.state.auth is None:
            raise HTTPException(
                status_code=409,
                detail="credential storage requires authentication — configure LDAP "
                "(CHKP_CPUSE_LDAP_*) before storing credentials",
            )
        if not _registry(request).get(env).credential_storage_enabled:
            raise HTTPException(
                status_code=409,
                detail=f"credential storage is disabled for environment {env!r} — "
                "enable it first, or supply credentials per operation",
            )
        store = _credentials_or_503(request)

        def _reveal(value: SecretStr | None) -> str | None:
            return value.get_secret_value() if value is not None else None

        try:
            info = store.put_set(
                env,
                body.name,
                ssh_username=body.ssh_username,
                ssh_password=_reveal(body.ssh_password),
                ssh_private_key=_reveal(body.ssh_private_key),
                expert_password=_reveal(body.expert_password),
                api_key=_reveal(body.api_key),
            )
            # First credentials in an environment become its default automatically.
            if body.default_if_none and store.default_set_name(env) is None:
                store.set_default(env, body.name)
                info = info.model_copy(update={"is_default": True})
            return info
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/credentials/{name}/default")
    def set_default_credential_set(env: str, name: str, request: Request) -> dict[str, str | None]:
        """Make a credential set the environment's default (assigned to new servers)."""
        _require_env(request, env)
        store = _credentials_or_503(request)
        if not store.set_default(env, name):
            raise HTTPException(status_code=404, detail=f"credential set {name!r} not found")
        return {"default": name}

    @app.delete("/api/env/{env}/credentials/{name}")
    def delete_credential_set(env: str, name: str, request: Request) -> dict[str, bool]:
        _require_env(request, env)
        return {"deleted": _credentials_or_503(request).delete_set(env, name)}

    @app.post("/api/env/{env}/servers/{name}/credential")
    def assign_credential(
        env: str, name: str, body: CredentialAssignmentIn, request: Request
    ) -> dict[str, str | None]:
        """Assign a credential set (by name) to a management server, or clear it."""
        try:
            _envmgr(request).assign_credential(env, name, body.set)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"credential_set": body.set}

    # -- CDT (gateway fleet, driven from a management server) --------------------

    def _cdt(request: Request) -> CDTService:
        cdt: CDTService = request.app.state.cdt
        return cdt

    @app.post("/api/env/{env}/cdt/{name}/status")
    async def cdt_status(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> dict[str, Any]:
        creds = _op_creds(body, name, env)
        try:
            return await asyncio.to_thread(_cdt(request).get_status, env, name, credentials=creds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/cdt/{name}/candidates/read")
    async def cdt_candidates(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> dict[str, Any]:
        creds = _op_creds(body, name, env)
        try:
            cands = await asyncio.to_thread(
                _cdt(request).get_candidates, env, name, credentials=creds
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"header": cands.header, "rows": cands.rows}

    @app.put("/api/env/{env}/cdt/{name}/candidates")
    async def cdt_save_candidates(
        env: str, name: str, body: CandidatesIn, request: Request
    ) -> dict[str, int]:
        creds = _build_credentials(body.credentials, name, env)
        try:
            count = await asyncio.to_thread(
                _cdt(request).save_candidates,
                env,
                name,
                CandidatesFile(header=body.header, rows=body.rows),
                credentials=creds,
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"rows": count}

    @app.post("/api/env/{env}/cdt/{name}/stage", status_code=202)
    def cdt_stage(env: str, name: str, body: StageRequest, request: Request) -> JobRecord:
        try:
            return _cdt(request).submit_stage(
                env, name, body.package, credentials=_build_credentials(body.credentials, name, env)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/cdt/{name}/generate", status_code=202)
    def cdt_generate(
        env: str, name: str, request: Request, body: GenerateRequest | None = None
    ) -> JobRecord:
        try:
            return _cdt(request).submit_generate(env, name, credentials=_op_creds(body, name, env))
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/cdt/{name}/prepare", status_code=202)
    def cdt_prepare(env: str, name: str, body: PrepareRequest, request: Request) -> JobRecord:
        try:
            return _cdt(request).submit_prepare(
                env,
                name,
                extended=body.extended,
                credentials=_build_credentials(body.credentials, name, env),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/cdt/{name}/execute", status_code=202)
    def cdt_execute(env: str, name: str, body: ExecuteRequest, request: Request) -> JobRecord:
        try:
            return _cdt(request).submit_execute(
                env,
                name,
                confirmed=body.confirmed,
                credentials=_build_credentials(body.credentials, name, env),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- jobs ------------------------------------------------------------------

    @app.get("/api/jobs")
    def list_jobs(request: Request, limit: int = 50) -> list[JobRecord]:
        store: Store = request.app.state.store
        return store.list_jobs(limit=limit)

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> JobRecord:
        store: Store = request.app.state.store
        try:
            return store.get_job(job_id)
        except StoreError as exc:
            raise _map_error(exc) from exc

    @app.get("/api/jobs/{job_id}/events")
    def job_events(job_id: str, request: Request, after: int = 0) -> list[JobEvent]:
        store: Store = request.app.state.store
        return store.events(job_id, after_seq=after)

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, request: Request) -> dict[str, str]:
        runner: JobRunner = request.app.state.runner
        try:
            runner.request_cancel(job_id)
        except StoreError as exc:
            raise _map_error(exc) from exc
        return {"status": "cancel requested"}

    # -- static UI (mounted last so /api and /health win) -----------------------
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")


app = create_app()
