"""FastAPI application — JSON API + static, hand-editable UI.

The UI is plain HTML/CSS/JS served from ``web/static/`` (no build step, no
templating — see .claude/memory/patching-web-design.md). Routes here stay thin:
business logic lives in ``services/``.

Run: ``uvicorn convoy.web.app:app --host 0.0.0.0 --port 8080``, or
``python -m convoy.web`` (see web/__main__.py) for optional, off-by-default
HTTPS via ``CONVOY_SSL_CERTFILE`` / ``CONVOY_SSL_KEYFILE``.

Startup wiring (lifespan): config → Store → PackageStore → CredentialStore
(if the master key env is set — otherwise credential/patching endpoints return
503 and everything else still works) → JobRunner + PatchingService/CDTService/
PackageJobService → recover orphaned jobs → start the runner loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import uuid
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import FastAPI, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import RequestResponseEndpoint

from .. import __version__
from ..archive import JobArchiver
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
from ..envcompat import compat_env
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
from ..packages import PackageStore, check_filename
from ..reporting import configure_logging, get_logger, resolve_log_level
from ..services.api_access import ApiAccessService
from ..services.cdt_ops import CDTService
from ..services.common import ClientFactory, EnvironmentRegistry
from ..services.connect_primary import PrimaryConnectService
from ..services.cred_ops import CredentialJobService
from ..services.discovery import DiscoveryService, MgmtClientFactory
from ..services.environments import EnvironmentManager
from ..services.firewalls import FirewallManager
from ..services.gateway_bootstrap import GatewayBootstrapService
from ..services.patching import PatchingService
from ..services.pkg_repo_ops import PackageRepoService, RepoClientFactory
from ..services.pkgs_ops import PackageJobService
from ..services.prov_ops import UNSET, ProvisioningJobService
from ..services.provisioning import (
    MDS_API_NOTE,
    MGMT_API_NOTES,
    PROVISIONING_NOTES,
    render_gaia_user_commands,
    render_mgmt_api_commands,
)
from ..services.spark_patching import SparkPatchingService
from ..store import JobEvent, JobRecord, JobStatus, PackageRecord, Store, utcnow
from ..transport.ssh import forget_host_key, set_known_hosts_path
from .auth import (
    ALLOW_NO_AUTH_ENV,
    BASIC_AUTH_DISABLE_ENV,
    LOGIN_ATTEMPT_TTL,
    SESSION_COOKIE_NAME,
    Authenticator,
    AuthManager,
    AuthSettings,
    BasicAuthenticator,
    BasicAuthSettings,
    LDAPAuthenticator,
    LoginThrottle,
    load_active_auth_settings,
)

logger = get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

# Ceiling on one /api/jobs page, including the Jobs tab's "All" option. Each
# JobRecord can carry up to 2 MB of captured install-log text, so "all" over a
# year of retained history is an expensive response to rebuild on every poll.
MAX_JOBS_PAGE = 500

# Ceiling on one package upload. Check Point JHF bundles run to a few GB, so
# this has to be generous — it exists to stop an unbounded or repeated upload
# filling /data, which also holds the SQLite DB and the job archive, not to
# second-guess a legitimate package. Overridable for deployments with unusually
# large images.
MAX_UPLOAD_BYTES = int(compat_env().get("CONVOY_MAX_UPLOAD_BYTES") or 16 * 1024**3)
# Keep this much free beyond the incoming file, so an upload that just fits
# doesn't leave the DB with nowhere to write.
_UPLOAD_FREE_SPACE_MARGIN = 1 * 1024**3
_UPLOAD_CHUNK = 1024 * 1024

# How often the background reaper sweeps for expired packages.
_REAP_INTERVAL_SECONDS = 3600.0
# How often idle web sessions are swept from the DB.
_SESSION_REAP_INTERVAL_SECONDS = 600.0
# How often old jobs are swept into the flat-file archive. The retention
# window is a year, so once a day is plenty — this just needs to run
# regularly enough that the archive/DB don't fall meaningfully behind.
_JOB_ARCHIVE_INTERVAL_SECONDS = 86400.0

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


async def _reap_old_jobs(
    archiver: JobArchiver, interval: float = _JOB_ARCHIVE_INTERVAL_SECONDS
) -> None:
    """Periodically move jobs past the retention window into the flat-file
    archive and delete them from the DB. Runs an immediate sweep on startup,
    then every ``interval`` seconds. Never raises out of the loop — a failed
    sweep is logged and retried next tick."""
    while True:
        try:
            archived = await asyncio.to_thread(archiver.run)
            if archived:
                logger.info("archived old jobs", count=archived)
        except Exception as exc:  # keep the reaper alive across transient errors
            logger.warning("job archive sweep failed", error=str(exc))
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
            # Same sweep keeps login_attempts from accumulating one row per
            # source address ever seen. Records this old are already past any
            # backoff window (see LOGIN_ATTEMPT_TTL).
            stale = await asyncio.to_thread(auth.purge_login_attempts, utcnow() - LOGIN_ATTEMPT_TTL)
            if stale:
                logger.info("purged stale login-throttle records", count=stale)
        except Exception as exc:
            logger.warning("session reaper sweep failed", error=str(exc))


# -- request/response bodies -------------------------------------------------------


class CredentialSetIn(BaseModel):
    """Create/replace a named login set. A set needs an SSH secret or an API
    key; a set carrying an SSH secret needs exactly one (password or private
    key) plus an expert-mode password, since every stored host is a management
    server or a firewall and either may need to escalate (see
    .claude/memory/gaia-shell-posture.md). All enforced in
    ``CredentialStore.put_set``, which keys the rules off what the set carries
    rather than off the environment's access mode.

    Every secret field is optional on the wire: on an update, omitting one
    keeps the stored value, which is what lets an operator change just the API
    key without re-entering the SSH secret."""

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
    # Carries an operator's override past a disk-space shortfall a previous
    # run of this same import already failed on (see
    # PatchingService.retry_import_with_override)
    # (still >=1.5x the package's own size) and the operator chose to
    # proceed anyway. Ignored by the precheck endpoint itself.
    force_low_space: bool = False


class ImportCloudRequest(OperationCredentials):
    package_id: str  # CPUSE identifier as published in Check Point's cloud repo


class InstallRequest(OperationCredentials):
    package_id: str  # CPUSE identifier as shown by detect
    confirmed: bool = False  # UI must send True after an explicit operator confirm
    verify_first: bool = True


class UninstallRequest(OperationCredentials):
    package_id: str  # CPUSE identifier as shown by detect (must be Installed)
    confirmed: bool = False  # UI must send True after the operator types the host's name


class SparkImportRequest(OperationCredentials):
    package: str  # .img filename in the package store — SCP to /storage only, no confirm
    # needed: unlike install (InstallRequest, shared with CPUSE), this doesn't reboot anything.


class RetentionRequest(BaseModel):
    pinned: bool  # True → keep indefinitely; False → apply the retention window


class StageRequest(OperationCredentials):
    package: str  # filename in the package store


class GenerateRequest(OperationCredentials):
    pass  # credentials only


class PushToRepoRequest(OperationCredentials):
    pass  # credentials only — the target is always the environment's primary


class PrepareRequest(OperationCredentials):
    extended: bool = False  # extended also updates CPUSE + imports on targets


class ExecuteRequest(OperationCredentials):
    confirmed: bool = False  # UI must send True after an explicit operator confirm


class QueryRequest(OperationCredentials):
    pass  # live-state query bodies carry only (optional) credentials


class ClusterNameRequest(BaseModel):
    cluster_name: str | None = None  # None clears a manually-set name


class FirewallDomainRequest(BaseModel):
    mds_domain: str | None = None  # None clears a manually-set domain


class CandidatesIn(OperationCredentials):
    header: list[str]
    rows: list[list[str]]  # row order == deployment order


class CredentialStorageIn(BaseModel):
    enabled: bool


class LoginIn(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ChangePasswordIn(BaseModel):
    """Basic-auth only (see AuthManager.change_password) — 400 under LDAP."""

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class ProvisionRequest(BaseModel):
    """Renders the Gaia service-account clish commands only — Management API
    provisioning is now a separate, automated step (see ConnectPrimaryIn /
    PrimaryConnectService); this endpoint never itself reads or writes the
    store. No uid field: this tool always provisions uid 0 (render_gaia_user_
    commands' default, matching the built-in adminRole accounts it mirrors) —
    not an operator choice."""

    username: str
    password: str = Field(min_length=1)  # only hashed, never stored or echoed


class EnvironmentIn(BaseModel):
    name: str
    # Ignored by the rename endpoint (name-only); create uses it to declare the
    # environment's kind up front. See EnvironmentKindIn for changing it later.
    is_mds: bool = False


class EnvironmentKindIn(BaseModel):
    is_mds: bool


class EnvironmentAccessIn(BaseModel):
    api_only: bool


class SkipVerifyDefaultIn(BaseModel):
    skip_verify_by_default: bool


class EnvServerIn(BaseModel):
    name: str
    address: str
    # One of the seven management-plane roles (see inventory.Role); legacy
    # management/mds still accepted for back-compat.
    role: str = "primary_sms"
    ssh_user: str = "admin"
    ssh_port: int = 22
    notes: str | None = None
    # Explicit assignment (or clear, with null) made in the same Add/Edit modal
    # submit — folded into the same prov.add/prov.edit job rather than a
    # separate follow-up call, which could otherwise 404 if it reached the
    # server before the add/edit job itself had run. Omit the field entirely
    # to leave any existing assignment (or the environment-default-on-create
    # logic in EnvironmentManager.add_server) alone — see services/prov_ops.py.
    credential_set: str | None = None


class ConfirmRequest(BaseModel):
    """Body for a destructive endpoint whose only input is the operator saying
    yes. Same `confirmed` convention as InstallRequest/UninstallRequest/
    ExecuteRequest — these two were the only state-changing routes taking no
    body at all, so a bare POST was enough to rewrite a live gateway's admin
    account or restart a management server's API."""

    confirmed: bool = False


class AcceptHostKeyRequest(BaseModel):
    """Operator acknowledgement that a host's SSH key legitimately changed."""

    confirmed: bool = False


class ConnectPrimaryIn(OperationCredentials):
    name: str
    address: str
    role: str = "primary_sms"  # primary_sms or primary_mds only
    ssh_user: str = "admin"
    ssh_port: int = 22
    # Acknowledges repointing an EXISTING server to a different address, which
    # redirects its stored credentials and every future job to the new host.
    # Ignored when adding a new server or reconnecting to the same address.
    confirm_address_change: bool = False
    # Name of a stored credential set (storage-enabled environments only) —
    # its ssh_username also becomes the Management API administrator's name.
    # None for storage-disabled environments, which instead supply
    # `credentials` (OperationCredentials) for the one-off SSH connection and
    # never get the captured key auto-saved anywhere durable.
    credential_set: str | None = None


class DiscoverIn(BaseModel):
    primary: str  # name of the already-defined management server to scan from


class DiscoverFirewallsIn(BaseModel):
    # No source server here — an environment has exactly one primary (SMS or
    # MDS), so DiscoveryService resolves it automatically. MDS only: which
    # Domain/CMA (from the /domains endpoint) to scan for gateways.
    domain: str | None = None


class FirewallIn(BaseModel):
    name: str
    address: str
    # One of the firewall roles (see inventory.FIREWALL_ROLES).
    role: str = "gateway"
    ssh_user: str = "admin"
    ssh_port: int = 22
    notes: str | None = None
    # See EnvServerIn.credential_set — same reasoning, same fold-into-the-job.
    credential_set: str | None = None
    # Real cluster object name, pre-filled by the discover-firewalls import
    # flow (Management API resolved it at scan time — see
    # DiscoveryService.find_cluster_for_gateway). Only ever applied on a
    # genuine creation (services/prov_ops.py gates on JOB_ADD), so leaving
    # this unset on an edit can never clobber a previously-detected name.
    cluster_name: str | None = None
    # MDS Domain/CMA this firewall lives in, pre-filled by the discover-
    # firewalls import flow (the operator-picked Domain that scan ran
    # against). Same JOB_ADD-only gating as cluster_name — manual correction
    # goes through the dedicated mds-domain endpoint instead.
    mds_domain: str | None = None
    # Operator-entered free-text labels, applied on every add AND edit
    # (unlike cluster_name/mds_domain above) — plain UI metadata.
    tags: list[str] = Field(default_factory=list)


# -- app factory -------------------------------------------------------------------


def create_app(
    config: Config | None = None,
    *,
    client_factory: ClientFactory | None = None,
    mgmt_client_factory: MgmtClientFactory | None = None,
    authenticator: Authenticator | None = None,
    auth_settings: AuthSettings | None = None,
    spark_probe_reachable: Callable[[str, int], bool] | None = None,
) -> FastAPI:
    """Build the app. Tests pass a custom ``config`` (tmp paths), a fake
    ``client_factory``, and — to exercise auth without a live directory — a fake
    ``authenticator`` (with optional ``auth_settings`` to tune idle/cookie
    behaviour). Production leaves those ``None`` and resolves LDAP config from the
    environment at startup (auth stays off when it isn't configured).
    ``spark_probe_reachable`` overrides SparkPatchingService's post-reboot
    reachability check (real ICMP/TCP by default) — tests inject one that
    skips real network I/O against inventory addresses that don't exist."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(level=resolve_log_level())
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
        # with the given (or a permissive default) settings. Otherwise resolve the
        # active backend from the environment: LDAP takes priority when configured
        # (a half-finished LDAP config raises ConfigError and aborts startup);
        # otherwise local basic-auth, which is ON BY DEFAULT (BASIC_AUTH_USER/
        # BASIC_AUTH_PASSWORD, default admin/admin) unless BASIC_AUTH_DISABLE is
        # set — only then does auth end up fully off (auth-optional).
        auth: AuthManager | None = None
        active_auth = authenticator
        settings: AuthSettings | BasicAuthSettings | None = auth_settings
        if active_auth is None:
            settings = load_active_auth_settings()
            if isinstance(settings, BasicAuthSettings):
                active_auth = BasicAuthenticator(store, settings)
            elif settings is not None:
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

        # H3: a tool that can reboot production firewalls should not sit on the
        # shipped default password quietly. Warned on EVERY startup while it is
        # still live, not once — an operator who never reads the first boot log
        # is exactly the one who needs telling.
        if isinstance(active_auth, BasicAuthenticator) and active_auth.uses_default_password:
            logger.warning(
                "SECURITY: still using the built-in default password "
                "(admin/admin) — anyone who can reach this service has full "
                "control of every managed firewall",
                hint=(
                    "change it in the UI's User Settings modal, or set "
                    "BASIC_AUTH_PASSWORD, or configure LDAP"
                ),
            )

        # Independent management environments — DB-backed and UI-editable. Seeded
        # once from config/inventory files, then the DB is authoritative (see
        # services/environments.py and .claude/memory/patching-web-design.md).
        registry = EnvironmentRegistry()
        env_manager = EnvironmentManager(
            store, registry, credentials, client_factory, auth_enabled=auth is not None
        )
        env_manager.seed_from_config(cfg)
        env_manager.rebuild()
        firewall_manager = FirewallManager(store, env_manager)

        # Without authentication, persisting credentials is not permitted — for
        # every environment alike, including one seeded from config.yaml with
        # the DB flag already on (see EnvironmentManager.rebuild, which ANDs
        # that flag with auth_enabled when building each connector). So this
        # is no longer "silently exposing secrets" the way it used to be —
        # storage is genuinely unusable here — just a heads-up that the
        # operator's stored preference isn't taking effect yet.
        if auth is None:
            # H5: running open exposes EVERY destructive route — enumerate the
            # estate, delete environments, cancel jobs, bootstrap gateway admin
            # accounts. Only credential *storage* was ever gated on auth. Warn
            # unconditionally, not just when a storage-enabled environment
            # happens to exist.
            logger.warning(
                "SECURITY: authentication is DISABLED — every API route, including "
                "credential bootstrap, CDT execute, and environment deletion, is "
                "reachable by anyone who can connect to this service",
                hint=(
                    f"unset {BASIC_AUTH_DISABLE_ENV}/{ALLOW_NO_AUTH_ENV} to restore "
                    "the login gate, or configure LDAP (CONVOY_LDAP_*)"
                ),
            )
            open_envs = [e.name for e in store.list_environments() if e.credential_storage_enabled]
            if open_envs:
                logger.warning(
                    "credential storage requested but authentication isn't configured — "
                    "treating storage as disabled for these environments",
                    environments=open_envs,
                    hint="configure LDAP auth (CONVOY_LDAP_*) to enable it",
                )

        # Purge a job's in-memory credentials the moment it reaches any terminal
        # state (success/failure/cancel), guaranteed by the runner.
        runner = JobRunner(store, on_job_finished=vault.discard)
        service = PatchingService(
            registry=registry, packages=packages, runner=runner, vault=vault, store=store
        )
        spark_service = SparkPatchingService(
            registry=registry,
            packages=packages,
            runner=runner,
            vault=vault,
            store=store,
            probe_reachable=spark_probe_reachable,
        )
        cdt_service = CDTService(
            registry=registry, packages=packages, runner=runner, vault=vault, store=store
        )
        # No runner: package CRUD runs synchronously (services/pkgs_ops.py).
        pkgs_jobs = PackageJobService(packages=packages, store=store)
        # Only when the store is actually unlocked — a locked store already
        # returns 503 for every credential-dependent endpoint (see
        # _credentials_or_503), and that check happens before this is ever
        # reached, but there's no valid CredentialStore to hand it otherwise.
        # No runner/vault: credential CRUD runs synchronously (services/cred_ops.py).
        cred_jobs = (
            CredentialJobService(credentials=credentials, store=store)
            if credentials is not None
            else None
        )
        # No credential store dependency (no secrets involved), unlike cred_jobs —
        # always constructed. No runner: server/firewall CRUD runs synchronously
        # (services/prov_ops.py).
        prov_jobs = ProvisioningJobService(
            store=store, env_manager=env_manager, firewall_manager=firewall_manager
        )
        primary_connect = PrimaryConnectService(
            registry=registry,
            env_manager=env_manager,
            credentials=credentials,
            vault=vault,
            runner=runner,
            store=store,
        )
        discovery = DiscoveryService(registry=registry, mgmt_client_factory=mgmt_client_factory)
        api_access = ApiAccessService(registry=registry, runner=runner)
        gateway_bootstrap = GatewayBootstrapService(registry=registry, store=store, runner=runner)
        pkg_repo = PackageRepoService(
            registry=registry,
            packages=packages,
            runner=runner,
            vault=vault,
            store=store,
            # Same test-injection knob DiscoveryService uses just above — both
            # protocols just mean "a callable that builds a ManagementAPIClient".
            mgmt_client_factory=cast("RepoClientFactory | None", mgmt_client_factory),
        )

        # Pin SSH host keys beside the DB on the data volume, so pins survive
        # container restarts. Set here rather than threaded through every
        # service that builds a client — see transport/ssh.py.
        known_hosts = cfg.paths.state_dir / "known_hosts"
        set_known_hosts_path(known_hosts)
        logger.info("ssh host-key pinning enabled", known_hosts=str(known_hosts))

        app.state.store = store
        app.state.job_archive_path = str(cfg.paths.job_archive_path)
        app.state.packages = packages
        app.state.credentials = credentials
        app.state.vault = vault
        app.state.registry = registry
        app.state.env_manager = env_manager
        app.state.firewall_manager = firewall_manager
        app.state.runner = runner
        app.state.service = service
        app.state.spark_service = spark_service
        app.state.cdt = cdt_service
        app.state.pkgs_jobs = pkgs_jobs
        app.state.cred_jobs = cred_jobs
        app.state.prov_jobs = prov_jobs
        app.state.primary_connect = primary_connect
        app.state.discovery = discovery
        app.state.api_access = api_access
        app.state.gateway_bootstrap = gateway_bootstrap
        app.state.pkg_repo = pkg_repo

        interrupted = runner.recover()
        if interrupted:
            logger.warning("jobs interrupted by previous shutdown", count=len(interrupted))
        archiver = JobArchiver(store, cfg.paths.job_archive_path)
        serve_task = asyncio.create_task(runner.serve())
        reaper_task = asyncio.create_task(_reap_expired_packages(packages))
        job_archive_task = asyncio.create_task(_reap_old_jobs(archiver))
        bg_tasks = [reaper_task, job_archive_task]
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
        title="Convoy",
        version=__version__,
        summary="Orchestration API for Check Point CDT/CPUSE deployments.",
        lifespan=lifespan,
    )
    # Registered after the auth guard so it runs OUTSIDE it — Starlette
    # applies middleware in reverse order of registration, and the headers
    # must be on every response including the 401s and redirects the auth
    # guard itself returns.
    _register_auth_middleware(app)
    _register_security_headers(app)
    _register_routes(app)
    return app


# Content-Security-Policy for the UI. Strict because it can be: the pages carry
# no inline <script>, no inline style attributes, no inline event handlers and
# no external script/style/font/image sources (the GitHub mark is inline SVG).
# The only external references are ordinary anchor hrefs, which CSP does not
# restrict. Verified against index.html and login.html — if either ever grows an
# inline handler or a CDN reference, THIS is what will break, and the fix is to
# move the code into a .js file rather than to loosen the policy.
_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        # No <object>/<embed>, and no <base> rewriting of relative URLs.
        "object-src 'none'",
        "base-uri 'none'",
        # Only same-origin XHR/fetch/WebSocket.
        "connect-src 'self'",
        # Modern equivalent of X-Frame-Options: DENY (kept below for older UAs).
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _register_security_headers(app: FastAPI) -> None:
    """Set defence-in-depth response headers on every response.

    None of these is the primary control for anything — there are no reachable
    XSS sinks today — but clickjacking was otherwise entirely unmitigated, and
    a CSP is the difference between one future injected string being an
    inconvenience and being a full compromise of a tool that patches firewalls.

    HSTS is set only when the response was actually served over HTTPS: sending
    it over plain HTTP is meaningless, and pinning a host to HTTPS that is not
    yet serving it would lock operators out. Deployments behind a TLS-
    terminating proxy get it via X-Forwarded-Proto.
    """

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        forwarded = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme == "https" or forwarded.split(",")[0].strip() == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


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


def _spark_service(request: Request) -> SparkPatchingService:
    service: SparkPatchingService = request.app.state.spark_service
    return service


def _current_user(request: Request) -> str | None:
    """The logged-in username, or None when auth is off — recorded on every
    submitted job for the Jobs tab's User column/filter."""
    return getattr(request.state, "user", None)


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


def _cred_jobs(request: Request) -> CredentialJobService:
    service: CredentialJobService | None = request.app.state.cred_jobs
    if service is None:
        reason = getattr(request.app.state, "credentials_error", "credential store is locked")
        raise HTTPException(status_code=503, detail=reason)
    return service


def _prov_jobs(request: Request) -> ProvisioningJobService:
    service: ProvisioningJobService = request.app.state.prov_jobs
    return service


def _primary_connect(request: Request) -> PrimaryConnectService:
    service: PrimaryConnectService = request.app.state.primary_connect
    return service


def _api_access(request: Request) -> ApiAccessService:
    service: ApiAccessService = request.app.state.api_access
    return service


def _gateway_bootstrap(request: Request) -> GatewayBootstrapService:
    service: GatewayBootstrapService = request.app.state.gateway_bootstrap
    return service


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
            "job_archive_path": request.app.state.job_archive_path,
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
            # "basic" → the User Settings modal offers a password change; "ldap"
            # → directory-managed, no change-password control.
            "backend": auth.backend,
        }

    @app.post("/api/auth/login")
    async def auth_login(body: LoginIn, request: Request, response: Response) -> dict[str, str]:
        auth = _auth(request)
        if auth is None:
            raise HTTPException(status_code=400, detail="authentication is not configured")
        # Throttled per-username AND per-source-IP; the stricter governs. Without
        # this there is nothing at all between an attacker and unlimited guessing
        # against a tool that can reboot production firewalls. See LoginThrottle.
        throttle = LoginThrottle(request.app.state.store)
        source_ip = request.client.host if request.client else None
        scopes = LoginThrottle.scopes(body.username, source_ip)
        wait = await run_in_threadpool(throttle.retry_after, scopes)
        if wait > 0:
            logger.warning(
                "login throttled",
                username=body.username,
                source_ip=source_ip,
                retry_after=round(wait),
            )
            raise HTTPException(
                status_code=429,
                detail=f"too many failed login attempts — try again in {round(wait)}s",
                headers={"Retry-After": str(max(1, round(wait)))},
            )
        try:
            token, user = await run_in_threadpool(auth.login, body.username, body.password)
        except AuthError as exc:
            await run_in_threadpool(throttle.record_failure, scopes)
            # Deliberately generic — don't disclose which check failed.
            logger.warning(
                "login failed", username=body.username, source_ip=source_ip, reason=str(exc)
            )
            raise HTTPException(
                status_code=401, detail="invalid credentials or insufficient group membership"
            ) from exc
        await run_in_threadpool(throttle.record_success, scopes)
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

    @app.post("/api/auth/password")
    async def auth_change_password(
        body: ChangePasswordIn, request: Request, response: Response
    ) -> dict[str, bool]:
        """Change the basic-auth password (User Settings modal). Requires the
        current password; 400 when auth is off or the backend is LDAP (directory-
        managed, not ours to change).

        A successful change revokes every existing session for the user — the
        reason to change a password is usually that someone else may have the
        old one, and a session token otherwise outlives it. The caller gets a
        fresh session cookie here so the tab they changed it in stays usable;
        every other session has to log in again."""
        auth = _auth(request)
        if auth is None:
            raise HTTPException(status_code=400, detail="authentication is not configured")
        username = _current_user(request)
        assert username is not None  # guarded by the auth middleware
        try:
            await run_in_threadpool(
                auth.change_password, username, body.current_password, body.new_password
            )
            token, _user = await run_in_threadpool(auth.login, username, body.new_password)
        except AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            httponly=True,
            samesite="strict",
            secure=auth.settings.cookie_secure,
            path="/",
        )
        logger.info("basic-auth password changed; other sessions revoked", user=username)
        return {"ok": True}

    # -- environments (create/edit; DB-backed, UI-managed) ----------------------

    def _envmgr(request: Request) -> EnvironmentManager:
        manager: EnvironmentManager = request.app.state.env_manager
        return manager

    @app.get("/api/environments")
    def environments(request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        store: Store = request.app.state.store
        skip_verify_by_default = {
            row.name: row.skip_verify_by_default for row in store.list_environments()
        }
        return [
            {
                "name": env,
                "management_servers": len(service.management_servers(env)),
                "credential_storage_enabled": _registry(request)
                .get(env)
                .credential_storage_enabled,
                "is_mds": _registry(request).get(env).is_mds,
                "api_only": _registry(request).get(env).api_only,
                "skip_verify_by_default": skip_verify_by_default.get(env, False),
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
                "(CONVOY_LDAP_*) before enabling storage for any environment",
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

    @app.post("/api/environments/{env}/access")
    def set_environment_access(
        env: str, body: EnvironmentAccessIn, request: Request
    ) -> dict[str, Any]:
        """Declare an environment SSH-reachable or API-only — decides whether
        SSH to its management servers is allowed at all (see
        HostConnector.api_only). Orthogonal to is_mds."""
        try:
            _envmgr(request).set_environment_access(env, body.api_only)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"api_only": body.api_only}

    @app.post("/api/environments/{env}/skip-verify-default")
    def set_skip_verify_default(
        env: str, body: SkipVerifyDefaultIn, request: Request
    ) -> dict[str, Any]:
        """Set whether the Management tab's "skip verify" install checkbox is
        pre-checked by default in this environment — some environments
        chronically fail `installer verify` for reasons unrelated to the
        install itself. Purely a UI default; never skips verify on its own."""
        try:
            _envmgr(request).set_skip_verify_default(env, body.skip_verify_by_default)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"skip_verify_by_default": body.skip_verify_by_default}

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

    @app.post("/api/environments/{env}/servers")
    def add_env_server(env: str, body: EnvServerIn, request: Request) -> JobRecord:
        """Executes immediately as a tracked prov.add/prov.edit job
        (services/prov_ops.py) — same model as credentials/packages. Validation
        errors (bad role, name collision with a firewall, ...) surface as a
        failed job, not a synchronous 400/409."""
        _require_env(request, env)
        try:
            return _prov_jobs(request).submit_put_server(
                env,
                name=body.name,
                address=body.address,
                role=body.role,
                ssh_user=body.ssh_user,
                ssh_port=body.ssh_port,
                notes=body.notes,
                credential_set=(
                    body.credential_set if "credential_set" in body.model_fields_set else UNSET
                ),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/environments/{env}/servers/{name}")
    def remove_env_server(env: str, name: str, request: Request) -> JobRecord:
        """Executes immediately as a tracked prov.delete job — see
        add_env_server above."""
        _require_env(request, env)
        try:
            return _prov_jobs(request).submit_delete_server(
                env, name, triggered_by=_current_user(request)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

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

    # -- firewalls (environment-scoped; CRUD + discovery) ------------------------

    def _fwmgr(request: Request) -> FirewallManager:
        manager: FirewallManager = request.app.state.firewall_manager
        return manager

    @app.get("/api/environments/{env}/firewalls")
    def env_firewalls(env: str, request: Request) -> list[dict[str, Any]]:
        """Full editable firewall list for the environment editor."""
        try:
            return [
                {
                    "name": h.name,
                    "address": h.address,
                    "role": h.role,
                    "ssh_user": h.ssh_user,
                    "ssh_port": h.ssh_port,
                    "tags": h.tags,
                }
                for h in _fwmgr(request).list_firewalls(env)
            ]
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/environments/{env}/firewalls")
    def add_firewall(env: str, body: FirewallIn, request: Request) -> JobRecord:
        """Executes immediately as a tracked prov.add/prov.edit job — see
        add_env_server above."""
        _require_env(request, env)
        try:
            return _prov_jobs(request).submit_put_firewall(
                env,
                name=body.name,
                address=body.address,
                role=body.role,
                ssh_user=body.ssh_user,
                ssh_port=body.ssh_port,
                notes=body.notes,
                credential_set=(
                    body.credential_set if "credential_set" in body.model_fields_set else UNSET
                ),
                cluster_name=body.cluster_name,
                mds_domain=body.mds_domain,
                tags=body.tags,
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/environments/{env}/firewalls/{name}")
    def remove_firewall(env: str, name: str, request: Request) -> JobRecord:
        """Executes immediately as a tracked prov.delete job — see
        add_env_server above."""
        _require_env(request, env)
        try:
            return _prov_jobs(request).submit_delete_firewall(
                env, name, triggered_by=_current_user(request)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/environments/{env}/discover-firewalls")
    def discover_firewalls(env: str, body: DiscoverFirewallsIn, request: Request) -> dict[str, Any]:
        """Scan the estate from the environment's primary management server and
        return candidate firewalls (gateways/cluster members) for the operator
        to review and import. Read-only: nothing is added here — the UI posts
        confirmed rows back to the add-firewall endpoint."""
        discovery: DiscoveryService = request.app.state.discovery
        try:
            result = discovery.discover_firewalls(env, domain=body.domain)
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
                    "cluster_name": s.cluster_name,
                    # The Domain/CMA this whole scan ran against (None on SMS) —
                    # uniform across every row in one discover-firewalls call, so
                    # it's threaded straight from the request rather than tracked
                    # per-server. Rides into the import payload as FirewallIn.mds_domain.
                    "mds_domain": body.domain,
                }
                for s in result.servers
            ],
            "warnings": result.warnings,
        }

    @app.get("/api/environments/{env}/domains")
    def env_domains(env: str, request: Request) -> dict[str, Any]:
        """Enumerate Domains (CMAs) on the environment's primary MDS, for the
        discover-firewalls modal's domain picker. SMS environments never call
        this — the picker is hidden client-side."""
        discovery: DiscoveryService = request.app.state.discovery
        try:
            result = discovery.list_domains(env)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"domains": result.domains, "warnings": result.warnings}

    # -- service-account provisioning (pure rendering; nothing stored) ---------

    @app.post("/api/provision")
    def provision(body: ProvisionRequest) -> dict[str, list[str]]:
        try:
            commands = render_gaia_user_commands(body.username, body.password)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"commands": commands, "notes": PROVISIONING_NOTES}

    # -- connect to primary (SSH-executed Management API provisioning) --------

    @app.get("/api/environments/{env}/connect-primary/preview")
    def connect_primary_preview(env: str, username: str, request: Request) -> dict[str, Any]:
        """Renders the full "assume-fresh" Management API command sequence for
        the operator to review before Connect to Primary actually runs it over
        SSH (see PrimaryConnectService) — no SSH involved here."""
        _require_env(request, env)
        is_mds = _registry(request).get(env).is_mds
        try:
            commands = render_mgmt_api_commands(username, is_mds=is_mds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        notes = [*MGMT_API_NOTES, MDS_API_NOTE] if is_mds else MGMT_API_NOTES
        return {"commands": commands, "notes": notes}

    @app.post("/api/environments/{env}/connect-primary", status_code=202)
    def connect_primary(env: str, body: ConnectPrimaryIn, request: Request) -> JobRecord:
        _require_env(request, env)
        is_mds = _registry(request).get(env).is_mds
        try:
            return _primary_connect(request).submit_connect_primary(
                env,
                name=body.name,
                address=body.address,
                role=body.role,
                ssh_user=body.ssh_user,
                ssh_port=body.ssh_port,
                credential_set=body.credential_set,
                is_mds=is_mds,
                confirm_address_change=body.confirm_address_change,
                credentials=_build_credentials(body.credentials, body.name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/jobs/{job_id}/reveal-api-key")
    def reveal_api_key(job_id: str, request: Request) -> dict[str, str | None]:
        """Pop-once read of a connect-primary job's captured API key — returns
        null on a second call, an unknown job id, a job that isn't a
        connect-primary job, or one submitted by a different operator. Never
        logged; see PrimaryConnectService.

        POST rather than GET: this both returns a secret and CONSUMES it, so it
        is a state change, and it must never be reachable by anything that
        follows or prefetches links."""
        return {
            "api_key": _primary_connect(request).reveal_api_key(
                job_id, requested_by=_current_user(request)
            )
        }

    # -- Management API accessibility diagnose/repair (SSH) --------------------
    # Proactive follow-up to Connect to Primary above: the UI calls diagnose
    # right after a connect-primary job succeeds, so a Management API that's
    # unreachable (e.g. accessibility scoped to require-local) surfaces right
    # where it was just provisioned, instead of showing up later as a
    # confusing 403 during estate discovery.

    @app.post("/api/environments/{env}/api-access/diagnose")
    def diagnose_api_access(env: str, request: Request) -> dict[str, Any]:
        """Runs `api status` on the environment's primary over SSH to tell
        "API not enabled" apart from "accessibility restricted to
        localhost" — the two common causes of a 403 from the Management API.
        Never itself raises an OrchestratorError: any failure (no SSH
        credential, unreachable host, bad command) comes back as ``error``
        for the UI to show inline."""
        # Every sibling route has this; without it an unknown environment
        # returned 200 with a diagnosis of nothing instead of 404.
        _require_env(request, env)
        diag = _api_access(request).diagnose(env)
        # raw_output is deliberately NOT returned: it is unparsed remote command
        # output that nothing in the UI reads, so it was pure extra surface for
        # anything sensitive `api status` might print. It stays available
        # server-side on the diagnosis object.
        return {
            "overall_started": diag.overall_started,
            "restricted_to_local": diag.restricted_to_local,
            "error": diag.error,
        }

    @app.get("/api/environments/{env}/api-access/repair-preview")
    def api_access_repair_preview(env: str, request: Request) -> dict[str, Any]:
        """Renders the exact mgmt_cli sequence the repair job below runs over
        SSH, so the operator can review it before confirming — same pattern
        as connect-primary/preview."""
        try:
            commands = _api_access(request).preview_repair_commands(env)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"commands": commands}

    @app.post("/api/environments/{env}/api-access/repair", status_code=202)
    def repair_api_access(env: str, body: ConfirmRequest, request: Request) -> JobRecord:
        """Widens the primary's Management API accessibility off
        `require-local` over SSH (see services/api_access.py) and restarts
        the API server for the change to take effect.

        Confirm-gated: the restart briefly interrupts every other Management
        API session against that server, which the UI's own help text warns
        about — so it should not be reachable by a bare POST."""
        _require_env(request, env)
        if not body.confirmed:
            raise HTTPException(
                status_code=400,
                detail=(
                    "repairing API access requires explicit confirmation — it widens "
                    "Management API accessibility and restarts the API server, briefly "
                    "interrupting other sessions"
                ),
            )
        try:
            return _api_access(request).submit_repair(env, triggered_by=_current_user(request))
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

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
                        "installed": cached.installed if cached else [],
                        "cluster_role": cached.cluster_role if cached else None,
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
            "installed": cached.installed,
            "cluster_role": cached.cluster_role,
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
                env,
                name,
                body.package,
                force_low_space=body.force_low_space,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
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
                triggered_by=_current_user(request),
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
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/servers/{name}/uninstall", status_code=202)
    def server_uninstall(
        env: str, name: str, body: UninstallRequest, request: Request
    ) -> JobRecord:
        try:
            return _service(request).submit_uninstall(
                env,
                name,
                body.package_id,
                confirmed=body.confirmed,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- firewalls (patching view; same CPUSE mechanics as servers) --------------
    # These are thin wrappers around the exact same PatchingService methods used
    # above — CPUSE import/install doesn't care whether the target is a
    # management server or a firewall (see HostConnector.patchable_host).
    # Separate URLs purely so the UI/Jobs semantics read as "distinct from
    # management," matching the Firewalls panel.

    @app.get("/api/env/{env}/firewalls")
    def firewalls(env: str, request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        store: Store = request.app.state.store
        try:
            result = []
            for h in service.firewalls(env):
                cached = store.get_server_state(env, h.name)
                # cluster_name is on the firewall record itself (real
                # SmartConsole name, set at discovery time or via "re-check
                # cluster membership"), not the live-refreshed state cache —
                # see clusterxl-live-state / store schema v19.
                fw_row = store.get_firewall(env, h.name)
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
                        "installed": cached.installed if cached else [],
                        "cluster_role": cached.cluster_role if cached else None,
                        "cluster_name": fw_row.cluster_name if fw_row else None,
                        "mds_domain": fw_row.mds_domain if fw_row else None,
                        "tags": fw_row.tags if fw_row else [],
                    }
                )
            return result
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/state")
    async def firewall_state(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> dict[str, Any]:
        creds = _op_creds(body, name, env)
        service = _service(request)
        try:
            # Spark (Gaia Embedded) has no CPUSE agent, so its refresh skips
            # PatchingService.detect() entirely (show installer .../show
            # cluster state) in favor of SparkPatchingService.detect()'s
            # plain `fw ver` — see spark_patching.py's module docstring.
            # Both persist into the same ServerStateRow cache, so the
            # response below reads from there either way.
            if service.host_role(env, name) == "spark_firewall":
                await asyncio.to_thread(
                    _spark_service(request).detect, env, name, credentials=creds
                )
                agent_build: str | None = None
                packages: list[dict[str, Any]] = []
            else:
                detected = await asyncio.to_thread(service.detect, env, name, credentials=creds)
                agent_build = detected.agent_build
                packages = [
                    {
                        "identifier": p.identifier,
                        "status": p.status,
                        "description": p.description,
                        "is_installed": p.is_installed,
                        "is_imported": p.is_imported,
                    }
                    for p in detected.packages
                ]
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        store: Store = request.app.state.store
        cached = store.get_server_state(env, name)
        assert cached is not None  # detect() just persisted it
        fw_row = store.get_firewall(env, name)
        return {
            "host": name,
            "agent_build": agent_build,
            "version": cached.version,
            "jhf": cached.jhf,
            "checked_at": cached.checked_at.isoformat(),
            "installable": cached.installable,
            "installed": cached.installed,
            "cluster_role": cached.cluster_role,
            "cluster_name": fw_row.cluster_name if fw_row else None,
            "mds_domain": fw_row.mds_domain if fw_row else None,
            "tags": fw_row.tags if fw_row else [],
            "packages": packages,
        }

    @app.post("/api/env/{env}/firewalls/{name}/cluster-recheck")
    async def firewall_cluster_recheck(env: str, name: str, request: Request) -> dict[str, Any]:
        """Re-resolve a firewall's real cluster object name via the
        Management API only — the Firewalls panel's edit-modal "Re-check
        cluster membership" button, for firewalls that weren't auto-resolved
        at discovery time (manually added, or added before this shipped).
        Never falls back to SSH: Check Point doesn't expose the SmartConsole
        cluster object's own name over the CLI on the member itself (see
        clusterxl.py), so no live command can ever answer this. On a Multi-
        Domain environment, the lookup logs into the firewall's stored
        ``mds_domain`` (set at discovery-import time, or by hand from the
        edit modal's Domain dropdown) — without one, the Management API has
        no Domain to log into and this always resolves nothing. If the API
        can't resolve one (no primary configured, no usable credentials,
        older management version, or no domain tracked for this firewall),
        the previously stored name is left untouched — operators can set it
        by hand via the edit modal's manual field instead."""
        discovery: DiscoveryService = request.app.state.discovery
        store: Store = request.app.state.store
        fw_row = store.get_firewall(env, name)
        domain = fw_row.mds_domain if fw_row else None
        cluster_name = await asyncio.to_thread(
            discovery.find_cluster_name, env, name, domain=domain
        )
        if cluster_name is not None:
            try:
                _fwmgr(request).set_cluster_name(env, name, cluster_name)
            except OrchestratorError as exc:
                raise _map_error(exc) from exc
            return {"cluster_name": cluster_name, "resolved": True}
        return {"cluster_name": fw_row.cluster_name if fw_row else None, "resolved": False}

    @app.post("/api/environments/{env}/hosts/{name}/accept-host-key")
    def accept_host_key(
        env: str, name: str, body: AcceptHostKeyRequest, request: Request
    ) -> dict[str, Any]:
        """Drop a host's pinned SSH key so the next connection re-pins whatever
        it presents (see transport/ssh.py).

        This is the recovery path for a legitimate rebuild/upgrade, which
        changes a Gaia host's key and makes every job for it fail closed with
        a "host key changed" error. It is deliberately confirm-gated and
        deliberately narrow — one host, and the operator has to say so — since
        the same symptom is what an on-path interception looks like. Works for
        management servers and firewalls alike; the host only has to exist in
        this environment's inventory."""
        _require_env(request, env)
        if not body.confirmed:
            raise HTTPException(
                status_code=400,
                detail=(
                    "accepting a changed host key requires explicit confirmation — a "
                    "changed key is also what an intercepted connection looks like"
                ),
            )
        try:
            host = _registry(request).get(env).inventory.host(name)
            removed = forget_host_key(host)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        logger.warning(
            "operator cleared a pinned SSH host key",
            environment=env,
            host=name,
            address=host.address,
            had_pin=removed,
            user=_current_user(request),
        )
        return {"host": name, "address": host.address, "cleared": removed}

    @app.get("/api/env/{env}/firewalls/{name}/bootstrap-credentials/preview")
    def firewall_bootstrap_credentials_preview(
        env: str, name: str, request: Request
    ) -> dict[str, Any]:
        """Renders the exact clish commands a bootstrap run would push via
        the Management API, so the operator can review them before
        confirming — same pattern as api-access/repair-preview. The
        Firewalls panel's "Bootstrap Credentials" link (shown after an SSH
        auth failure during status refresh) opens this preview first. Spark
        firewalls use the separate, display-only preview below instead."""
        try:
            commands = _gateway_bootstrap(request).preview_bootstrap_commands(env, name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"commands": commands}

    @app.post("/api/env/{env}/firewalls/{name}/bootstrap-credentials", status_code=202)
    def firewall_bootstrap_credentials(
        env: str, name: str, body: ConfirmRequest, request: Request
    ) -> JobRecord:
        """Pushes the firewall's assigned credential set onto the gateway via
        the Management API's run-script (see services/gateway_bootstrap.py) —
        the "Bootstrap Credentials" link's Run button, after the operator has
        reviewed the preview above. Rejects Spark firewalls (no automated
        push there — see the Spark bootstrap preview route).

        Confirm-gated: this rewrites a live gateway's local admin account
        (uid 0, adminRole) over SIC."""
        if not body.confirmed:
            raise HTTPException(
                status_code=400,
                detail=(
                    "bootstrapping credentials requires explicit confirmation — it "
                    "rewrites this gateway's local admin account"
                ),
            )
        try:
            return _gateway_bootstrap(request).submit_bootstrap(
                env, name, triggered_by=_current_user(request)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.get("/api/env/{env}/firewalls/{name}/spark-bootstrap-admin/preview")
    def firewall_spark_bootstrap_admin_preview(
        env: str, name: str, request: Request
    ) -> dict[str, Any]:
        """Renders the Quantum Spark (SMB) `add administrator` clish command
        for name's assigned credential set — display-only, for the operator
        to paste into the device's own clish shell (no automated push; see
        services/gateway_bootstrap.py's module docstring for why). The
        Firewalls panel shows this instead of the "Bootstrap Credentials"
        link for Spark firewalls after an SSH auth failure during status
        refresh."""
        try:
            commands = _gateway_bootstrap(request).preview_spark_admin_commands(env, name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"commands": commands}

    @app.post("/api/env/{env}/firewalls/{name}/mds-domain")
    def firewall_set_mds_domain(
        env: str, name: str, body: FirewallDomainRequest, request: Request
    ) -> dict[str, Any]:
        """Manually set (or clear, with ``null``) the MDS Domain/CMA a
        firewall lives in — the Firewalls panel edit modal's Domain dropdown,
        for MDS environments only. Deliberate, separate action from the
        generic firewall edit save, matching cluster-name's manual field:
        ordinary edits never touch this field (see FirewallManager.set_domain)."""
        try:
            _fwmgr(request).set_domain(env, name, body.mds_domain)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"mds_domain": body.mds_domain}

    @app.post("/api/env/{env}/firewalls/{name}/cluster-name")
    def firewall_set_cluster_name(
        env: str, name: str, body: ClusterNameRequest, request: Request
    ) -> dict[str, Any]:
        """Manually set (or clear, with ``null``) a firewall's cluster object
        name — the fallback for when Management API re-check can't resolve
        one. A deliberate, separate action from the generic firewall edit
        save, matching "re-check": ordinary edits never touch this field
        (see set_cluster_name)."""
        try:
            _fwmgr(request).set_cluster_name(env, name, body.cluster_name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"cluster_name": body.cluster_name}

    @app.post("/api/env/{env}/firewalls/{name}/import", status_code=202)
    def firewall_import(env: str, name: str, body: ImportRequest, request: Request) -> JobRecord:
        try:
            return _service(request).submit_import(
                env,
                name,
                body.package,
                force_low_space=body.force_low_space,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/import-cloud", status_code=202)
    def firewall_import_cloud(
        env: str, name: str, body: ImportCloudRequest, request: Request
    ) -> JobRecord:
        try:
            return _service(request).submit_import_cloud(
                env,
                name,
                body.package_id,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/install", status_code=202)
    def firewall_install(env: str, name: str, body: InstallRequest, request: Request) -> JobRecord:
        """Shared by CPUSE-patched firewalls and Spark ones — the row-level
        Install button and package picker are the same widget for both (see
        app.js renderInstallSelect); this just dispatches on host role, same
        as the /state endpoint above. Spark ignores verify_first — Gaia
        Embedded has no `installer verify` step."""
        service = _service(request)
        try:
            if service.host_role(env, name) == "spark_firewall":
                return _spark_service(request).submit_install(
                    env,
                    name,
                    body.package_id,
                    confirmed=body.confirmed,
                    credentials=_build_credentials(body.credentials, name, env),
                    triggered_by=_current_user(request),
                )
            return service.submit_install(
                env,
                name,
                body.package_id,
                confirmed=body.confirmed,
                verify_first=body.verify_first,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/uninstall", status_code=202)
    def firewall_uninstall(
        env: str, name: str, body: UninstallRequest, request: Request
    ) -> JobRecord:
        try:
            return _service(request).submit_uninstall(
                env,
                name,
                body.package_id,
                confirmed=body.confirmed,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/spark-test-credentials", status_code=202)
    def firewall_spark_test_credentials(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> JobRecord:
        """SSH login + `expert`-mode escalation, nothing more — the Firewalls
        panel's "Test Credentials" link for a Spark row. Never touches device
        state, so no confirmation is required, unlike spark-import below."""
        try:
            return _spark_service(request).submit_test_credentials(
                env,
                name,
                credentials=_op_creds(body, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/spark-import", status_code=202)
    def firewall_spark_import(
        env: str, name: str, body: SparkImportRequest, request: Request
    ) -> JobRecord:
        """SCPs a `.img` firmware image to a Spark firewall's /storage and
        nothing else — see services/spark_patching.py. Doesn't reboot
        anything, so no confirmation is required; running the actual upgrade
        against the staged file is a separate, confirmed /install call (the
        same row-level Install button CPUSE-patched firewalls use)."""
        try:
            return _spark_service(request).submit_transfer(
                env,
                name,
                body.package,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/firewalls/{name}/credential")
    def assign_firewall_credential(
        env: str, name: str, body: CredentialAssignmentIn, request: Request
    ) -> dict[str, str | None]:
        """Assign a credential set (by name) to a firewall, or clear it."""
        try:
            _fwmgr(request).assign_credential(env, name, body.set)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"credential_set": body.set}

    # -- packages ------------------------------------------------------------
    # Upload/keep/unkeep/delete execute immediately (see services/pkgs_ops.py)
    # but each still returns a (already-terminal) JobRecord rather than the
    # mutated PackageRecord, so a pkgs.* row still lands on the Jobs tab for
    # audit history.

    def _pkgs_jobs(request: Request) -> PackageJobService:
        service: PackageJobService = request.app.state.pkgs_jobs
        return service

    @app.get("/api/packages")
    def list_packages(request: Request) -> list[PackageRecord]:
        packages: PackageStore = request.app.state.packages
        return packages.list()

    @app.post("/api/packages")
    async def upload_package(file: UploadFile, request: Request) -> JobRecord:
        packages: PackageStore = request.app.state.packages
        if not file.filename:
            raise HTTPException(status_code=400, detail="upload is missing a filename")
        # Validate the NAME before writing a single byte. This used to run only
        # inside submit_upload -> add_stream, i.e. after the whole body had been
        # spooled by Starlette AND copied again to the staging path — so a
        # rejected filename still cost two full writes of a GB-scale file.
        try:
            check_filename(file.filename)
        except PackageError as exc:
            raise _map_error(exc) from exc

        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid Content-Length") from None
            if declared_size > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"upload is {declared_size} bytes, over the {MAX_UPLOAD_BYTES}-byte limit"
                    ),
                )
            # /data also holds the SQLite DB (jobs, sessions, encrypted
            # credentials) and the job archive, so filling it does not merely
            # fail the upload — it starts failing session and job writes too.
            free = shutil.disk_usage(packages.directory).free
            if declared_size + _UPLOAD_FREE_SPACE_MARGIN > free:
                raise HTTPException(
                    status_code=507,
                    detail=(
                        f"not enough free space to accept this upload: {declared_size} bytes "
                        f"incoming, {free} bytes free on the package volume"
                    ),
                )
        # Stage to a stable path inside the package directory first — the
        # upload's bytes only exist for the lifetime of this request (Starlette
        # tears down its spooled temp file once the response is sent), so the
        # actual work (packages.add_stream: hash, dedupe, move into place) —
        # done synchronously in submit_upload, see services/pkgs_ops.py — reads
        # from this copy instead. Cleaned up here if anything goes wrong before
        # submit_upload takes ownership of it; that call cleans it up itself
        # once it does.
        staged_path = packages.directory / f".upload-{uuid.uuid4().hex}"

        def _stage() -> None:
            # Content-Length is whatever the client claimed, so the cap is
            # enforced again against the bytes actually arriving.
            written = 0
            with staged_path.open("wb") as out:
                while chunk := file.file.read(_UPLOAD_CHUNK):
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise PackageError(f"upload exceeded the {MAX_UPLOAD_BYTES}-byte limit")
                    out.write(chunk)

        try:
            await asyncio.to_thread(_stage)
            # submit_upload does real (blocking) disk I/O — off the event loop.
            return await asyncio.to_thread(
                _pkgs_jobs(request).submit_upload,
                file.filename,
                staged_path,
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            staged_path.unlink(missing_ok=True)
            raise _map_error(exc) from exc
        except Exception:
            staged_path.unlink(missing_ok=True)
            raise

    @app.post("/api/packages/{filename}/retention")
    def set_package_retention(filename: str, body: RetentionRequest, request: Request) -> JobRecord:
        """Pin a package to keep it indefinitely, or un-pin it so the retention
        window applies again — executes immediately as a tracked
        pkgs.keep/pkgs.notkeep job."""
        try:
            return _pkgs_jobs(request).submit_retention(
                filename, body.pinned, triggered_by=_current_user(request)
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/packages/{filename}")
    def delete_package(filename: str, request: Request) -> JobRecord:
        """Executes immediately as a tracked pkgs.delete job."""
        try:
            return _pkgs_jobs(request).submit_delete(filename, triggered_by=_current_user(request))
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    def _pkg_repo(request: Request) -> PackageRepoService:
        service: PackageRepoService = request.app.state.pkg_repo
        return service

    @app.post("/api/env/{env}/packages/{filename}/push-to-repo", status_code=202)
    def push_package_to_repo(
        env: str, filename: str, request: Request, body: PushToRepoRequest | None = None
    ) -> JobRecord:
        """Push a stored package onto the environment's primary management
        server and register it in the SmartConsole Package Repository (see
        services/pkg_repo_ops.py) — genuinely slow (file transfer + a
        server-side import), so unlike the rest of this section this runs as
        a real background job, not immediately."""
        try:
            return _pkg_repo(request).submit_push_to_repo(
                env,
                filename,
                credentials=_op_creds(body, env, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- credential sets (named login objects; environment-scoped) --------------

    @app.get("/api/env/{env}/credentials")
    def list_credential_sets(env: str, request: Request) -> list[CredentialSetInfo]:
        _require_env(request, env)
        return _credentials_or_503(request).list_sets(env)

    @app.put("/api/env/{env}/credentials")
    def put_credential_set(env: str, body: CredentialSetIn, request: Request) -> JobRecord:
        """Executes immediately (services/cred_ops.py) — unlike CPUSE/CDT/pkgs/prov
        jobs, this never queues. Still recorded as a cred.add/cred.edit JobRecord,
        already terminal by the time it's returned, for Jobs-tab visibility and
        audit history. The plaintext secrets never reach JobRecord.params
        (persisted as plain JSON)."""
        _require_env(request, env)
        if request.app.state.auth is None:
            raise HTTPException(
                status_code=409,
                detail="credential storage requires authentication — configure LDAP "
                "(CONVOY_LDAP_*) before storing credentials",
            )
        if not _registry(request).get(env).credential_storage_enabled:
            raise HTTPException(
                status_code=409,
                detail=f"credential storage is disabled for environment {env!r} — "
                "enable it first, or supply credentials per operation",
            )

        def _reveal(value: SecretStr | None) -> str | None:
            return value.get_secret_value() if value is not None else None

        try:
            return _cred_jobs(request).submit_put(
                env,
                name=body.name,
                ssh_username=body.ssh_username,
                ssh_password=_reveal(body.ssh_password),
                ssh_private_key=_reveal(body.ssh_private_key),
                expert_password=_reveal(body.expert_password),
                api_key=_reveal(body.api_key),
                default_if_none=body.default_if_none,
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/credentials/{name}/default")
    def set_default_credential_set(env: str, name: str, request: Request) -> dict[str, str | None]:
        """Make a credential set the environment's default (assigned to new servers).
        Not job-tracked — a lightweight pointer flip, not an add/edit/delete."""
        _require_env(request, env)
        store = _credentials_or_503(request)
        if not store.set_default(env, name):
            raise HTTPException(status_code=404, detail=f"credential set {name!r} not found")
        return {"default": name}

    @app.delete("/api/env/{env}/credentials/{name}")
    def delete_credential_set(env: str, name: str, request: Request) -> JobRecord:
        """Executes immediately as a tracked cred.delete job — see
        put_credential_set above."""
        _require_env(request, env)
        try:
            return _cred_jobs(request).submit_delete(env, name, triggered_by=_current_user(request))
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

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
                env,
                name,
                body.package,
                credentials=_build_credentials(body.credentials, name, env),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/cdt/{name}/generate", status_code=202)
    def cdt_generate(
        env: str, name: str, request: Request, body: GenerateRequest | None = None
    ) -> JobRecord:
        try:
            return _cdt(request).submit_generate(
                env,
                name,
                credentials=_op_creds(body, name, env),
                triggered_by=_current_user(request),
            )
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
                triggered_by=_current_user(request),
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
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- jobs ------------------------------------------------------------------

    @app.get("/api/jobs")
    def list_jobs(
        request: Request,
        limit: int = 10,
        kind: Annotated[list[str] | None, Query()] = None,
        target: Annotated[list[str] | None, Query()] = None,
        environment: Annotated[list[str] | None, Query()] = None,
        status: Annotated[list[str] | None, Query()] = None,
        user: Annotated[list[str] | None, Query()] = None,
    ) -> list[JobRecord]:
        """``limit <= 0`` means "as many as allowed" — capped at
        ``MAX_JOBS_PAGE``, not unbounded: each record can carry up to 2 MB of
        captured install log, so an uncapped listing over a year of retained
        jobs is a large response to build and serialise on demand, repeatedly.
        kind/target/environment/status/user each accept repeated query params
        (``?status=failed&status=succeeded``) and filter as OR within a field,
        AND across fields — powers the Jobs tab's multiselect filters. Options
        come from ``/api/jobs/facets``, not this endpoint."""
        store: Store = request.app.state.store
        limit = MAX_JOBS_PAGE if limit <= 0 else min(limit, MAX_JOBS_PAGE)
        statuses: list[JobStatus] | None = None
        if status:
            try:
                statuses = [JobStatus(s) for s in status]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"invalid status: {exc}") from exc
        return store.list_jobs(
            limit=limit,
            kinds=kind,
            targets=target,
            environments=environment,
            statuses=statuses,
            usernames=user,
        )

    @app.get("/api/jobs/facets")
    def job_facets(request: Request) -> dict[str, list[str]]:
        """Distinct kind/target/environment/status/username values across
        *every* job, not just the currently displayed page — the Jobs tab's
        filter dropdowns must offer every real option regardless of display
        limit."""
        store: Store = request.app.state.store
        return store.list_job_facets()

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

    @app.post("/api/jobs/{job_id}/retry-import-with-override")
    async def retry_import_with_override(
        job_id: str, body: OperationCredentials, request: Request
    ) -> JobRecord:
        """ "Retry with override" for an import job that failed on an
        override-eligible disk-space shortfall (Jobs tab). Submits a NEW
        import for the same host/package with force_low_space set; the failed
        job stays as the record of why. Rejected unless that job really did
        fail that way — and the job's own check still refuses anything below
        1.5x the package size regardless."""
        store: Store = request.app.state.store
        try:
            job = store.get_job(job_id)
        except StoreError as exc:
            raise _map_error(exc) from exc
        try:
            return await asyncio.to_thread(
                _service(request).retry_import_with_override,
                job_id,
                credentials=_build_credentials(body.credentials, job.target or "", job.environment),
                triggered_by=_current_user(request),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/jobs/{job_id}/recheck-import")
    async def recheck_import(
        job_id: str, body: OperationCredentials, request: Request
    ) -> JobRecord:
        """Manual "Check status" recheck for a TIMED_OUT import job (Jobs
        tab). The job record itself carries the environment/host to recheck
        against — the operator only needs to (optionally) supply credentials
        for a storage-disabled environment."""
        store: Store = request.app.state.store
        try:
            job = store.get_job(job_id)
        except StoreError as exc:
            raise _map_error(exc) from exc
        try:
            return await asyncio.to_thread(
                _service(request).recheck_import,
                job_id,
                credentials=_build_credentials(body.credentials, job.target or "", job.environment),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- static UI (mounted last so /api and /health win) -----------------------
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")


app = create_app()
