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

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from .. import __version__
from ..cdt import CandidatesFile
from ..config import Config
from ..credentials import (
    Credential,
    CredentialBundle,
    CredentialInfo,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
    load_master_key,
)
from ..errors import (
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
from ..services.environments import EnvironmentManager
from ..services.patching import PatchingService
from ..services.provisioning import (
    DEFAULT_UID,
    PROVISIONING_NOTES,
    render_gaia_user_commands,
)
from ..store import JobEvent, JobRecord, PackageRecord, Store

logger = get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

# How often the background reaper sweeps for expired packages.
_REAP_INTERVAL_SECONDS = 3600.0


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


# -- request/response bodies -------------------------------------------------------


class CredentialIn(BaseModel):
    host: str
    kind: CredentialKind
    username: str | None = None
    secret: str = Field(min_length=1)


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


class ProvisionRequest(BaseModel):
    username: str
    password: str = Field(min_length=1)  # only hashed, never stored or echoed
    uid: int = DEFAULT_UID


class EnvironmentIn(BaseModel):
    name: str


class EnvServerIn(BaseModel):
    name: str
    address: str
    role: str = "management"  # management | mds
    ssh_user: str = "admin"
    ssh_port: int = 22
    notes: str | None = None


# -- app factory -------------------------------------------------------------------


def create_app(
    config: Config | None = None, *, client_factory: ClientFactory | None = None
) -> FastAPI:
    """Build the app. Tests pass a custom ``config`` (tmp paths) and a fake
    ``client_factory``; production uses defaults resolved at startup."""

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

        # Independent management environments — DB-backed and UI-editable. Seeded
        # once from config/inventory files, then the DB is authoritative (see
        # services/environments.py and .claude/memory/patching-web-design.md).
        registry = EnvironmentRegistry()
        env_manager = EnvironmentManager(store, registry, credentials, client_factory)
        env_manager.seed_from_config(cfg)
        env_manager.rebuild()

        # Purge a job's in-memory credentials the moment it reaches any terminal
        # state (success/failure/cancel), guaranteed by the runner.
        runner = JobRunner(store, on_job_finished=vault.discard)
        service = PatchingService(registry=registry, packages=packages, runner=runner, vault=vault)
        cdt_service = CDTService(registry=registry, packages=packages, runner=runner, vault=vault)

        app.state.store = store
        app.state.packages = packages
        app.state.credentials = credentials
        app.state.vault = vault
        app.state.registry = registry
        app.state.env_manager = env_manager
        app.state.runner = runner
        app.state.service = service
        app.state.cdt = cdt_service

        interrupted = runner.recover()
        if interrupted:
            logger.warning("jobs interrupted by previous shutdown", count=len(interrupted))
        serve_task = asyncio.create_task(runner.serve())
        reaper_task = asyncio.create_task(_reap_expired_packages(packages))
        try:
            yield
        finally:
            runner.stop()
            reaper_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper_task
            await serve_task

    app = FastAPI(
        title="chkp-cpuse-orch",
        version=__version__,
        summary="Orchestration API for Check Point CDT/CPUSE deployments.",
        lifespan=lifespan,
    )
    _register_routes(app)
    return app


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
            "environments": _registry(request).names(),
            "management_servers": sum(
                len(service.management_servers(env)) for env in _registry(request).names()
            ),
            "packages": len(request.app.state.packages.list()),
        }

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
            }
            for env in _registry(request).names()
        ]

    @app.post("/api/environments", status_code=201)
    def create_environment(body: EnvironmentIn, request: Request) -> dict[str, str]:
        try:
            name = _envmgr(request).create_environment(body.name)
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
        try:
            purged = _envmgr(request).set_credential_storage(env, body.enabled)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"enabled": body.enabled, "purged_credentials": purged}

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

    # -- service-account provisioning (pure rendering; nothing stored) ---------

    @app.post("/api/provision")
    def provision(body: ProvisionRequest) -> dict[str, list[str]]:
        try:
            commands = render_gaia_user_commands(body.username, body.password, uid=body.uid)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"commands": commands, "notes": PROVISIONING_NOTES}

    # -- servers (environment-scoped) ------------------------------------------

    @app.get("/api/env/{env}/servers")
    def servers(env: str, request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        try:
            return [
                {
                    "name": h.name,
                    "address": h.address,
                    "role": h.role.value,
                    "ssh_user": h.ssh_user,
                    "credentials": service.credential_kinds(env, h.name),
                }
                for h in service.management_servers(env)
            ]
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/env/{env}/servers/{name}/state")
    async def server_state(
        env: str, name: str, request: Request, body: QueryRequest | None = None
    ) -> dict[str, Any]:
        """Live CPUSE state (POST so storage-disabled environments can carry
        one-shot credentials in the body; the body is empty otherwise)."""
        creds = _op_creds(body, name, env)
        service = _service(request)
        try:
            detected = await asyncio.to_thread(service.detect, env, name, credentials=creds)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {
            "host": detected.host,
            "agent_build": detected.agent_build,
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

    # -- credentials (environment-scoped; never echo secrets) -------------------

    @app.get("/api/env/{env}/credentials")
    def list_credentials(env: str, request: Request) -> list[CredentialInfo]:
        _require_env(request, env)
        return _credentials_or_503(request).list(environment=env)

    @app.put("/api/env/{env}/credentials", status_code=201)
    def put_credential(env: str, body: CredentialIn, request: Request) -> CredentialInfo:
        _require_env(request, env)
        if not _registry(request).get(env).credential_storage_enabled:
            raise HTTPException(
                status_code=409,
                detail=f"credential storage is disabled for environment {env!r} — "
                "enable it first, or supply credentials per operation",
            )
        store = _credentials_or_503(request)
        try:
            return store.put(
                Credential(
                    host=body.host,
                    kind=body.kind,
                    username=body.username,
                    secret=SecretStr(body.secret),
                    environment=env,
                )
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/env/{env}/credentials/{host}/{kind}")
    def delete_credential(
        env: str, host: str, kind: CredentialKind, request: Request
    ) -> dict[str, bool]:
        _require_env(request, env)
        return {"deleted": _credentials_or_503(request).delete(host, kind, environment=env)}

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
