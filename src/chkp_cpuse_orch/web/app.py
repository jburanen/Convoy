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
    CredentialInfo,
    CredentialKind,
    CredentialStore,
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
from ..inventory import Inventory
from ..jobs import JobRunner
from ..packages import PackageStore
from ..reporting import configure_logging, get_logger
from ..services.cdt_ops import CDTService
from ..services.common import ClientFactory, HostConnector
from ..services.patching import PatchingService
from ..store import JobEvent, JobRecord, PackageRecord, Store

logger = get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


# -- request/response bodies -------------------------------------------------------


class CredentialIn(BaseModel):
    host: str
    kind: CredentialKind
    username: str | None = None
    secret: str = Field(min_length=1)


class ImportRequest(BaseModel):
    package: str  # filename in the package store


class InstallRequest(BaseModel):
    package_id: str  # CPUSE identifier as shown by detect
    confirmed: bool = False  # UI must send True after an explicit operator confirm
    verify_first: bool = True


class StageRequest(BaseModel):
    package: str  # filename in the package store


class PrepareRequest(BaseModel):
    extended: bool = False  # extended also updates CPUSE + imports on targets


class ExecuteRequest(BaseModel):
    confirmed: bool = False  # UI must send True after an explicit operator confirm


class CandidatesIn(BaseModel):
    header: list[str]
    rows: list[list[str]]  # row order == deployment order


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
        packages = PackageStore(store, cfg.paths.packages_dir)

        inventory = Inventory()
        if cfg.paths.inventory_path.is_file():
            inventory = Inventory.load(cfg.paths.inventory_path)
        else:
            logger.warning("no inventory file", path=str(cfg.paths.inventory_path))

        credentials: CredentialStore | None = None
        try:
            credentials = CredentialStore(store, load_master_key())
        except CredentialError as exc:
            # Boot anyway: health/packages/jobs still work; credential-dependent
            # endpoints return 503 with this reason.
            logger.warning("credential store locked", reason=str(exc))
            app.state.credentials_error = str(exc)

        runner = JobRunner(store)
        connector = HostConnector(inventory, credentials, client_factory)
        service = PatchingService(
            inventory=inventory,
            credentials=credentials,
            packages=packages,
            runner=runner,
            connector=connector,
        )
        cdt_service = CDTService(
            inventory=inventory,
            credentials=credentials,
            packages=packages,
            runner=runner,
            connector=connector,
        )

        app.state.store = store
        app.state.packages = packages
        app.state.credentials = credentials
        app.state.runner = runner
        app.state.service = service
        app.state.cdt = cdt_service

        interrupted = runner.recover()
        if interrupted:
            logger.warning("jobs interrupted by previous shutdown", count=len(interrupted))
        serve_task = asyncio.create_task(runner.serve())
        try:
            yield
        finally:
            runner.stop()
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
        status = 404 if "not found" in str(exc) or "no such" in str(exc) else 400
    elif isinstance(exc, CredentialError):
        status = 503 if "locked" in str(exc) else 409
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
            "management_servers": len(service.management_servers()),
            "packages": len(request.app.state.packages.list()),
        }

    # -- servers -------------------------------------------------------------

    @app.get("/api/servers")
    def servers(request: Request) -> list[dict[str, Any]]:
        service = _service(request)
        return [
            {
                "name": h.name,
                "address": h.address,
                "role": h.role.value,
                "ssh_user": h.ssh_user,
                "credentials": service.credential_kinds(h.name),
            }
            for h in service.management_servers()
        ]

    @app.get("/api/servers/{name}/state")
    async def server_state(name: str, request: Request) -> dict[str, Any]:
        _credentials_or_503(request)
        service = _service(request)
        try:
            detected = await asyncio.to_thread(service.detect, name)
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

    @app.post("/api/servers/{name}/import", status_code=202)
    def server_import(name: str, body: ImportRequest, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _service(request).submit_import(name, body.package)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/servers/{name}/install", status_code=202)
    def server_install(name: str, body: InstallRequest, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _service(request).submit_install(
                name, body.package_id, confirmed=body.confirmed, verify_first=body.verify_first
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

    @app.delete("/api/packages/{filename}")
    def delete_package(filename: str, request: Request) -> dict[str, bool]:
        packages: PackageStore = request.app.state.packages
        try:
            return {"deleted": packages.delete(filename)}
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    # -- credentials (never echo secrets) --------------------------------------

    @app.get("/api/credentials")
    def list_credentials(request: Request) -> list[CredentialInfo]:
        return _credentials_or_503(request).list()

    @app.put("/api/credentials", status_code=201)
    def put_credential(body: CredentialIn, request: Request) -> CredentialInfo:
        store = _credentials_or_503(request)
        try:
            return store.put(
                Credential(
                    host=body.host,
                    kind=body.kind,
                    username=body.username,
                    secret=SecretStr(body.secret),
                )
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.delete("/api/credentials/{host}/{kind}")
    def delete_credential(host: str, kind: CredentialKind, request: Request) -> dict[str, bool]:
        return {"deleted": _credentials_or_503(request).delete(host, kind)}

    # -- CDT (gateway fleet, driven from a management server) --------------------

    def _cdt(request: Request) -> CDTService:
        cdt: CDTService = request.app.state.cdt
        return cdt

    @app.get("/api/cdt/{name}/status")
    async def cdt_status(name: str, request: Request) -> dict[str, Any]:
        _credentials_or_503(request)
        try:
            return await asyncio.to_thread(_cdt(request).get_status, name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.get("/api/cdt/{name}/candidates")
    async def cdt_candidates(name: str, request: Request) -> dict[str, Any]:
        _credentials_or_503(request)
        try:
            cands = await asyncio.to_thread(_cdt(request).get_candidates, name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"header": cands.header, "rows": cands.rows}

    @app.put("/api/cdt/{name}/candidates")
    async def cdt_save_candidates(
        name: str, body: CandidatesIn, request: Request
    ) -> dict[str, int]:
        _credentials_or_503(request)
        try:
            count = await asyncio.to_thread(
                _cdt(request).save_candidates,
                name,
                CandidatesFile(header=body.header, rows=body.rows),
            )
        except OrchestratorError as exc:
            raise _map_error(exc) from exc
        return {"rows": count}

    @app.post("/api/cdt/{name}/stage", status_code=202)
    def cdt_stage(name: str, body: StageRequest, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _cdt(request).submit_stage(name, body.package)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/cdt/{name}/generate", status_code=202)
    def cdt_generate(name: str, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _cdt(request).submit_generate(name)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/cdt/{name}/prepare", status_code=202)
    def cdt_prepare(name: str, body: PrepareRequest, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _cdt(request).submit_prepare(name, extended=body.extended)
        except OrchestratorError as exc:
            raise _map_error(exc) from exc

    @app.post("/api/cdt/{name}/execute", status_code=202)
    def cdt_execute(name: str, body: ExecuteRequest, request: Request) -> JobRecord:
        _credentials_or_503(request)
        try:
            return _cdt(request).submit_execute(name, confirmed=body.confirmed)
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
