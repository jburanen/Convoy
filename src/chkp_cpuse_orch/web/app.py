"""FastAPI application — minimal placeholder.

Exposes just enough to confirm the container is live and correctly wired:
``GET /health`` for liveness/readiness probes and ``GET /`` for service info.
Candidate/plan/run management endpoints are added here as the web UI is built.

Run: ``uvicorn chkp_cpuse_orch.web.app:app --host 0.0.0.0 --port 8080``.
"""

from __future__ import annotations

from fastapi import FastAPI

from .. import __version__

app = FastAPI(
    title="chkp-cpuse-orch",
    version=__version__,
    summary="Orchestration API for Check Point CDT/CPUSE deployments.",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness/readiness probe. Cheap, no external dependencies."""
    return {"status": "ok", "version": __version__}


@app.get("/")
def root() -> dict[str, str]:
    """Service banner. The management UI is not implemented yet."""
    return {
        "service": "chkp-cpuse-orch",
        "version": __version__,
        "status": "placeholder — management UI not yet implemented",
    }
