---
name: architecture
description: Module layout and data flow of the orchestrator
metadata:
  type: project
---

Package: `src/chkp_cpuse_orch/`. Layered so the CDT/CPUSE wrappers stay thin and the
orchestration/safety logic is testable without live gear.

**Front-end model: web-primary, CLI-secondary.** The FastAPI web app is the main
interface; the Typer CLI is a secondary/automation caller. Both are thin front-ends
over the same **service core** — no business logic lives in `web/` routes or `cli.py`.
See [[patching-web-design]] for the two-subsystem design this serves.

```
chkp_cpuse_orch/
  cli.py            # Typer entrypoint (secondary front-end); calls the service core
  web/              # FastAPI app (PRIMARY front-end): routes, SSE/WS status, static UI
    app.py          # ASGI app, health/root today; grows the management UI
  services/         # Service core — the shared logic both front-ends call
    common.py       # HostConnector: inventory+credentials→connected Transport; ClientFactory
    patching.py     # CPUSE-local subsystem: detect/import/install jobs per mgmt server
    cdt_ops.py      # CDT subsystem: stage/generate/candidates-edit/prepare/execute jobs
    pkgs_ops.py     # Package-action jobs: upload/keep/notkeep/delete (pkgs.* kinds)
  config.py         # Pydantic settings (global tool config, defaults, paths)
  inventory.py      # Pydantic models: Site, ManagementServer, Gateway, Cluster; loader
  credentials.py    # Encrypted-at-rest credential store (key + password; see design)
  packages.py       # Package store: streaming upload, SHA-1/size verify, dedupe on /data
  jobs.py           # Background job model + runner; persisted state machine per action
  store.py          # SQLite persistence on /data (jobs, cred ciphertext, pkg metadata)
  transport/
    ssh.py          # Paramiko SSH to Gaia (clish + expert), command runner + SCP/SFTP
    gaia_api.py     # Gaia REST API client (httpx)
    mgmt_api.py     # Check Point Management API (mgmt_cli / web-api) client
  cpuse.py          # Thin wrapper over CPUSE installer verbs on ONE Gaia host
  cdt.py            # Thin wrapper: build XML plan + target list, invoke `cdt`, parse
  orchestrator.py   # Fleet sequencing: batching, HA-aware ordering, gating on checks
  checks.py         # Pre/post health checks (version, cluster state, policy, disk)
  reporting.py      # structlog + Rich run records; write auditable reports/
  errors.py         # Typed exceptions
```

**Data flow:** front-end (web/CLI) → `services/` → `orchestrator` builds a run plan →
`checks` gate each step → `cpuse`/`cdt` execute via `transport` → `jobs` tracks
long-running work (persisted in `store`) → `reporting` records everything. Inventory
and config still load from `inventory.yaml` + `config.yaml` into Pydantic models;
credentials come from the encrypted `credentials` store, never from those files.

**Design rules**
- Wrappers (`cpuse.py`, `cdt.py`) never make policy decisions; they execute and
  parse. All sequencing/safety lives in `orchestrator.py` + `checks.py`.
- Business logic lives in `services/`, never in `web/` routes or `cli.py`. Both
  front-ends stay thin.
- Every mutating operation supports **dry-run** and emits an audit record.
- Long-running ops (import/install, CDT execute) run as **background jobs** with a
  persisted state machine — a web click enqueues, never blocks. See [[patching-web-design]].
- Nothing hardcodes hostnames/IPs/credentials — all from inventory/config/secrets
  store. See [[security-hygiene]] and [[safety-constraints]].
