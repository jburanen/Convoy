---
name: patching-web-design
description: The two patching subsystems, the web-primary service core, and the key design decisions behind them
metadata:
  type: project
---

The tool handles **two patching subsystems** over one shared service core. The web
UI is the primary interface (see [[architecture]]); the CLI is secondary.

## Two subsystems
- **CDT subsystem** — gateways and other CDT-patchable hosts. Fan-out from a mgmt
  server: build XML plan + candidates CSV, invoke CDT, tail status. See
  [[cdt-cpuse-domain]]. Code: `cdt.py`.
- **CPUSE-local subsystem** — the **management servers themselves**, which CDT does
  NOT patch. Operator-driven, one host at a time, via the web UI. Per-host flow:
  **transfer package → `installer import` → `installer install`** (→ optional reboot
  → verify). Code: `cpuse.py`. This is the manual flow the web UI exposes as
  per-server buttons that reflect *detected* state (`show installer packages` is the
  source of truth), each button idempotent.

## Decisions locked (2026-07-17)
- **Gaia auth = both/mixed.** SSH key for the transport; admin **password** for
  privileged installer/expert steps. The credential store holds both per host.
- **Web-primary, CLI-secondary.** Invest in the web + job-runner model as the main
  experience; CLI is a thin secondary caller of the same `services/` core.
- **Persistence = SQLite on `/data`** (the bind-mounted, git-ignored volume) via
  **stdlib `sqlite3`** (connection-per-call + WAL in `store.py` — chose it over
  SQLModel/SQLAlchemy: 4 small tables, zero extra deps, cleaner under mypy strict).
  Holds jobs, credential ciphertext, package metadata. Migrations are an
  append-only script list checked against `PRAGMA user_version`.
- **Crypto = `cryptography` (Fernet)**, key derived from the master passphrase via
  scrypt with a per-DB salt; a canary token in `meta` makes a wrong key fail fast.
  Only new runtime dependency.

## Web frontend structure (operator preference — hand-editable, 2026-07-17)
The operator wants to **hand-edit the UI files directly**, so the frontend must stay
plain and file-based:
- Static `*.html` + `css/` + `js/` files under `src/chkp_cpuse_orch/web/static/`,
  served via FastAPI `StaticFiles`. What's on disk is what the browser gets.
- **No build step, no bundler, no npm, no SPA framework.** Edit → refresh.
- Dynamic data comes from plain-JS `fetch()` against the JSON API, filling
  placeholders. Repeated markup (table rows, cards) lives in HTML `<template>`
  elements in the page — never in Python strings, never in JS string literals.
- Avoid Jinja; if templating ever becomes unavoidable, keep it to a minimal base
  layout. Never generate HTML from Python.

## Web UI authentication (requirement, 2026-07-19 — not yet built)
The admin UI must support **both**:
- **Basic auth** — local users; password hashes at rest (never plaintext).
- **LDAP** — bind against the org directory (likely AD); config for server URL,
  base DN, bind template/service account, and an allowed group.
Design so both are backends behind one auth layer (session cookie after login;
FastAPI dependency guarding all /api routes and the static UI). Until this
ships, the app is safe only on a trusted network — flagged in the Phase 3
commit message.

## New core infrastructure (shared by both subsystems)
- **Credential store, encrypted at rest.** Ciphertext in SQLite; master key supplied
  at container start (env var / docker secret), held only in memory, never written to
  `/data`. External Vault can later slot behind the same interface. Repo is public and
  `/data` is a bind mount, so plaintext secrets must never land on the volume. See
  [[security-hygiene]].
- **Package store.** Upload once via web (JHFs are GB-scale → streaming upload +
  SHA-1/size verify against Check Point's published values + dedupe), stored on
  `/data`. Then distribute: SCP to each mgmt server + `installer import`, or the Gaia
  REST software-updates import endpoint where available. Upload-once / push-to-many.
- **Background job runner.** Import/install take minutes and may reboot the host, so a
  web click enqueues a persisted **Job** with a state machine
  (staged → imported → installed → reboot → verified) and live status (SSE/WebSocket,
  poll fallback). Jobs survive page refresh and container restart.

## Safety still applies to the "manual" mgmt-server flow
Management servers are usually **HA pairs** and JHF installs often reboot. Even in
button-driven mode the tool must warn/gate: never patch both HA members at once,
confirm the peer is healthy first, dry-run/confirm before mutating. See
[[safety-constraints]].
