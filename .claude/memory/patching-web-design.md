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
  privileged installer/expert steps. Both live together in a named **login set**
  assigned to the server (migration v8; see [[credential-sets]]).
- **Web-primary, CLI-secondary.** Invest in the web + job-runner model as the main
  experience; CLI is a thin secondary caller of the same `services/` core.
- **Environments are DB-backed and UI-editable** (v0.4.0). `environments` +
  `env_hosts` tables (migration v4); managed by `services/environments.py`
  (`EnvironmentManager`). **Seeded once** from config.yaml + inventory files on
  first run (meta flag `environments_seeded`), then the DB is authoritative and
  config files are ignored. Only management/mds hosts are stored (gateways come
  from CDT). UI split (v0.5.0/v0.8.0, operator-directed): the picker's "Manage
  Environments…" entry opens a **create + rename modal**; server add/remove and
  environment deletion live on the **Provisioning tab**, scoped to the picker's
  current environment (no separate manage tab). **Rename** is a real endpoint
  (`POST /api/environments/{env}/rename`): one SQLite transaction moves
  env_hosts, credentials, and job history to the new name (insert-new /
  move-children / delete-old — the FK is ON DELETE CASCADE only, so no PK
  update). `EnvironmentRegistry.rebuild()` refreshes the live registry after each
  mutation so long-lived services see changes without reconstruction. Deleting an
  environment drops its `env_hosts` (cascade) **and purges its credentials** — a
  later same-named environment must not inherit old secrets (credential-leak
  guard, operator-flagged). Credential purge works even when the store is locked.
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
- **Planned split (operator-directed, 2026-07-19):** when auth + RBAC land, do NOT
  split index.html into per-tab pages (tabs share live state: env selection, jobs
  polling, cross-tab refreshes). Instead split **app.js into per-section files**
  loaded via multiple plain `<script>` tags — no tooling needed. The **login screen
  becomes a separate page** (it shares no tab state); RBAC admin likewise if it
  outgrows a tab. Header/footer stay in the one main page — plain HTML has no
  include mechanism worth its cost here.

## Web UI authentication (LDAP shipped 2026-07-20 — see [[web-auth]])
LDAP/AD authentication is **built**: `web/auth.py` (`Authenticator` protocol,
`LDAPAuthenticator`, `AuthManager`, env-driven `AuthSettings`), server-side
sessions (migration v7 `sessions` table, hashed tokens), and a middleware guarding
all `/api/*` + the static UI. Full design in [[web-auth]]. Key facts:
- **Auth is optional** (operator-chosen): unset LDAP env → app runs open, as before
  — **but** enabling per-environment credential storage is then rejected (409). No
  persistent secrets without an auth gate.
- **Group gate = direct `memberOf`** membership of `CHKP_CPUSE_LDAP_REQUIRED_GROUP`.
- **Idle logout** (`CHKP_CPUSE_SESSION_IDLE_MINUTES`, default 30) enforced
  server-side (sliding `last_seen_at`) *and* client-side; logout/idle/401 all wipe
  the tab's cached credentials via the existing `cacheClearCreds()`.
- Login is a **separate static page** (`login.html` + `js/login.js`), as planned.
Still outstanding (unchanged from the original requirement): a **local basic-auth**
backend (design already fits behind the `Authenticator` protocol) and **per-
environment RBAC** — environments are DB rows partly for that reason.

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
