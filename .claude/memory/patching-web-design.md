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
  NOT patch. Operator-driven, via the web UI. Per-host flow:
  **transfer package → `installer import` → `installer install`** (→ optional reboot
  → verify). Code: `cpuse.py`. This is the manual flow the web UI exposes as
  per-server buttons that reflect *detected* state (`show installer packages` is the
  source of truth), each button idempotent.
  - **Two import paths** (2026-07-22): bulk-import controls above the servers table,
    targeting one or more checkbox-selected servers, sequentially (not parallel —
    same pattern as "Refresh all"): (1) upload a package from the local store, SFTP
    it to a staging path, **verify its sha1 on the host itself** (`sha1sum`, raw
    shell command — catches transit corruption the size check alone would miss),
    `installer import local`, **confirm via `show installer packages imported`**
    (matching by filename *or* by hf.config's version+Take — see
    [[cdt-cpuse-domain]] for why filename alone isn't reliable), then remove the
    temp copy; (2) `import_cloud()` — give
    CPUSE a package identifier and it fetches + imports directly from Check Point's
    cloud repo (`installer import <ID>`, no "local", no upload at all — confirmed
    via docs MCP against sk92449's `show installer packages available` / `installer
    import <name>` workflow). Install itself stays per-server (its own dropdown of
    that server's cached "imported but not installed" packages,
    `server_state.installable` — see below), not part of the bulk controls, since a
    reboot-worthy action needs one target at a time with its own confirmation.
  - **`installer import local` is asynchronous — don't trust its exit status alone**
    (bug found in production, 2026-07-22). The clish command returns before CPUSE
    finishes processing the file ("Determining the package type" → "Examining the
    file" → ... in `xpand` logs); the first cut of "remove the temp copy after
    import" deleted it right after the command returned, racing CPUSE's own
    pipeline, which then failed with *"The package file is missing from
    /var/log/upload/"* — while our job still reported **succeeded**. Fix in
    `PatchingService._wait_until_imported`: after `import_local`, poll `show
    installer packages imported` (via `CPUSE.list_packages(PackageScope.IMPORTED)`)
    until the package actually appears (default 60 attempts × 5s = 5 min) before
    declaring success or touching the temp file; if it never shows up, the job
    **fails** and the temp copy is left in place for manual investigation. Matches
    by exact identifier or filename-stem substring (identifier format drifts across
    Gaia versions — see `cpuse.parse_packages`).

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
  Each environment also declares itself **SMS or Multi-Domain (MDS)** once
  (`is_mds`, migration v10) — see [[environment-kind]].
- **Persistence = SQLite on `/data`** (the bind-mounted, git-ignored volume) via
  **stdlib `sqlite3`** (connection-per-call + WAL in `store.py` — chose it over
  SQLModel/SQLAlchemy: 4 small tables, zero extra deps, cleaner under mypy strict).
  Holds jobs, credential ciphertext, package metadata. Migrations are an
  append-only script list checked against `PRAGMA user_version`.
- **Crypto = `cryptography` (Fernet)**, key derived from the master passphrase via
  Argon2id (`argon2-cffi`) with a per-DB salt; a canary token in `meta` makes a
  wrong key fail fast.

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
- **Cached CPUSE state per server** (`server_state` table, migration v11,
  2026-07-22). The Management tab no longer queries CPUSE state on page load —
  `GET /servers` returns whatever was last detected (version/JHF/agent build/
  checked_at), so the table always shows *something* without an SSH round trip.
  A per-row text link + a top "Refresh all" button trigger a live
  `POST .../state`, which re-derives the summary via `cpuse.summarize_jumbo()`
  (major version + highest-Take installed JHF — earlier Takes a JHF superseded
  show as "installed as part of") and persists it. Keyed by (environment, host)
  name, not an `env_hosts` FK — same reasoning as the pre-v8 credentials table.

- **Jobs tab retention + archival** (operator-directed, 2026-07-23). The Jobs
  table is meant for recent operational history, not an indefinite audit log:
  - **Display limit**: `GET /api/jobs?limit=N` — `N<=0` means unlimited (the
    Jobs tab's "All" option). The tab's "Show N jobs" `<select>` (10/20/50/
    All, default 10, persisted in localStorage) drives this. The live-count
    badge is deliberately fed by `pollJobs()`'s own fixed `limit=25` fetch,
    never by the display-limited one — otherwise a small display limit would
    make the running/pending badge undercount.
  - **Flat-file archive** (`archive.py`, `JobArchiver`, store migration
    unaffected — reads/writes existing tables): a daily background sweep
    (`_reap_old_jobs` in `web/app.py`, same pattern as the package-retention
    reaper) moves *terminal* jobs older than 366 days — metadata, full
    progress log, and any captured install-log text — out of the DB as one
    JSON line per job appended to `cfg.paths.job_archive_path` (default
    `state/job_archive.log`, alongside the DB on `/data`), then deletes them
    (events cascade). The archive file is kept under 50MB by dropping the
    *oldest* lines once a sweep would push it over, so it never grows
    unbounded even across years of operation. Not browsable in the web UI —
    the Jobs tab hint just names the path (`GET /api/status` →
    `job_archive_path`) so an operator knows where to look.
  - **Install log capture**: CPUSE's own "Installation log:" field (from
    `show installer package <id>`) only names a *path* on the host — worthless
    once CPUSE rotates/deletes the file. `PatchingService._capture_install_log`
    `cat`s that path over the same SSH connection right after an install
    finishes (success or failure) and saves the actual content on
    `JobRecord.install_log` (capped at 2MB), not just the path. Best-effort —
    a fetch failure is a warning, never a job failure. The Jobs tab renders it
    as a collapsed-by-default `<details>` section under the job row (open
    state persists across polls since the row isn't torn down); it's included
    verbatim in the flat-file archive above.
  - **Per-column multiselect filters** (operator-directed, 2026-07-23):
    Kind/Target/Env/Status each get a native `<select multiple>` above the
    table, OR'd within a column and AND'd across columns
    (`GET /api/jobs?kind=a&kind=b&status=failed`, repeated query params).
    Options come from `GET /api/jobs/facets` (`Store.list_job_facets`) —
    `SELECT DISTINCT` over the *whole* jobs table, deliberately independent
    of the display-limit query, so a "Show 10" view still offers every kind/
    target/env/status that exists, not just what's on the current page. Null
    `target` (CDT/non-host jobs) is excluded from the target facet — not a
    selectable option. Facets refresh whenever the visible job set's shape
    changes in `loadJobs()`, preserving the operator's current selections.

## Safety still applies to the "manual" mgmt-server flow
Management servers are usually **HA pairs** and JHF installs often reboot. Even in
button-driven mode the tool must warn/gate: never patch both HA members at once,
confirm the peer is healthy first, dry-run/confirm before mutating. See
[[safety-constraints]].
