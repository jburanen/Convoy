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
  - **The disk-space check is part of the import job** (operator-directed,
    2026-08-26). It used to ALSO run as a synchronous pre-submit probe
    (`check_import_disk_space` + two `/import/disk-space` routes, now removed)
    so the UI could show the shortfall and `confirm()` an override before
    queuing. That probe needed SSH plus an expert-mode escalation, so the
    operator sat on a spinner with nothing on the Jobs tab, and a failure
    arrived as a browser `alert()` rather than a job they could inspect.
    Now: submitting an import creates the job immediately, `bulkImport()`
    switches to the Jobs tab (expanding the log only for a single target --
    every open log is re-fetched on each poll), and the check runs as the
    job's first step with `ctx.set_status("checking disk space")`. A shortfall
    fails the job. An **override-eligible** shortfall (still >=1.5x the
    package size) additionally offers **"Retry with override"** on the job
    row, which submits a NEW import with `force_low_space` via
    `retry_import_with_override`; the failed job stays as the record of why.
    The link is gated on the error carrying `LOW_SPACE_OVERRIDABLE`
    (`services/patching.py`, mirrored as `LOW_SPACE_OVERRIDABLE_RE` in
    app.js -- keep the two in step), and the service re-checks that same
    marker so the link can't be repurposed to force an unrelated failure.
    Below 1.5x there is still no override, ever.
  - **Pre-import disk space check** (operator-specified, 2026-07-23):
    `PatchingService._check_disk_space` runs `df -Pk` on `/var/log` and `/`
    (raw shell command, same as `sha1sum` below) before anything else in the
    local-upload import path — fails the job closed with `PreCheckError`,
    before ever uploading, if free space is under 3x the package size on
    `/var/log` (staging + CPUSE's own extraction headroom) or 2x on `/`
    (CPUSE's import bookkeeping). Not applied to `import_cloud` (no local
    file size to check against — CPUSE fetches it directly).
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
    until the package actually appears (default 30 attempts × 10s = 5 min) before
    declaring success or touching the temp file. Matches by exact identifier or
    filename-stem substring (identifier format drifts across Gaia versions — see
    `cpuse.parse_packages`).
  - **A timeout is TIMED_OUT, not FAILED** (operator-specified, 2026-07-25 — imports
    "can sometimes take many minutes"). `JobStatus.TIMED_OUT` (new) + `JobTimedOut`
    (jobs.py, caught in `JobRunner._run` alongside `JobCancelled`) exist because a
    poll giving up isn't a verdict — CPUSE may still be working server-side. The temp
    copy is left in place either way, same as before. The Jobs tab shows a "Check
    status" text link (`button.link-btn`, reused from the per-row Refresh links) on
    any TIMED_OUT `cpuse.import` row — `POST /api/jobs/{id}/recheck-import` →
    `PatchingService.recheck_import`, one more live `show installer packages
    imported` look reusing the same match logic (`_is_imported_now`, factored out of
    `_wait_until_imported` for this). If it now shows up: resolves the job to
    SUCCEEDED, cleans up the temp copy, refreshes cached state — same as the
    automatic path would have. If not: stays TIMED_OUT, just logs the negative
    check, operator can try again later. Route derives host/environment from the
    job record itself (not the URL) since a TIMED_OUT job's in-memory credentials
    are already purged by `JobRunner`'s `on_job_finished` — a storage-disabled
    environment needs credentials re-supplied, so `operationCredentials()` gained an
    optional third `env` param (defaulting to `currentEnv`) since the Jobs tab isn't
    scoped to one environment the way every other credential-prompting action is.
  - **Polling progress lines overwrite in place, not stack** (operator-specified,
    2026-07-25 — a slow import polling every 10s for 5 minutes could leave ~30
    near-identical "not yet listed as imported" lines to scroll through).
    `Store.update_event(job_id, seq, message, level)` UPDATEs an existing
    `job_events` row instead of inserting; `JobContext.log(msg, replace=seq)` uses
    it when `replace` is given and now returns the `JobEvent` (previously `None`)
    so callers can chain the next replacement off its `seq`. `_wait_until_imported`
    tracks one `progress_seq` across its loop, so the "still waiting (check N/M)"
    line updates itself each attempt instead of accumulating — the operator still
    sees a live attempt counter and timestamp, just as one line. The Jobs tab needed
    no frontend change: `refreshJobLogRow` already refetches and re-renders the full
    event list every poll rather than appending incrementally.

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
- Static `*.html` + `css/` + `js/` files under `src/convoy/web/static/`,
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
- **CSS gotcha: a bare `.foo-link` override loses to `button.link-btn`'s own
  rule** (operator-reported, 2026-08-18 — the Firewalls table's name-as-button
  read as indented ~6px vs. its column header). `button.link-btn` sets
  `margin-left: 0.4rem` (for the inline "Refresh"-style use) at specificity
  (0,1,1); a later `.fw-name-link { margin-left: 0; }` is only (0,1,0) — class
  alone loses to element+class regardless of source order, so the override
  silently never applied despite reading correctly in the stylesheet. Fixed by
  writing it `button.link-btn.srv-name-link, button.link-btn.fw-name-link`
  (app.css). Any future `.link-btn` variant needing to override a property
  `button.link-btn` itself sets must match or exceed that selector's
  specificity, not just come later in the file. The Management-tab server row
  (`.srv-name`) got the same button-wrapped name-as-Edit-trigger treatment as
  the Firewalls table's `.fw-name` in this pass (`loadServers()` now iterates
  the CRUD `editable` list, cross-referenced via `stateByName` for cached
  CPUSE state — same split `loadFirewalls()` already used, needed here too
  since `openEditServerModal` wants `ssh_port`, which the patching-view list
  doesn't carry).

## Web UI authentication (LDAP shipped 2026-07-20 — see [[web-auth]])
LDAP/AD authentication is **built**: `web/auth.py` (`Authenticator` protocol,
`LDAPAuthenticator`, `AuthManager`, env-driven `AuthSettings`), server-side
sessions (migration v7 `sessions` table, hashed tokens), and a middleware guarding
all `/api/*` + the static UI. Full design in [[web-auth]]. Key facts:
- **Auth is optional** (operator-chosen): unset LDAP env → app runs open, as before
  — **but** enabling per-environment credential storage is then rejected (409). No
  persistent secrets without an auth gate.
- **Group gate = direct `memberOf`** membership of `CONVOY_LDAP_REQUIRED_GROUP`.
- **Idle logout** (`CONVOY_SESSION_IDLE_MINUTES`, default 30) enforced
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
  - **Package actions are jobs too** (`pkgs.upload`/`pkgs.keep`/`pkgs.notkeep`/
    `pkgs.delete` — `services/pkgs_ops.py`, `PackageJobService`; operator-directed,
    2026-07-23). Unlike CPUSE/CDT jobs these are local disk+DB ops with no SSH
    host/credentials, so they're submitted straight via `JobRunner.submit()`, not
    `submit_host_job`; `target` is the package filename. Keep/unkeep get *separate*
    kinds (not one `pkgs.retention` with a bool param) so the Jobs tab's Kind
    filter distinguishes them. **Upload's wrinkle**: the file's bytes only exist
    for the HTTP request's lifetime (Starlette tears down its spooled temp file
    once the response is sent), so a background job can't consume the `UploadFile`
    directly — the route first stages the upload to a stable path inside the
    package directory (a cheap disk copy, no hashing, still synchronous — inherent
    to HTTP, can't be deferred), *then* submits the job; the job handler does the
    real work (hash, dedupe, move into place) via `PackageStore.add_stream` and
    removes the staging file when done (success or failure). One consequence:
    the "same name, different content" conflict, previously an immediate 409, is
    now a **deferred job failure** (only detectable once the job hashes the
    staged file) — matches how CPUSE errors already surface. Retention/delete
    still 404 synchronously (`PackageStore.get()` is cheap to check before
    creating a job). Frontend: `PKGS_JOB_KINDS` in `pollJobs()` (mirrors
    `IMPORT_JOB_KINDS`) reloads the Packages tab on any pkgs.* job's terminal
    transition; the three call sites (upload form/drag-drop, the Keep checkbox,
    Delete) only react to *submit* failure now (revert/toast), same as every
    other job-backed action in the app (e.g. `installPackage` never waits for
    its own job either) — the job's actual outcome is Jobs-tab-only.

    **Update, 2026-07-24: `pkgs.*` no longer queues, same change as `cred.*`
    (see below).** Upload/keep/unkeep/delete now execute **synchronously**
    inside the request (`services/pkgs_ops.py`, operator-directed) instead of
    going through `JobRunner.submit()` — local disk+DB ops with no SSH host
    involved have no reason to make the operator wait on the async queue. A
    `JobRecord` is still inserted and immediately finished purely for
    Jobs-tab visibility/audit history; routes return `200`, not `202`. The
    "same name, different content" conflict is therefore back to being an
    immediate response (a **failed job** in that response, not a bare 409 —
    the failed-job convention itself didn't change, only *when* it's
    knowable) rather than something only detectable on a later poll. Upload
    still stages to a temp path first (the multipart body's bytes only exist
    for the request's lifetime — inherent to HTTP, can't be synchronous vs.
    deferred either way), then `submit_upload` does the real work (hash,
    dedupe, move into place) in the same call and removes the staging file
    itself. The frontend's three call sites (upload form/drag-drop, the Keep
    checkbox, Delete) now react to the *actual* outcome, not just submit
    failure — e.g. the Keep checkbox reverts if the write itself failed, not
    only on a network-level error — and reload the Packages table directly
    rather than waiting for `PKGS_JOB_KINDS`/`pollJobs()`, which is now only a
    fallback for another tab/session polling mid-write.

    **New, 2026-07-24: `pkgs.push_to_repo` — the one pkgs.\* op that stays
    queued.** "Upload to repo" button (Packages tab, left of Delete) pushes a
    stored package onto the environment's *primary* management server and
    registers it in SmartConsole's Package Repository, via
    `services/pkg_repo_ops.py`'s `PackageRepoService`. Confirmed against Check
    Point's official API reference that the real command is
    `add-repository-package` — it does **not** accept file bytes, it needs the
    package to already exist at a path on the management server's own
    filesystem, and returns a `task-id` polled via `show-task`. So this job:
    SFTPs the file to the primary (same skip-if-already-staged/size-verified
    pattern as `cdt_ops.py`'s stage step, reusing `patching.py`'s
    `ProgressReporter`), then opens a **write-capable**
    (`ManagementAPIClient(..., read_only=False)`) session and calls
    `add_repository_package` + polls `show_task`. Genuinely slow (large-file
    SFTP + a server-side import) — deliberately *not* folded into the
    synchronous `pkgs.*` pattern above, and *not* added to `discovery.py`
    (whose docstring states it "never writes" — a real boundary). Targets
    `HostConnector.primary_mgmt_host()` always — no per-row host to pick from
    on the Packages tab, since packages are environment-agnostic; the
    Management-API credential↔bundle mapping (`api_auth`, prefers an API key,
    falls back to the SSH username/password) moved from `discovery.py` to
    `services/common.py` since this is now its second caller. **Open
    question, unverified against live gear:** whether `add-repository-package`
    needs a `publish` call afterward — assumed not (task-based commands like
    `install-policy` normally don't, unlike object CRUD); a wrong assumption
    surfaces as a task-failure error, not a silent false success.

    **Confirmed against live gear, 2026-07-25: `path` must end with `/`.**
    First real-world call failed with `The path must start with the forward
    slash, must not contain spaces, and must end with the forward slash.`
    `DEFAULT_STAGING_DIR` (`/var/log/upload`, `cpuse.py`) has no trailing
    slash, so every call was broken until fixed. `pkg_repo_ops.py`'s
    `_do_push` now appends `/` to `self._staging_dir` before passing it as
    `add_repository_package`'s `path` arg — fix lives at the call site, not in
    `mgmt_api.py`, since `ManagementAPIClient.add_repository_package` is a
    thin wrapper and other callers may want to pass an already-correct path.
  - **Server/firewall CRUD is jobs too** (`prov.add`/`prov.edit`/`prov.delete` —
    `services/prov_ops.py`, `ProvisioningJobService`; operator-directed, 2026-07-23).
    Add/edit/delete of management servers *and* CPUSE firewalls share these three
    kinds — no per-entity split — with an internal `params["entity"]` ("server"|
    "firewall") discriminator the single handler pair uses to call
    `EnvironmentManager`/`FirewallManager`; invisible on the Jobs tab, which only
    ever shows `prov.add`/`prov.edit`/`prov.delete`. Whether a `submit_put_*` is
    an add or an edit is decided the same way `cred.add`/`cred.edit` is — a cheap
    existence read before the kind is picked. **Validation now matches
    credentials**: a bad role or a name colliding with the other entity's table
    (servers and firewalls share one name space) surfaces as a **failed job**,
    not a synchronous 400/409 — a deliberate operator choice, since the more
    consistent alternative (client-side wait-for-job to preserve instant
    feedback) was explicitly rejected in favor of matching `cred.*`. Only
    environment existence (route-level `_require_env`) and, for delete, target
    existence stay a synchronous pre-submit check (mirrors
    `CredentialJobService.submit_delete`'s "don't defer an obviously-doomed
    job"). **Credential-set assignment made in the same Add/Edit modal submit
    rides in the same job** (`credential_set`, tri-state via the `UNSET`
    sentinel — omitted/null/name) instead of the separate `POST .../credential`
    call the frontend used to fire immediately after add/edit: that separate
    call could 404 if it reached the server before the add/edit job itself had
    run (`JobRunner.submit()` from a sync route only *wakes* the async runner;
    the actual DB write can lag by up to the 1s poll interval). One frontend
    call site (`primary-form`, the Connect-to-Primary bootstrap flow) has a
    real, not just cosmetic, dependency on the add having landed — it reads the
    servers list straight from the DB right after adding a brand-new
    environment's first server, and would wrongly report "no primary to
    discover from" if raced — so it alone uses a small `waitForJobDone(jobId)`
    poll before opening the discover modal; every other add/edit/delete call
    site reloads optimistically like `pkgs.*`/`cred.*`, and `PROV_JOB_KINDS` in
    `pollJobs()` reloads both `loadServers()`/`loadFirewalls()` (kind alone
    doesn't say which entity) on the job's real terminal transition. Same turn,
    unrelated to prov.*: `cred.*` jobs' Jobs-tab Env column stopped showing a
    synthetic "Credentials" label and now shows the real environment name, like
    every non-`pkgs.*` kind always has (the Env *filter* dropdown already used
    it).

    **Update, 2026-07-24: `cred.*` no longer queues.** Credential-set add/edit/
    delete now execute **synchronously** inside the request (`services/cred_ops.py`,
    operator-directed) instead of going through `JobRunner.submit()` — a local
    encrypt+DB write with no SSH host involved has no reason to make the operator
    wait on the async queue. A `JobRecord` is still inserted and immediately
    finished (`insert_job` → do the write → `finish_job`) purely for Jobs-tab
    visibility/audit history; there's no PENDING state, no background pickup, no
    `JobCredentialVault` involvement (secrets pass straight through the same call
    stack, never touching `JobRecord.params`). Routes return `200`, not `202`. The
    "existence read decides add vs edit" and "missing-target delete 404s
    synchronously, no job row" conventions above are unchanged — they just also
    apply to the rest of the write now, not only the pre-submit check.
    the real name via `list_job_facets()` — only the rendered column lagged).

    **Update, 2026-08-18: `prov.*` no longer queues either** (operator-reported —
    a `prov.add`/`prov.edit`/`prov.delete` job shared `JobRunner`'s bounded
    concurrency pool with genuinely slow `cpuse.*`/`cdt.*` device jobs, so e.g.
    importing a gateway found by discovery could sit queued behind an unrelated
    server's in-progress JHF install with nothing to do with it). Same
    conversion as `cred.*`/`pkgs.*` before it: `ProvisioningJobService`
    (`services/prov_ops.py`) no longer takes a `runner` and calls
    `EnvironmentManager`/`FirewallManager` directly inside `submit_put_*`/
    `submit_delete_*`, wrapped in the same `_start`/`_succeed`/`_fail` shape as
    `CredentialJobService`. Routes (`/api/environments/{env}/servers` and
    `/firewalls`, add + delete) return `200`, not `202`. Frontend call sites
    (Add/Edit Server/Firewall modals, row-level Remove, and both discovery
    bulk-import loops) now check the returned job's `status` immediately
    instead of only reacting to a network/submit-level failure — a validation
    failure (bad role, name collision) surfaces right there, not just via a
    later Jobs-tab poll. `PROV_JOB_KINDS` in `pollJobs()` is unchanged in
    shape but is now, like `CRED_JOB_KINDS`/`PKGS_JOB_KINDS`, just the "another
    tab/session" fallback rather than the primary way a submitting tab learns
    the outcome. `connect_primary.py`'s own `prov.connect_primary` kind is
    unaffected — it genuinely does SSH + several `mgmt_cli` round-trips and
    stays a real background job.
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
    (events cascade). The archive file keeps a **3-year retention window**
    (age-based, by each entry's `created_at` — not a byte-size cap): every
    append also prunes archive entries older than 3 years, so it never grows
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
    **Native `<select multiple>` click gotcha** (operator-reported, 2026-07-23,
    same day it shipped): a plain click on an `<option>` *replaces* the whole
    selection — Ctrl/Cmd-click is needed to add to it — which isn't obvious
    and made one unmodified click silently filter the Jobs tab down to almost
    nothing, reported as "none of my job history is showing" (the jobs were
    never gone; the DB was untouched). Fixed by intercepting `mousedown` on
    each filter `<select>` and toggling `option.selected` manually, so every
    click behaves like a checkbox regardless of modifier keys.

## Safety still applies to the "manual" mgmt-server flow
Management servers are usually **HA pairs** and JHF installs often reboot. Even in
button-driven mode the tool must warn/gate: never patch both HA members at once,
confirm the peer is healthy first, dry-run/confirm before mutating. See
[[safety-constraints]].
