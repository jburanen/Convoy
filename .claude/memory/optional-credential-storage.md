---
name: optional-credential-storage
description: Per-environment credential storage is optional; disabled envs use in-memory-only per-job credentials
metadata:
  type: project
---

Credential storage is a **per-environment** choice (`environments.credential_storage_enabled`,
schema migration v6). New UI-created environments default to **disabled**; config-seeded
ones default to **enabled** to preserve prior behaviour.

**Enabled** → the encrypted [[security-hygiene]] `CredentialStore`, which since
migration **v8** stores **named "login sets"** rather than per-host secrets (see
[[credential-sets]]).

**Disabled** → nothing is persisted. Every SSH-backed request supplies credentials
inline (`credentials: [{kind, username?, secret}]`):
- **Jobs** stash them in the in-memory `JobCredentialVault` (credentials.py) keyed by
  job id, dropped the instant the job ends via `JobRunner(on_job_finished=vault.discard)`
  (guaranteed in `_run`'s finally, even on cancel-while-queued). Race-free: creds are
  vaulted *before* `runner.submit(job_id=...)` makes the job claimable.
- **Sync queries** (detect, CDT status/candidates) use them one-shot and never store them.

**Where the wiring lives:**
- `HostConnector.require_credentials(host, provided)` — the gate: enabled → check store,
  return None (connect resolves from store); disabled → validate provided, return the bundle.
- `services/common.py::submit_host_job` / `job_run_credentials` — shared submit + handler helpers.
- Disabled envs don't need a master key at all (never touch the store).
- Toggling storage **off** purges that env's stored credentials (like env delete does).

**API shape:** live-state reads are **POST** (state, cdt/status, cdt/candidates/read) so a
secret body can ride along. Toggle: `POST /api/environments/{env}/credential-storage {enabled}`.
UI: toggle in Manage Environments modal; a credential-prompt modal fires before any SSH
action in a disabled env.

**Client-side session cache** (app.js `credCache`): opt-in "Remember for this tab (15 min)"
checkbox in the prompt. Lives ONLY in a JS `Map` — never localStorage/sessionStorage, never
the server — so it dies on tab close/reload. Keyed by env+host, TTL 15 min, evicted when an
action using it fails (wrong/stale password self-heals), cleared on storage toggle / env
delete / rename and via the header "Forget now" note. It does not change the server contract:
the backend still holds credentials in memory only for the life of each job.
