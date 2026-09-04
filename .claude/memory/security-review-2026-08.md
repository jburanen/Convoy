---
name: security-review-2026-08
description: The 2026-08-26 independent security review — what was fixed, what was deliberately declined, and why
metadata:
  type: project
---

An independent agentic security review (2026-08-26) of all of `src/` produced 4
Critical, 9 High, 14 Medium and ~10 Low findings — the v1 milestone
"Independent agentic code security review". Every claim was re-verified against
the code before acting; the report was accurate except for the two corrections
below. Phase 1 shipped in **v0.70.0**.

**Why this file exists:** the declined items look like oversights to anyone
reading the code later. They were decisions. Don't silently "fix" them without
revisiting the reasoning.

## Report corrections (don't re-raise these)
- **The "unquoted shell interpolation" findings are not exploitable.** The six
  sites (`pkg_repo_ops.py` x2, `cdt_ops.py`, `common.py`'s `sha1sum`,
  `patching.py` x2) genuinely lack `shlex.quote()`, but each interpolates
  `posixpath.join(<module constant>, package)` where `package` already passed
  `PackageStore._check_filename` via a `path_for()` earlier in the same
  function. Real hygiene defect, latent not live. Still worth quoting (Phase 3).
- **The ".dockerignore is missing" finding is simply wrong** — the file exists
  and is thorough.

## Shipped in v0.70.0 (Phase 1)
- **C1, the one live RCE:** Spark `submit_install` never validated the
  caller-supplied filename (only a `.img` suffix check) before it reached
  `upgrade_revert_image.sh <path> upgrade safe` in an expert-mode root pty.
  Fixed with `packages.check_filename()` at the boundary **plus**
  `shlex.quote()` at the sink. Deliberately `check_filename()`, **not**
  `path_for()`: install runs against a file already staged on the device, which
  may legitimately have aged out of the local package store, so presence isn't
  required — safety is. `packages._check_filename` was made public for this.
  Note `InstallRequest.package_id` was deliberately left unconstrained: it is
  shared with the CPUSE install route, where identifiers legitimately contain
  spaces (see [[cpuse-package-id-shell-safety]]).
- **C2:** `run-script` resolves targets by **name** against the management
  server's own object DB, so bootstrap could push a uid-0 `adminRole` account
  onto any SIC-trusted firewall sharing a name. `_confirm_target_identity()` now
  resolves via `show-gateways-and-servers` and asserts the address matches the
  inventory row, failing closed on unknown/ambiguous/addressless objects.
- **C3:** `inventory.Host` had no validation at all despite a comment in
  `environments.py` claiming it did. `address` is now IP-or-hostname validated,
  `ssh_port` range-checked, names/addresses stripped and length-capped.
  Separately, `connect-primary` repointing an *existing* server to a different
  address now needs `confirm_address_change` (`add_server` is an upsert — it
  silently redirected stored credentials and all future jobs).
- **H1:** SSH host keys are now pinned. `transport/ssh.py` gained a
  module-level `known_hosts` path (set once in `create_app`, lives on `/data`),
  a custom `_PinningPolicy` (paramiko's `AutoAddPolicy` rewrites the whole file
  from its in-memory copy and can lose a concurrent pin — a lost pin silently
  re-TOFUs), `HostKeyChangedError`, and `forget_host_key()`. TOFU on first
  contact, hard fail on change **before any credential is sent**. Recovery is
  `POST /api/environments/{env}/hosts/{name}/accept-host-key` (confirm-gated)
  plus an "Accept New Host Key" link on both tables' state rows.
- **H3/H4/H5:** startup warning while admin/admin is still live
  (`BasicAuthenticator.uses_default_password` — checks the env default AND the
  absence of a DB-persisted change); persistent per-username **and**
  per-source-IP login throttle (`LoginThrottle`, store migration **v28**
  `login_attempts`, 5 free attempts then exponential backoff capped at 15 min,
  swept by the existing session reaper); and `BASIC_AUTH_DISABLE` alone no
  longer runs the app open — it needs `CONVOY_ALLOW_NO_AUTH` too, otherwise
  the login gate stays up with a warning (fail closed). **tests/conftest.py sets
  both**, since the suite deliberately runs auth-off.
- **M13:** a password change now revokes every other session for that user
  (`Store.delete_sessions_for_user`) and re-issues the caller's own cookie.
- **Docs truth pass:** `snapshot_before_install`, `stop_on_first_failure`,
  `reboot_after_install` and `maintenance_window` were **deleted** from
  `config.py` and `config.example.yaml` — nothing ever read them, so operators
  could believe a rollback snapshot was being taken. Re-add them only with the
  code that honours them. README's Safety model now says plainly that
  cluster-aware ordering is operator-supplied via the CDT candidates list, not
  tool-enforced, and documents the flat-privilege model.

## Deliberately NOT implemented (operator decisions)
- **Management API TLS verification stays off** (`mgmt_api.py`
  `verify_tls=False`). Operator's call, 2026-08-26: Check Point management
  servers ship self-signed certs. **Recorded caveat:** self-signed does not mean
  unverifiable — pinning that specific cert would still stop an on-path attacker
  capturing the API key. Revisit if that trade changes; don't "fix" it silently.
- **Cluster-awareness / health gating (C4) is docs-only for now.** CDT fleet
  deploy is a v2 milestone. `Orchestrator.assert_cluster_safe` remains dead
  code, `HealthChecks` remains stubbed, and `clusterxl.py` still fails **open**
  (an unparseable local-member row reads as "not a cluster member"; `ACTIVE(!)`
  counts as healthy). Fix `clusterxl.py` when a health gate actually consumes
  it — pull forward if v2 slips.
- **RBAC (H9) documented, not built.** Auth is LDAP-group with several
  engineers, so this is a real gap, not theoretical — every group member has
  full destructive authority over every environment. Two-tier viewer/operator is
  a v2 design item. README and `.env.example` now say so explicitly.
- **Config path containment declined** — `config.yaml` is operator-supplied with
  no API to write it, and a containment check would break the legitimate
  absolute-path (`/data/...`) setup.
- **CSRF token declined** — `SameSite=Strict` + `HttpOnly` is adequate and there
  are no reachable XSS sinks. Security headers are the better spend (Phase 3).
- **`/api/status`'s archive path stays** — a deliberate feature (the Jobs tab
  hint names the path), authenticated-only.
- **No `127.0.0.1` port bind** — would break browser access with no reverse
  proxy in the compose stack.

## Done since (outside the Phase 1 batch)
- **M9 shipped in v0.72.1.** `cpuse.py` no longer issues `lock database
  override` before every call. Read-only queries override nothing at all
  (verified on live gear: Gaia prints CLINFR0771 and answers anyway); the
  mutating path uses `transport/ssh.py`'s `run_breaking_config_lock`, which
  overrides only after an observed refusal and logs who held it. See
  [[gaia-shell-posture]].

## Phase 2 shipped in v0.73.0
- **H6, all four leaks.** Pty transcripts run through `scrub_transcript()`
  before entering any exception (they reach job.error, job_events, the archive
  AND the browser). The mgmt_cli session id moved from one fixed
  `/tmp/convoy_mgmt_api.sid` to a per-run unguessable path created under
  `umask 077` and removed in a `finally` (`new_api_session_file()`);
  `reveal-api-key` became a POST scoped to `job.username`; `_redact` matches
  key **substrings**, so `script` / `password-hash` / `new-password` /
  `session-id` are covered — `script` was the sharp one, since the bootstrap
  run-script payload carries a `password-hash $6$...`.
- **H7.** `ensure_host_free` now guards all four `cdt_ops` submits and
  `pkg_repo_ops.submit_push_to_repo`; both services took a `Store` for it.
- **M8.** The full-Gaia bootstrap preview renders `REDACTED_HASH` instead of a
  real one (`render_gaia_user_commands(..., redact_hash=True)`); the push
  computes the real value. **The Spark preview deliberately still renders a
  real hash** — it is display-only with no automated push, so the operator has
  to paste it; eliding it would just break the feature. Rounds stay at 5000:
  raising them makes passlib emit a `rounds=` directive, and whether Gaia's
  `set user password-hash` accepts that form is unverified.
- **M14.** `bootstrap-credentials` and `api-access/repair` take a
  `ConfirmRequest` body; both UI paths already had confirm modals, the server
  just wasn't enforcing it.
- **H8 / M11.** `deploy.sh` refuses to run as root (it feeds `DEPLOY_UID` into
  compose's `user:`, so `sudo ./deploy.sh` silently ran the container as uid 0).
  Compose gained `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit`,
  `pids_limit`. Still deliberately NOT `read_only` (the app writes /data and
  /tmp) and NOT a loopback port bind (no reverse proxy in this stack).
- Also folded in: the mgmt-API "TLS verification disabled" note went from
  `logger.debug` to `logger.warning` — an accepted posture nobody can see is
  one nobody can reconsider.

## Phase 3 shipped in v0.74.0 — the review is now closed
- **M1**: all six `shlex.quote()` sinks quoted (never reachable; hygiene).
- **M2**: `cdt.py` rejects `..` segments in paths CDT runs as root (the
  allowlist permitted dots, so `/opt/CPcdt/../../tmp/evil.sh` matched).
  `_check_id` gained control-character and length checks. It deliberately does
  **NOT** reject glob/brace characters, which a denylist review suggests:
  nothing there reaches a bash word-expansion context (expert mode
  `shlex.quote`s the whole clish command; clish mode goes straight to clish,
  which does not glob), so adding them would only reject legitimate CPUSE
  names — the same mistake the old allowlist made with spaces.
- **M4**: uninstall no longer treats an EMPTY package list as proof of
  removal — absence only means something once we have a list we actually
  parsed. Spark build confirmation compares the full common suffix of the two
  ids instead of a fixed three digits (`builds_match`), refusing to confirm on
  under three digits of overlap. Full ids can't be compared: `fw ver` reports
  a truncated form of what the .img filename carries.
- **M5**: install-log read bounded at the source (`head -c N`, was `cat` then
  truncate); mgmt-API paging bounded via `_paged_objects` (page + object caps,
  non-numeric `total` is an error not an unhandled ValueError, non-advancing
  page ends the loop); `hfconfig._read_capped` caps the two metadata member
  reads that ran unbounded on every upload.
- **M6**: wall-clock deadlines on both `_poll_task` loops and on the install
  poll's "uncapped" branch (which drops its attempt budget on purpose so a long
  install isn't cut off — but no budget must not mean no limit, or one wedged
  install pins a JobRunner slot forever). `raise_if_cancelled()` added to the
  import/install/uninstall polls, so **Cancel actually works** mid-poll.
- **M7**: upload filename validated BEFORE staging (it was checked only inside
  `add_stream`, i.e. after two full writes of a GB-scale file); `Content-Length`
  ceiling (`MAX_UPLOAD_BYTES`, env-overridable) re-enforced while streaming
  since the header is client-supplied; free-space precheck, because /data also
  holds the DB and job archive.
- **Low**: security-headers middleware (CSP/X-Frame-Options/nosniff/
  Referrer-Policy, HSTS only over real HTTPS) — registered AFTER the auth guard
  so it wraps it and the 401s get headers too; a strict CSP is safe because the
  pages carry no inline script/style/handlers (verified — if one ever appears,
  this is what breaks, and the fix is to move the code to a .js file, not to
  loosen the policy). `JobContext.log()` honours its `level` (job failures were
  emitted at INFO and so never reached `docker compose logs`). `JobRunner`
  retrieves completed task exceptions. `api-access/diagnose` gained
  `_require_env` and stopped returning `raw_output` nothing consumed.
  `/api/jobs` capped at `MAX_JOBS_PAGE`.

**Everything not listed as shipped was a decision, not an omission — see
"Deliberately NOT implemented" above.**
