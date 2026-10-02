---
name: bootstrap-run-with-existing-login
description: Bootstrap panel's "Log in and run for me" — temporary existing login, never stored, chains bootstrap → Connect to Primary → Discover; unvalidated on live gear
metadata:
  type: project
---

Added 2026-10-02 (v1.4.0, operator-requested). Alternative to pasting the
Bootstrap panel's clish commands: the operator types an existing Gaia login once
and Convoy runs the commands over SSH (`services/mgmt_bootstrap.py`, job kind
`prov.bootstrap_mgmt`, route `POST /api/environments/{env}/bootstrap-mgmt`).

**The temporary login must never be persisted** (operator's hard requirement):
not to the credential store, job params, logs, or errors, in either storage
mode. Server side it lives in the shared `JobCredentialVault`; the new account's
rendered commands (password hash) live in the service's own in-memory map. Both
are purged by web/app.py's `job_finished` hook for every terminal state,
including cancel-before-run. `require_ok()` is deliberately NOT used there: its
message embeds the raw command (hash) and becomes `job.error`. Errors and logs go
through `redact()`. Browser side, `bootstrapFlow` (app.js) holds it only for one
flow and is cleared on finish, failure, any cancel, Reset, and env switch; it
never touches localStorage or the session credential cache.

**Why the stored set is never used:** the account being created is the one the
set holds, so it cannot be what logs in. `connector.connect(host, bundle)` with
an explicit bundle bypasses the store regardless of storage mode.

**Flow (operator-specified):** Run in the modal → bootstrap the primary → Connect
to Primary's own preview modal (pre-filled, the new set selected) → API-key
reveal → Discover modal (primary preselected) → on Import, a confirm offers to
run the same bootstrap on the picked servers (port 22) before importing. Each
step's own Cancel ends the flow. Cancel handlers check the modal is actually open
because the app-wide Escape handler calls every close function.

**Storage-enabled needs the expert password up front** — Connect to Primary logs
in from the saved set, which `put_set` refuses without one. Building this also
fixed Connect to Primary in storage-disabled environments: its Run never sent
inline credentials, so it could not succeed from the UI; it now uses
`operationCredentials()`.

**Config lock (operator-directed):** a command Gaia refuses with CLINFR0771 is
retried once after `lock database override`, via the shared
`run_breaking_config_lock` (override only on an observed conflict, like CPUSE
installs — never pre-emptively). It gained a `display=` kwarg so its structlog
warning logs the redacted command, not the hash.

**Unvalidated against live gear:** whether a lock taken in one SSH exec session
lets the next command's session through, and the exact refusal output. An
existing account fails `add user`; reported, not worked around. The target needn't be in inventory (transient `Host`); host
keys still TOFU-pin by address. See [[gaia-shell-posture]], [[provisioning-command-order]],
[[optional-credential-storage]], [[ui-dialogs-convention]].
