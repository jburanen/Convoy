---
name: gaia-shell-posture
description: Universal clish-login-plus-on-demand-expert posture for every Gaia host (not just Spark), the GaiaSession transport, the file-transfer shell-toggle maneuver, and the credential enforcement it required
metadata:
  type: project
---

Added 2026-08-24 (operator-directed). Spark (Gaia Embedded) firewalls already
operated this posture — SSH lands in clish, elevate to `expert` only for the
specific commands that need it (see [[spark-firmware-patching]]). Every other
Gaia host (management servers, CPUSE-patched firewalls, CDT-driven gateways)
worked the opposite way: `services/provisioning.py` set `/bin/bash` as the
service account's **login** shell, so a plain SSH connect already landed at
a root-equivalent prompt — no elevation, no expert password ever required.
This generalizes the Spark posture to every host.

## `GaiaSession` (transport/ssh.py)

Replaces bare `SSHClient` as the `Transport`/`CommandRunner`
`default_client_factory` (services/common.py) returns for every non-Spark
Gaia host. Spark's own SSH plumbing (services/spark_patching.py) is separate
and already correct — unaffected, though `GaiaSession` still exposes
`open_interactive_shell()`/`put_scp()` passthroughs so Spark's code (which
also goes through `connector.connect()`) keeps working unchanged.

- **Shell detection** (lazy, cached, one probe per connection): `echo
  <token>` over a bare `exec_command()`. A clish-default account rejects
  `echo` as an unrecognized clish verb (non-zero exit, no echoed token) →
  `GaiaShell.CLISH`; an already-bash account runs it and echoes the token →
  `GaiaShell.EXPERT`. **Unvalidated against real full-Gaia hardware** — the
  exact clish error shape for an unrecognized command is a guess; the
  detection logic only cares whether the token comes back verbatim at rc 0,
  which should be robust regardless.
- **`run()`** (clish-native — CPUSE's only use): bare passthrough to
  `SSHClient.run()`. `cpuse.py` needed **zero changes** — it already formats
  the wire string itself based on the `GaiaShell` it's constructed with
  (`_clish()`'s existing bare-vs-`clish -c` logic, now fed a live-detected
  value instead of a static default). A bare clish command against a
  clish-default account, and a `clish -c "..."` string against a bash-default
  account, are both today's already-confirmed-working paths — `GaiaSession`
  doesn't change how either is sent, only which `GaiaShell` gets chosen.
- **`run_bash()`** (new — every call site that used to assume direct bash
  access): passthrough if already-`EXPERT`; if `CLISH`, lazily opens an
  interactive shell and escalates via `GaiaExpertSession.enter_expert()`
  **exactly once per session** (sticky — `self._elevated`), then routes every
  subsequent bash-native command through `GaiaExpertSession.
  run_expert_command()` (new: wraps `run_expert()` with a `; echo
  __CHKP_ORCH_RC__:$?` sentinel + parse, since `run_expert()` only ever
  returned text — Spark's own text-scanning use of it is unchanged). Raises
  `CredentialError` up front if no expert password is available. Every
  formerly-bare-bash `client.run(...)` call site across the codebase (CDT —
  `cdt.py`'s every verb, since CDT is never clish-native; `services/
  patching.py`'s `df`/`sha1sum`/`cat`; `services/connect_primary.py` and
  `services/api_access.py`'s `mgmt_cli`/`api status`/`api restart`;
  `services/discovery.py`'s MDS enumeration; `services/cdt_ops.py` and
  `services/pkg_repo_ops.py`'s `stat`/`rm`) now calls `run_bash()` instead.
- **`put()`** — the hard case. Gaia's SFTP/SCP subsystem needs a genuinely
  bash-shell session; a clish login can't serve it (this is *why*
  provisioning used to set `/bin/bash` as the login shell in the first
  place). Operator-specified maneuver for a clish-default account: run `set
  user <username> shell /bin/bash` + `save config` (still clish at this
  point), close the connection (the shell change only takes effect on a
  fresh session), reconnect (now bash), transfer, then — **always, even on
  failure** — `clish -c "set user <username> shell /etc/cli.sh"` + `clish -c
  "save config"` on that same connection, close it, and reconnect the
  session's primary connection so the `GaiaSession` stays usable afterward
  either way. A restore failure raises `GaiaShellRestoreError`
  (`errors.py`, a `TransportError` subclass) — deliberately never swallowed,
  since it means a production account is left on a standing bash shell,
  defeating the whole point. An already-bash account (operator-supplied
  pre-existing admin, or an account provisioned before this change) skips
  all of this — `put()` is a bare passthrough, today's exact behavior,
  unchanged. **Caught via test-writing, fixed same day**: the first cut only
  resumed the primary connection on the success path — a failed transfer
  left `self._ssh` pointing at an already-closed client, breaking the
  session for anything the caller did next (logging, closing it again). The
  resume now happens unconditionally in the innermost `finally`.
- Backward compatible by construction: an account that's already
  bash-default (today's existing provisioning, or an operator-supplied
  pre-existing admin account) never touches any of the detection/elevation/
  toggle machinery — every method short-circuits to today's exact behavior.
  No forced re-provisioning of already-deployed service accounts.

**Unvalidated against real hardware this session** (no gear available,
same posture as the Spark work — see [[spark-firmware-patching]]): the
shell-detection probe, the `run_expert_command` exit-status marker, and the
whole file-transfer shell-toggle maneuver. Flagged in code comments at each
site; check these first if something misbehaves.

## `services/provisioning.py`

`render_gaia_user_commands` no longer sets `shell /bin/bash` — the generated
`set user <username> gid 100` clish command drops the shell clause entirely,
leaving the account on Gaia's own default (clish). `render_bootstrap_script`
(Management API `run-script`, always executes as bash regardless of login
shell — a different mechanism) and `render_spark_admin_commands` are
unaffected. `PROVISIONING_NOTES` now also flags that Gaia's `expert`
password is a single device-wide secret (`set expert-password`), not tied to
any one OS account.

## Credential enforcement — two different rules, deliberately asymmetric

**Storage-enabled**: `CredentialStore.put_set()` (credentials.py) now
requires an expert-mode password on **every** credential set, flat —
alongside the existing SSH-secret xor-check. Since every stored host is a
management server or a firewall ([[credential-sets]]'s `Role` enum has no
other category), and every set already required an SSH secret, this single
store-level rule covers "each mgmt server and firewall" without any
per-role branching. Replaces the old Spark-only opt-in `require_expert`
flag (`CredentialSetIn.require_expert`, the synchronous 422 check in
`web/app.py`'s `put_credential_set`) — both removed as dead code; Spark's
credential-scenario UI flow (`saveSparkCredential`) is otherwise unchanged,
it just no longer needs to pass a now-meaningless flag. A set created before
this shipped simply can't be saved again (add/edit) without an expert
password being added — no forced migration, no backfill attempt (nothing to
decrypt). `index.html`'s `cs-expert` field label dropped "(optional)" and is
now required client-side too.

**Storage-disabled**: the opposite policy — only *prompt* for an expert
password on job kinds that actually escalate, not blanket. A plain CPUSE
`detect`/refresh, `cpuse.import_cloud`, and `cpuse.uninstall` never touch
bash at all (pure clish `installer`/`show` verbs), so requiring an expert
password there would be pure friction. `HostConnector.require_credentials()`
/ `submit_host_job()` both gained a `require_expert: bool = False` param,
set `True` at each call site that needs it (`cpuse.import`/`install`, every
CDT job, `prov.connect_primary`, `pkgs.push_to_repo`, all three Spark job
kinds — Spark already had its own `_require_expert_password` check, now
promoted to a shared `services/common.py::require_expert_password()`
Spark still calls, deduplicated not behaviorally changed). On the frontend,
`operationCredentials()`/`promptCredentials()` gained a `needsExpert` param
threading through to each call site — the `#cred-modal`'s `cm-expert` field
(already existed, was never enforced) is now required and auto-expanded
when the operation needs it.

**A real behavior change worth knowing about**: for storage-enabled
environments, a missing expert password on an assigned set now fails
*synchronously at job submission* (`require_credentials` raises
`CredentialError` directly), not as a queued-then-failed job — this is
symmetric with how a missing SSH secret already worked, but Spark's own
three job kinds used to defer this check to inside the job handler
(`_require_expert_password`, called after the job had already been queued
and started running). Existing Spark tests expecting "job runs then shows
FAILED" for this case were rewritten to expect a synchronous raise instead
— see `tests/test_spark_patching_service.py`.

## Where the wiring lives

- `transport/ssh.py`: `GaiaShell` (moved here from cpuse.py — a transport
  concept, not a CPUSE one), `GaiaExpertSession.run_expert_command()`,
  `GaiaSession`, `_restore_clish_shell()`.
- `errors.py`: `GaiaShellRestoreError(TransportError)`.
- `services/common.py`: `default_client_factory` builds `GaiaSession`
  instead of bare `SSHClient`; `Transport` protocol gained `run_bash` and a
  `shell` property; `require_expert_password()` (promoted from
  spark_patching.py); `HostConnector.require_credentials`/
  `require_ssh_credential` gained `require_expert`.
- `credentials.py`: `CredentialStore.put_set()`'s new required-field check.
- `web/app.py` / `index.html` / `app.js`: `CredentialSetIn.require_expert`
  removed; `cs-expert` field required; job-time `#cred-modal` `needsExpert`
  threading.
- `tests/test_gaia_session.py`: `GaiaSession` unit tests against a scripted
  fake `SSHClient` (shell detection both branches, lazy single-elevation,
  the transfer toggle-and-restore maneuver success/failure/restore-failure
  paths) — monkeypatches `chkp_cpuse_orch.transport.ssh.SSHClient` so
  `GaiaSession._new_client()` picks up the fake.
