---
name: spark-firmware-patching
description: Spark (Gaia Embedded) firmware transfer+upgrade via upgrade_revert_image.sh — interactive expert-mode SSH primitive; transfer (spark.scp) and install (spark.install) are separate, independently-triggered jobs
metadata:
  type: project
---

Spark (Quantum Spark / Gaia Embedded) firewalls don't go through CPUSE or CDT
— they patch via SCP + expert-mode shell commands instead (operator-specified
sequence, 2026-08-19): SSH in, `expert`, `bashUser on`, exit expert, log out;
SCP a `.img` firmware file to `/storage`, verify it, then SSH back in,
`expert`, `bashUser off` again — that's the whole **transfer** job
(`spark.scp`). **install** (`spark.install`) is a separate, later job: SSH
in, `expert`, `bashUser off` (idempotent — already off from transfer, done
again here regardless since install doesn't assume transfer ever ran),
`upgrade_revert_image.sh <path> upgrade safe`, which reboots the device on
its own a minute or two later. Split into two jobs 2026-08-19 (operator-
reported: the Firewalls panel's "Upload and import" button was firing the
upgrade too, when it should only stage the file — see "The three jobs"
below). Implemented in `services/spark_patching.py` (`SparkPatchingService`),
following the same job/service shape as [[patching-web-design]]'s CPUSE
path.

## Why a new SSH primitive was needed

`SSHClient.run()` (`transport/ssh.py`) uses Paramiko's `exec_command()`,
which spawns a fresh, non-interactive shell per call — it can't see or
answer the `expert` command's interactive password prompt, or hold "we're
now in bash" across subsequent commands. `InteractiveShell` (a pty-backed
session via `invoke_shell()`, send/expect-style) and `GaiaExpertSession`
(the Gaia-specific prompt vocabulary layered on top) were added to the same
module to fill that gap. `GaiaExpertSession` is the *only* place that
encodes Gaia's actual prompt text/regexes.

## Two assumptions, both now confirmed against real hardware

No live Spark box was available to test against when this shipped, so two
guesses had to ship without confirmation — both deliberately isolated
behind narrow interfaces so a wrong guess is a contained fix, not a rewrite
of the job's sequencing:

1. **SFTP vs SCP.** The firmware upload originally reused `SSHClient.put()`
   (Paramiko's SFTP subsystem) unchanged, on the assumption Spark's SSH
   server exposed it in whichever `bashUser` state. **Confirmed wrong
   2026-08-19** — a real `spark.scp` run against live hardware
   failed at the transfer phase with `TransportError: SFTP upload to
   <host>:<path> failed: Channel closed`; `bashUser on`'s own banner had
   only ever said "SCP access enabled," never SFTP. Fixed the same day by
   adding `SSHClient.put_scp()` (`transport/ssh.py`) — the classic SCP sink
   protocol spoken directly over `exec_command("scp -t ...")` (control line
   `C0644 <size> <name>\n`, single-byte 0x00/0x01/0x02 acks, no third-party
   `scp` dependency) — and pointing `_transfer_image()` at it instead of
   `put()`. The Gaia CPUSE import path (`patching.py`) still calls `put()`
   unchanged; SFTP is confirmed working there.
2. **`expert` prompt text.** `GaiaExpertSession`'s `_PASSWORD_PROMPT`,
   `_EXPERT_PROMPT`, `_LOGIN_PROMPT` regexes are first guesses. **Confirmed
   correct 2026-08-19** — a direct probe (constructing `SSHClient` +
   `GaiaExpertSession` by hand, no orchestrator job/inventory involved) logged
   into a live Spark firewall as `admin`, ran `enter_expert()`, and got a
   clean match on `_EXPERT_PROMPT`, then `exit_expert()` matched
   `_LOGIN_PROMPT` cleanly too. No mutating command was run.

Both are called out in code comments at their definition site.

## The three jobs

- `spark.testcred` — SSH login + `expert` escalation, nothing more.
  Never runs a mutating command, so no confirmation gate; safe to run
  repeatedly. Surfaced as a "Test Credentials" link on every Spark row in
  the Firewalls panel (not reactive-after-failure like the Gaia bootstrap
  link — shown proactively).
- `spark.scp` — SCP the `.img` to `/storage`, nothing else. No confirmation
  gate: it doesn't reboot anything, same as CPUSE's plain import. This is
  what the Firewalls panel's "Upload and import to selected" button fires
  for a `.img` package selection (`app.js`'s `fw-bulk-import-btn` handler →
  `POST .../spark-import` → `submit_transfer`). On success it records the
  filename into the host's `ServerStateRow.installable` — the *same* cache
  field CPUSE hosts populate from a live `show installer packages ...`
  query, except here it's this tool's own bookkeeping of what it staged
  (Spark has no equivalent query to ask the device). That's what makes the
  filename show up in the row's Install picker (`renderInstallSelect`,
  previously CPUSE-only — the picker/button widget itself needed no
  changes, only what feeds it).
- `spark.install` — `upgrade_revert_image.sh <path> upgrade safe` against a
  `.img` expected to already be staged in `/storage` by a prior transfer
  (not re-checked at submit time — same trust-the-picker posture as CPUSE's
  own install). This is the row's "Install" button/endpoint
  (`POST .../install`, shared with CPUSE-patched firewalls — `web/app.py`'s
  `firewall_install` dispatches on `host_role()` the same way the `/state`
  endpoint already did for Refresh). Requires `confirmed=True` (the device
  reboots on its own once the upgrade command is issued — that can't be
  undone or cancelled after the fact). **Cannot confirm the upgrade
  actually completed** — Spark has nothing like CPUSE's `show installer
  package` to poll — the job's success only means the command was issued; a
  `TransportError` raised specifically while waiting on
  `upgrade_revert_image.sh`'s output is treated as an expected outcome (the
  device may drop the connection mid-reboot), not a failure. On success it
  drops the filename from `installable` again — best-effort UI hygiene, not
  a confirmed-uninstalled guarantee, same caveat as above.

All three require the assigned credential set to carry an expert-mode
password (`CredentialKind.EXPERT_PASSWORD` — see [[credential-sets]] and
[[spark-firewall-credential-scenarios]]) — checked *before* any SSH attempt,
since a Spark firewall's assigned set isn't guaranteed to have one just
because the Spark credential modal enforces it at creation time (a set
could have been reassigned since).

## Package/firewall compatibility filtering (Firewalls panel only)

`packages.py`'s `package_kind(filename)` (`.img` → `"spark_image"`,
`.tar`/`.tgz`/`.tar.gz` → `"archive"`) is mirrored by hand in `app.js` as
`packageKind()` — deliberately not a stored field or API response field,
just a filename-extension check computed on both sides. The Firewalls
panel's bulk package `<select>` and row checkboxes mutually constrain each
other by kind (`setFirewallRowLock`/`applyFirewallPackageFilter`/
`applyFirewallRowLockFromPackage` in `app.js`) — picking a `.img` package
only allows selecting Spark rows and vice versa, and picking a row first
locks the package picker to match. The Management Servers panel's
equivalent selectors are untouched (separate element ids, separate
`loadServers()` code path).

## Refresh (`detect`) is Spark-specific too

Added 2026-08-19. Firewalls-panel Refresh (`POST /api/env/{env}/firewalls/
{name}/state`) used to always call `PatchingService.detect()`, which issues
CPUSE-only queries (`show installer status build`/`show installer packages
...`/`show cluster state`) — meaningless on Spark, which has no CPUSE agent.
The web handler (`web/app.py`'s `firewall_state`) now checks the host's role
first (`PatchingService.host_role()`, a plain inventory lookup, added so the
handler can pick a service *before* committing to either one's host-
resolution/credential path) and routes Spark rows to
`SparkPatchingService.detect()` instead — a synchronous method mirroring
`PatchingService.detect()`'s shape (not a job), that runs plain `fw ver`
over a bare SSH exec (no `expert` escalation — unvalidated against real
hardware, same caveat as the two above) and truncates the banner
(`spark_patching.parse_fw_ver()`): `"This is Check Point's 1550 Appliance
R81.10.17 - Build 892"` → `"1550 Appliance R81.10.17 - Build 892"`. Both
detect() methods persist into the same `ServerStateRow` cache table, so the
response-building code after the branch is shared; Spark rows just get
`jhf`/`agent_build`/`cluster_role` = None written there instead of real
values. `installable` is the one field Spark's `detect()` does *not* reset —
it carries forward whatever a transfer job already staged (see "The three
jobs"); `detect()` used to always build a fresh `ServerStateRow`, which
silently wiped that list on every Refresh until fixed 2026-08-19 alongside
the transfer/install split. `installed` stays `[]` — Spark has no uninstall
concept. `app.js`'s `renderStateRow()` takes a
new `isSpark` param (Firewalls-panel call sites only — Servers are never
Spark) and shows just the truncated `fw ver` text instead of the
"Running X w/JHF Y | CPUSE Agent Z" line, which doesn't apply here.

## Shared helpers extracted for this

`services/common.py` gained `ensure_host_free` (promoted from
`PatchingService._ensure_host_free`, now a free function both services
call), `ProgressReporter` (moved from `patching.py`, still re-exported from
there for `cdt_ops.py`/`pkg_repo_ops.py`'s existing imports),
`remote_sha1`/`verify_uploaded_file` (extracted from `patching.py`'s
`_do_import`), and `HostConnector.spark_firewall_host()` (stricter than
`patchable_host()` — fails closed on any non-Spark role, since these
expert-mode commands are meaningless elsewhere).
