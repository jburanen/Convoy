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
(`spark.scp`), and the only place bashUser gets turned back off. **install**
(`spark.install`) is a separate, later job: SSH in, `expert`,
`upgrade_revert_image.sh <path> upgrade safe`, which reboots the device on
its own a minute or two later — it does NOT repeat `bashUser off` (removed
2026-08-19, same day as the split below; it was a leftover from when
transfer+install were one combined job and turning it off was the last step
before the upgrade command, not two independent jobs each responsible for
their own device-state cleanup). Split into two jobs 2026-08-19 (operator-
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
  undone or cancelled after the fact). **Cannot fully confirm the upgrade
  actually completed** — Spark has nothing like CPUSE's `show installer
  package` to poll — success mostly just means the command was issued and
  returned control, *except* one specific case it does fail closed on: see
  "Real-hardware finding" below. A `TransportError` raised specifically
  while waiting on `upgrade_revert_image.sh`'s output is treated as an
  expected outcome, not a failure — though per that same finding, a
  dropped connection is actually the *less* likely of the two ways this
  command normally ends (see below). On success it drops the filename
  from `installable` again — best-effort UI hygiene, not a confirmed-
  uninstalled guarantee, same caveat as above.

### Real-hardware finding 2026-08-19: a normal return isn't a success signal, and reboot timing was wrong

An install run against `lab02-1550` returned "job succeeded" after output
ending in `mke2fs 1.44.1 ... /dev/mmcblk1p6 is mounted; will not make a
filesystem here! ... tune2fs 1.44.1 (24-Mar-2018)`, while manually running
the identical command moments later got much further (full `mke2fs`
success, filesystem creation, then a *different*, later failure inside
`preboot.sh`: `"unitVer" not defined`, `rc=-11`). The operator supplied
Check Point's actual `upgrade_revert_image.sh` source for comparison
(not committed to this repo — vendor script, can't be redistributed here;
ask the operator if you need to see it again). Two things it revealed,
neither a truncated-capture artifact — `expect()` only returns once the
literal prompt reappears, so the tool's session genuinely got everything
the device sent:

1. **The mount conflict likely wasn't fatal to the script**, which is worse
   than it failing outright. `mount_pfrm_inactive_part()` runs `mke2fs`,
   then unconditionally runs `tune2fs`, then runs `mount` — and checks
   *`mount`'s* exit status, not `mke2fs`'s. If the partition's already
   mounted (a stale mount from an earlier, incomplete attempt on the same
   device — plausible operational history, not something this tool caused
   directly), `mke2fs` refuses but the subsequent `mount` likely succeeds
   as a no-op, so the function returns success and the script proceeds to
   extract the new rootfs onto a partition that was never reformatted.
   Fixed: `_run_upgrade` now scans the captured output for `mke2fs`'s own
   fixed refusal text (`_STALE_MOUNT_MARKER`, e2fsprogs wording, not a
   Check Point string) and raises `JobError` — job reported FAILED, not
   SUCCEEDED — telling the operator to reboot the firewall to clear the
   stale mount before retrying. This is the one specific case the job can
   detect; anything else Check Point's script might do wrong internally is
   still invisible to us.
2. **The "wait for the connection to drop, that means it's rebooting"
   framing was wrong.** `quit_upgrade_revert_image()` — the script's single
   exit function, called on both success and failure — *schedules* the
   reboot (writes a DB flag, default `rebootTime` ~60s out) and then exits
   immediately; it does not wait for the reboot itself. So the SSH session
   returning control normally is the *expected* outcome on success, not
   evidence against it — the actual reboot happens up to ~60s later,
   asynchronously, well after this tool has already disconnected. Fixed:
   reworded `_run_upgrade`'s log messages away from "the firewall will
   reboot in ~1-2 minutes, this job cannot wait for that" (implying we're
   the ones giving up early) to reflect that the script itself returns
   before the reboot on every path, success included.

Do not add further success/failure text-scanning beyond `_STALE_MOUNT_MARKER`
without new real-hardware evidence for each specific string — `mke2fs`'s
message is safe to match because it's a well-known third-party tool's fixed
wording, not a guess at this vendor script's internal, unseen conventions
(`write_log`/`output_error`'s exact terminal-visibility is still unknown —
`image_common.sh`, which defines them, hasn't been seen).

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
