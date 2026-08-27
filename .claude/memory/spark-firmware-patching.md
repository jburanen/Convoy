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

### Real-hardware finding 2026-08-20: point 2 above was incomplete — a timeout with the channel still open is not evidence of anything, and this run's "succeeded" was wrong

A second `lab02-1550` install run got past the stale-mount case entirely —
`mke2fs` fully succeeded (superblocks, journal, inode tables all completed,
no `_STALE_MOUNT_MARKER` text) — then produced no further output once
`tune2fs 1.44.1 (24-Mar-2018)` started, until `_run_upgrade`'s `expect()`
hit its 120s deadline (`_UPGRADE_TIMEOUT`). The job logged "succeeded" per
the existing `except TransportError` handling. **Operator confirmed after
the fact: the device did not install the patch, and never rebooted.**

This is a distinct case from the 2026-08-19 finding's point 2, and the
existing code conflates them. [ssh.py](../../src/convoy/transport/ssh.py)'s
`InteractiveShell.expect()` raises `TransportError` from two different
branches — channel actually reported closed (`self._channel.closed` true),
vs. the client-side deadline just elapsing with the channel still open —
and this run hit the *second* branch (the log said `"timed out waiting for
'...'"`, not `"channel ... closed while waiting"`). `_run_upgrade`'s
`except TransportError` block treats both identically, logging "expected if
the device began rebooting immediately" and letting the job report success
either way. That framing is now confirmed wrong for the timeout branch: the
device was still up on the old image, so the script was either hung on/
after `tune2fs`, or failed silently there with the session never seeing a
prompt again — not rebooting.

**Root cause, confirmed by diffing this run's output against the operator's
re-supplied script source line-for-line (script itself still not retained
anywhere — see below):**

- The two shell errors in this run's capture (`line 579: [: -lt: unary
  operator expected`, `line 615: [: too many arguments`) are both `[ ... ]`
  tests involving `$unitVer` (`unitVer=$(fw_printenv -n unitVer
  2>/dev/null)`), and both line numbers match exactly against the supplied
  source: `if [ $unitVer -lt 2 ]; then` (line 579, inside the `MRV`
  DTB-section-name branch) and `if [ -n "$unitVer" -a $unitVer == "2" ];
  then` (line 615, inside the `unitModel == "V0"` DTB-file-selection
  branch — this device hit *this* branch, confirming it's a V0-model unit).
  Both errors are exactly what bash produces when `$unitVer` expands to
  nothing — i.e. **`fw_printenv -n unitVer` is returning empty on
  `lab02-1550`**. The script has no guard for that; neither `[ ]` call
  aborts the script (no `set -e`), so it silently falls through to the
  `else`/non-"2" branch each time, meaning it picked the plain `v0.dtb`
  over `v0-6393.dtb` without knowing if that's actually correct for this
  unit's hardware revision. This is the same `unitVer` this repo's
  2026-08-19 finding already saw independently blow up *inside preboot.sh*
  on a manual run ("`unitVer` not defined", `rc=-11`) — same underlying
  condition on this device, hit from two different code paths on two
  different attempts. Worth having the operator confirm directly on the
  device (`fw_printenv unitVer`) and loop in Check Point support if it's
  genuinely unset — that's a device/provisioning-level gap this tool has no
  way to fix.
- Initial theory — `mount` or `tune2fs` hanging on stuck partition state,
  needing a power-cycle to clear — **was tested and disproven**: the
  operator rebooted `lab02-1550` first and re-ran the same job, and it
  failed again the same way. That rules out leftover device-side state as
  the cause.
- **Actual root cause, confirmed from the device's own `/logs/upgrade_image`
  after that second failed attempt**: the script logs its own progress via
  `write_log` (see the log-file entry below) — nothing in this tool's SSH
  capture, since those calls don't reach the terminal. That log showed the
  run reaching `tar xzf /storage/pfrm.tgz -C /mnt/inactive` at
  `09:39:47`, only **43 seconds** after the script started at `09:39:04` —
  and then nothing further. `pfrm.tgz` (the new rootfs) was **206,853,336
  bytes** (~197MB) in that run. Extracting ~200MB onto this device's
  embedded flash apparently takes noticeably longer than the
  `_UPGRADE_TIMEOUT` budget remaining at that point (120s total minus the
  43s already spent) — the tool's own deadline was cutting the extraction
  off mid-flight, not catching a genuine hang. Worse: `_run_upgrade`'s
  `finally` block used to unconditionally close the pty-backed shell/client
  on *any* exit, including this one. `open_interactive_shell()` opens a real
  pty (`invoke_shell(term="vt100", ...)`,
  [ssh.py:245-251](../../src/convoy/transport/ssh.py#L245-L251)),
  and `upgrade_revert_image.sh` (and its `tar` child) runs in that same
  pty's foreground — closing the channel almost certainly delivers a
  hangup to it, killing the extraction outright. This is why manual runs
  (operator just waits, no artificial deadline, no forced disconnect)
  succeeded every time while tool-driven runs consistently failed at the
  same point: **the tool itself was killing its own upgrades.**
- **Fixed 2026-08-20**: added `TransportTimeoutError(TransportError)`
  ([errors.py](../../src/convoy/errors.py)) — `InteractiveShell.expect()`
  now raises this specifically for the deadline-elapsed-but-channel-still-open
  case, keeping plain `TransportError` for an actually-closed channel (the
  2026-08-19 finding's case, still untested against real hardware). Bumped
  `_UPGRADE_TIMEOUT` from 120s to 600s. `_run_upgrade` now catches
  `TransportTimeoutError` before the generic `TransportError` handler: it
  no longer closes the shell/client on that path (leaves the SSH session
  connected so a still-running script isn't killed by us) and raises
  `JobError` instead of letting the job report success — we have no
  evidence of the outcome either way, and this tool should fail closed
  rather than claim success it can't back up. The channel-actually-closed
  branch (real hardware still unconfirmed) is unchanged. See
  `test_install_fails_and_leaves_connection_open_on_timeout` in
  `tests/test_spark_patching_service.py` (sibling to
  `test_install_succeeds_when_connection_drops_on_upgrade`, which covers
  the channel-closed case and is also unchanged). A leaked, still-open SSH
  connection on this path is accepted as the lesser cost versus killing a
  live upgrade — expected to be rare now that the timeout has real margin.
- **Log file location, confirmed from source**: for the `upgrade` mode this
  job always uses, the script sets `LOG_FILE=/logs/upgrade_image` up top
  (revert mode instead uses `/logs/revert_image` — not relevant to
  `spark.install`, which always passes `upgrade`). `write_log`'s calls
  throughout the script (e.g. "Preparing storage for image...", "Copying
  data from the image file...", the V1/V1R DTB-section-name lines) go
  *only* to this file, not the terminal — none of that text appears
  anywhere in this tool's SSH capture, which only ever sees raw stdout from
  invoked binaries (`dd`, `mke2fs`, `tune2fs`) plus bare shell errors. This
  is genuinely the more informative record of what the script actually did
  and where it stopped, and worth collecting after any future failed
  attempt, especially since the terminal capture alone couldn't show
  whether `mount` ever returned. `write_log`'s own definition (presumably
  in `image_common.sh`, sourced from `/pfrm2.0/bin/image_common.sh`) is
  still unseen.

The operator re-supplied the full script for this comparison; per the
2026-08-19 note it's still not retained in this repo (vendor source, not
redistributable) — this time saved to the session's local scratch temp dir
only (outside the repo, git-excluded by location, not by a `.gitignore`
rule), not persisted anywhere durable. Ask the operator to re-share again
in a future session if it's needed.

All three require the assigned credential set to carry an expert-mode
password (`CredentialKind.EXPERT_PASSWORD` — see [[credential-sets]] and
[[spark-firewall-credential-scenarios]]) — checked *before* any SSH attempt,
since a Spark firewall's assigned set isn't guaranteed to have one just
because the Spark credential modal enforces it at creation time (a set
could have been reassigned since).

## `spark.install` now verifies the outcome instead of guessing at it (operator-directed 2026-08-20)

The two 2026-08-20 findings above (a plain timeout ≠ evidence of anything;
this tool's own SSH capture can't see `/logs/upgrade_image`) led the
operator to redesign the whole install job around actually confirming the
result, rather than inferring it from `upgrade_revert_image.sh`'s own
session. `_run_upgrade` no longer tries to judge success/failure from what
it observes issuing the command — it just issues it, watches (without
force-closing the channel on a plain timeout, per the earlier fix), and
always returns normally except for the one specific already-confirmed-bad
case (`_STALE_MOUNT_MARKER`, still an immediate hard fail — see above).
`_do_install` then runs a definitive check no matter which of the three ways
`_run_upgrade` ended (prompt reappeared, channel closed, or timed out with
the channel still open and deliberately left connected):

1. Wait (`InteractiveShell.wait_for_close()`, a new primitive alongside
   `expect()` — same channel-open-vs-closed distinction, but waiting for a
   disconnect instead of a pattern) for the scheduled reboot to close the
   session, bounded — if it never does (e.g. the script actually failed
   without ever scheduling one), close the session itself (safe: the script
   has already exited by this point) and proceed anyway rather than hang.
2. Poll TCP-connect reachability on the SSH port (`_default_probe_reachable`
   — deliberately *not* ICMP `ping`: this tool's container has no
   `CAP_NET_RAW`/suid ping binary, and the slim base image doesn't even ship
   one) until the host responds.
3. Retry a full SSH reconnect (sshd can come up slightly after the host
   starts accepting TCP connects on the same port).
4. Run `fw ver` and compare its "Build NNN" against the *installed package
   filename's own* trailing build digits (operator-specified: compare the
   **last 3 digits** of each — `_image_build_suffix`/`_fw_ver_build_suffix`
   in `spark_patching.py`) — only a match is a confirmed SUCCEEDED. Checked
   *before* touching the device at all: if the package filename doesn't
   match the expected `..._<digits>.img` convention, the job fails closed
   immediately rather than run an upgrade it can never verify.

This means the same code path resolves every outcome correctly regardless of
*why* `_run_upgrade` couldn't tell what happened: if the script actually
failed without rebooting, the device stays reachable the whole time and
`fw ver` simply still reports the old build — caught by step 4 without
needing any more script-output text-matching (the project's `_STALE_MOUNT_
MARKER`-only doctrine, above, still holds — no new markers were added). A
confirmed build mismatch is `JobError` (FAILED); giving up at the ping or
reconnect stage without ever finding out is `JobTimedOut` (TIMED_OUT, not
FAILED — same "not a terminal verdict" semantics as `PatchingService`'s
import-verify polling) — this distinction matters operationally: FAILED
means "confirmed bad," TIMED_OUT means "still don't know, go check."
Timeouts/poll intervals for each stage are constructor params on
`SparkPatchingService` (`ping_timeout`, `reconnect_timeout`, etc. — same
convention as `PatchingService`'s `import_verify_attempts`/`_delay`), not
bare module constants, specifically so tests can shrink them instead of
sleeping real minutes.

**Live status while this runs**: `JobRecord.status_text` (new column,
migration v25) + `JobContext.set_status()` (`jobs.py`) is a single
overwritten "what's happening now" field, independent of the append-only
event log — the Jobs tab's Output column (`app.js` `renderJobRow`) shows it
live while a job is pending/running (`"connecting"` → `"installing"` →
`"waiting for reboot"` → `"waiting for firewall to respond to ping"` →
`"reconnecting over SSH"` → `"verifying installed build"`), falling back to
the terminal success/error text once the job finishes, same as before. Job
kinds that never call `set_status()` (everything except `spark.install` so
far) just show blank while running, unchanged from before this existed.

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
