---
name: mds-discovery-command
description: MDS discovery specifics — a plain SSH exec on Gaia loads none of the Check Point environment (not PATH, not $MDSDIR); locate MDSDIR via filesystem glob instead of trusting any env var. Global-domain API login for MDS-wide SmartEvent servers (confirmed working)
metadata:
  type: project
---

MDS-side peer discovery in `discovery.py` ([[architecture]]) locates the MDS
install directory via a filesystem glob (`/opt/CPmds-R*`) and exports
`$MDSDIR` itself before invoking `scripts/mdsquerydb MDSs` — it does not
trust *any* pre-set environment variable, including `$MDSDIR`.

**History (all against the operator's live MDS `townhall`, R82.10) — six
rounds to get right:**
1. (2026-07-21) Shipped as `$MDSVERUTIL AllMdssInfo` — invented, not verified.
   Failed: `Error: Illegal command 'AllMdssInfo'`. `mdsverutil`'s real
   sub-commands are all `AllCMAs`/`CMA*`/`MDS*` path/version helpers; none
   enumerate MDS/MLM peers.
2. (2026-07-21) Switched to `mdsenv; mdsquerydb MDSs` (per docs-tool guidance
   that `mdsenv` must run first). Failed the same way as step 3 — but note:
   we never actually saw *why* it failed, because the generic warning at the
   time didn't surface stderr/exit status. This mattered later (see step 6).
3. (2026-07-21) Switched to bare `mdsquerydb MDSs`. **Still failed** ("MDS
   enumeration returned no data") even though the operator confirmed the
   identical command works instantly in an interactive Expert SSH session.
   Hypothesized: non-login shell skips profile scripts that populate `PATH`.
   "Fixed" by wrapping as `bash -lc "mdsquerydb MDSs"` — unverified.
4. (2026-07-22) **`bash -lc` did not fix it** — same generic warning, still
   deployed. The login-shell theory was never confirmed against real data.
5. (2026-07-22) Asked the operator for `which mdsquerydb; env | grep -i mds`.
   Got real output: `mdsquerydb` at `/opt/CPmds-R82.10/scripts/mdsquerydb`,
   `MDSDIR=/opt/CPmds-R82.10`. **Mistake**: that command was run at an
   already-open interactive Expert prompt, not through a real non-interactive
   SSH exec (the one command that *did* try to simulate our tool's exec
   failed at the SSH protocol layer with a MAC error, unrelated, before
   reaching a shell — and got glossed over). I treated interactive-session
   env output as if it described the automated session, assumed `$MDSDIR`
   would carry over the same way `$MDSVERUTIL` seemed to, and shipped
   `$MDSDIR/scripts/mdsquerydb MDSs` without ever confirming `$MDSDIR` is set
   in the actual automated session. It wasn't.
6. (2026-07-22) **Root cause finally confirmed from the real failure itself**:
   added stderr/exit-status surfacing to the warning (see below), re-ran, and
   got: `/ngvsx/lib/libngvsx.sh: line 5: cpprod_util: command not found` /
   `bash: /scripts/mdsquerydb: No such file or directory`. The second line
   proves `$MDSDIR` expanded to **empty** in the automated session (the path
   that ran was `/scripts/mdsquerydb`, not `/opt/CPmds-R82.10/scripts/...`).
   The first line shows a system script (`libngvsx.sh`) *does* run
   automatically even in this non-interactive exec, but it itself can't find
   `cpprod_util` — meaning essentially **no** Check Point environment (not
   `PATH`, not `$MDSDIR`, not base utilities) is present in this session.
   Fix: stop depending on any pre-set env var. Locate the MDS install dir via
   `ls -d /opt/CPmds-R* 2>/dev/null | head -1` (versioned, so no hardcoded
   path) and `export MDSDIR` ourselves before invoking the script.

**The real lesson from round 5→6, not just "verify against live gear":**
directly-observed diagnostic output is only trustworthy for the exact
execution context you're actually fixing. An `env` dump from an interactive
Expert SSH session does **not** describe what a non-interactive
`paramiko.exec_command` sees, even on the same box, same account. When
asking an operator to gather diagnostics, be explicit that the comparison
command must run the same way the tool does (non-interactive, single exec,
no pty) — and if a "simulate the tool" attempt fails for an unrelated reason
(here: an SSH MAC error), don't quietly fall back to the interactive result
as a stand-in. That substitution is exactly what caused round 5 to ship wrong.

**Limitation to remember:** `mdsquerydb MDSs` output is only name + IP — it does
**not** report Primary/Secondary MDS or MLM role. `parse_mdsquerydb_mdss()` can only
infer the primary (the address discovery already connected to); every other peer is
returned as `SECONDARY_MDS` with `needs_review=True` for the operator to reclassify
(could be a Secondary MDS or an MLM). Don't reintroduce keyword-based role guessing
for this path — there's nothing in the output to guess from.

**Diagnostics are now built in:** `_discover_mds_via_ssh` surfaces the actual
exit status and stderr in the warning on failure (not a generic message) —
if this command is wrong *again*, the next warning should already say why
without another round-trip asking the operator to gather more logs.

**How to apply:** don't theorize about Gaia shell/profile semantics — every
theory here (bad command name, missing `mdsenv`, non-login shell, PATH not
loaded but env vars are) felt plausible and was wrong or only partially
right. Prefer commands that depend on nothing but the filesystem (globs,
absolute-path discovery) over anything requiring a specific shell
invocation mode or environment variable to be pre-populated. And per the
lesson above: any diagnostic gathered to fix this must come from an actual
non-interactive SSH exec, not an interactive comparison session.

**SmartEvent discovery on MDS — confirmed working (2026-07-21):**
SmartEvent servers shared across a Multi-Domain deployment live in the
**Global domain**, not any one Domain/CMA's view — `discovery.py`'s
`_discover_via_api` logs into the Management API with `domain="Global"` when
the primary is an MDS role (`ManagementAPIClient` has a `domain` constructor
kwarg, sent as `"domain"` in the login payload only when set). The operator
confirmed this actually finds the SmartEvent server on real gear — this part
did not need a second round.
