---
name: mds-discovery-command
description: MDS discovery specifics — mdsquerydb must be called via its $MDSDIR-relative path (not PATH), and Global-domain API login for MDS-wide SmartEvent servers (confirmed working)
metadata:
  type: project
---

MDS-side peer discovery in `discovery.py` ([[architecture]]) runs
`$MDSDIR/scripts/mdsquerydb MDSs` over SSH — called by its **$MDSDIR-relative
path**, not the bare command name, and not via `PATH` at all.

**History (all against the operator's live MDS `townhall`, R82.10):**
1. (2026-07-21) Shipped as `$MDSVERUTIL AllMdssInfo` — invented, not verified.
   Failed: `Error: Illegal command 'AllMdssInfo'`. `mdsverutil`'s real
   sub-commands are all `AllCMAs`/`CMA*`/`MDS*` path/version helpers; none
   enumerate MDS/MLM peers.
2. (2026-07-21) Switched to `mdsenv; mdsquerydb MDSs` (per docs-tool guidance
   that `mdsenv` must run first). Failed the same way as step 3.
3. (2026-07-21) Switched to bare `mdsquerydb MDSs`. **Still failed** ("MDS
   enumeration returned no data" — nonzero exit, empty output) even though the
   operator confirmed the identical command works instantly when typed into an
   interactive Expert SSH session. Hypothesized: non-login shell skips profile
   scripts that populate `PATH`. Fixed (believed) by wrapping as
   `bash -lc "mdsquerydb MDSs"`.
4. (2026-07-22) **`bash -lc` did not fix it either** — same warning, still
   deployed. The login-shell theory was wrong (or incomplete): whatever adds
   `mdsquerydb` to `PATH` apparently isn't triggered by login-shell semantics
   alone (Gaia's expert-mode environment setup may be conditioned on genuine
   interactivity, not just `-l`, or wired to the actual `expert` transition
   from clish rather than any bash invocation mode).
5. (2026-07-22) **Root cause found from real data, not another theory**: asked
   the operator to run `which mdsquerydb; env | grep -i mds` on the live box.
   Result: `mdsquerydb` resolves to `/opt/CPmds-R82.10/scripts/mdsquerydb`, and
   `MDSDIR=/opt/CPmds-R82.10` — i.e. the script is at exactly
   `$MDSDIR/scripts/mdsquerydb`. `$MDSDIR` is the same env var `$MDSVERUTIL` is
   built from (`$MDSDIR/system/shared/MDSVerUtil`), which has resolved in our
   SSH session since the very first version of this feature (that's *why*
   `$MDSVERUTIL AllMdssInfo` in step 1 got as far as "Illegal command" instead
   of "not found"). So `$MDSDIR` was never the missing piece — `PATH` was, and
   the fix is to stop depending on `PATH` at all: call the script by its
   `$MDSDIR`-relative path directly. Dropped the `bash -lc` wrapper — it's
   unnecessary now.

**Limitation to remember:** `mdsquerydb MDSs` output is only name + IP — it does
**not** report Primary/Secondary MDS or MLM role. `parse_mdsquerydb_mdss()` can only
infer the primary (the address discovery already connected to); every other peer is
returned as `SECONDARY_MDS` with `needs_review=True` for the operator to reclassify
(could be a Secondary MDS or an MLM). Don't reintroduce keyword-based role guessing
for this path — there's nothing in the output to guess from.

**How to apply:** this took *four* rounds to get right, and the first three were
all guesses (docs-tool speculation, then my own "login shell" theory) that felt
plausible but weren't verified against real data — each shipped anyway and each
was wrong. What actually worked was asking the operator to run `which <cmd>` and
`env` on the live box and reading the literal output. For any future "works by
hand, not through the tool" report on Gaia/MDS: **don't theorize about shell
modes — ask for `which <command>` and the relevant env vars first**, and prefer
calling scripts by an absolute or env-var-relative path over depending on `PATH`
resolution at all, since `PATH` is evidently the least reliable part of a Gaia
non-interactive SSH session.

**SmartEvent discovery on MDS — confirmed working (2026-07-21):**
SmartEvent servers shared across a Multi-Domain deployment live in the
**Global domain**, not any one Domain/CMA's view — `discovery.py`'s
`_discover_via_api` logs into the Management API with `domain="Global"` when
the primary is an MDS role (`ManagementAPIClient` has a `domain` constructor
kwarg, sent as `"domain"` in the login payload only when set). The operator
confirmed this actually finds the SmartEvent server on real gear — this part
did not need a second round.
