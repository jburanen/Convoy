---
name: mds-discovery-command
description: MDS discovery specifics — mdsquerydb MDSs must run via a login shell (bash -lc), and Global-domain API login for MDS-wide SmartEvent servers (confirmed working)
metadata:
  type: project
---

MDS-side peer discovery in `discovery.py` ([[architecture]]) runs
`bash -lc "mdsquerydb MDSs"` over SSH — a **login shell**, not a bare exec, and
not `$MDSVERUTIL AllMdssInfo`.

**History (all against the operator's live MDS `townhall`, 2026-07-21):**
1. Shipped as `$MDSVERUTIL AllMdssInfo` — invented, not verified. Failed:
   `Error: Illegal command 'AllMdssInfo'`. `mdsverutil`'s real sub-commands are
   all `AllCMAs`/`CMA*`/`MDS*` path/version helpers; none enumerate MDS/MLM peers.
2. Switched to `mdsenv; mdsquerydb MDSs` (per docs-tool guidance that `mdsenv`
   must run first). Also failed — same symptom as step 3 below, since the real
   problem wasn't `mdsenv` at all.
3. Switched to bare `mdsquerydb MDSs`. **Still failed** ("MDS enumeration
   returned no data" — nonzero exit, empty output) even though the operator
   confirmed the identical command works instantly when typed into an
   interactive Expert SSH session.
4. Root cause found: our SSH transport runs commands via a plain
   `exec_command` — a **non-login** shell. Gaia's MDS environment (PATH to
   `mdsquerydb`, `MDSDIR`, etc.) is set up by profile scripts that only run for
   *login* shells. Interactively you always get a login shell, so it "just
   works"; over automation you don't, so the binary isn't found (or resolves to
   nothing), and both `mdsenv` and `mdsquerydb` were victims of the same issue —
   not a bad command name at all. Fixed by wrapping in `bash -lc "..."` to force
   login-shell semantics for this one command.

**Limitation to remember:** `mdsquerydb MDSs` output is only name + IP — it does
**not** report Primary/Secondary MDS or MLM role. `parse_mdsquerydb_mdss()` can only
infer the primary (the address discovery already connected to); every other peer is
returned as `SECONDARY_MDS` with `needs_review=True` for the operator to reclassify
(could be a Secondary MDS or an MLM). Don't reintroduce keyword-based role guessing
for this path — there's nothing in the output to guess from.

**How to apply:** the documentation-tool MCP got this wrong three times running
(command name, required prefix, and it never surfaced the real login-shell/PATH
issue at all — that only came from the operator pasting the actual UI warning
and comparing interactive vs. automated behavior). For MDS-specific CLI
behavior over SSH, the fastest reliable signal is "does it work when I paste it
into an interactive session vs. through the tool" — that contrast is what
actually found this bug. If any other MDS/SSH command mysteriously "returns no
data" despite working by hand, suspect the same login-shell/PATH gap first
and reach for `bash -lc "..."` before inventing a new command name.

**SmartEvent discovery on MDS — confirmed working (2026-07-21 → 2026-07-22):**
SmartEvent servers shared across a Multi-Domain deployment live in the
**Global domain**, not any one Domain/CMA's view — `discovery.py`'s
`_discover_via_api` logs into the Management API with `domain="Global"` when
the primary is an MDS role (`ManagementAPIClient` has a `domain` constructor
kwarg, sent as `"domain"` in the login payload only when set). The operator
confirmed this actually finds the SmartEvent server on real gear — this part
did not need a second round.
