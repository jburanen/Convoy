---
name: mds-discovery-command
description: MDS discovery specifics — correct SSH command for MDS/MLM peers (not the invented $MDSVERUTIL AllMdssInfo), and Global-domain API login for MDS-wide SmartEvent servers
metadata:
  type: project
---

MDS-side discovery in `discovery.py` ([[architecture]]) runs plain `mdsquerydb MDSs`
over SSH — **no `mdsenv` prefix** — not `$MDSVERUTIL AllMdssInfo`.

**Why (round 1):** `AllMdssInfo` is not a real `mdsverutil` sub-command — it was
invented rather than verified, and failed against a live MDS with `Error: Illegal
command 'AllMdssInfo'` (reported 2026-07-21). Checked against Check Point docs
(documentation-tool MCP): `mdsverutil`'s real sub-commands are all
`AllCMAs`/`CMA*`/`MDS*` path/version helpers — none enumerate MDS/MLM peers.
`mdsquerydb`'s `MDSs` key ("Get names and IPs of all MDSs") is the real, documented
way to do it.

**Why (round 2):** the docs tool also claimed `mdsenv` had to run first, so the
command shipped as `mdsenv; mdsquerydb MDSs`. That broke too — the operator's own
live MDS (`townhall`) returned exit-status nonzero for the chained form (surfaced
in the UI as "MDS enumeration returned no data"), while running bare
`mdsquerydb MDSs` in an Expert SSH session worked immediately, returning
`name<TAB>IP` rows. The account's shell already has the MDS environment loaded
(same reason `$MDSVERUTIL` alone resolved before) — `mdsenv` was never needed and
likely misbehaves under a non-interactive `exec_command` (no pty). Fixed
2026-07-21 by dropping the prefix entirely; confirmed against live gear this time,
not just docs.

**Limitation to remember:** `mdsquerydb MDSs` output is only name + IP — it does
**not** report Primary/Secondary MDS or MLM role. `parse_mdsquerydb_mdss()` can only
infer the primary (the address discovery already connected to); every other peer is
returned as `SECONDARY_MDS` with `needs_review=True` for the operator to reclassify
(could be a Secondary MDS or an MLM). Don't reintroduce keyword-based role guessing
for this path — there's nothing in the output to guess from.

**How to apply:** the documentation-tool MCP got this command wrong twice in a row
(the command name itself, then the `mdsenv` prefix) — for MDS-specific CLI/API
behavior, treat its answers as a *hypothesis to test on live gear*, not a fact to
ship. Ask the operator to run the exact command and paste the real output/exit
behavior before trusting a fix here. General lesson: Check Point CLI surfaces are
large and version-dependent; don't guess sub-command names or required
setup steps.

**SmartEvent discovery on MDS (added 2026-07-21):** SmartEvent servers shared across
a Multi-Domain deployment live in the **Global domain**, not any one Domain/CMA's
view — `discovery.py`'s `_discover_via_api` now logs into the Management API with
`domain="Global"` when the primary is an MDS role (`ManagementAPIClient` gained a
`domain` constructor kwarg, sent as `"domain"` in the login payload only when set).
This is the best match for the operator-described "global domain" concept per
Check Point's docs, but the Global-domain object list for `show-gateways-and-servers`
still hasn't been confirmed against a live MDS — given the docs tool was wrong twice
on the SSH side of this same feature, treat `domain="Global"` as equally suspect
until the operator confirms it actually returns SmartEvent servers (or reports the
real error if it doesn't).
