---
name: mds-discovery-command
description: MDS discovery specifics — correct SSH command for MDS/MLM peers (not the invented $MDSVERUTIL AllMdssInfo), and Global-domain API login for MDS-wide SmartEvent servers
metadata:
  type: project
---

MDS-side discovery in `discovery.py` ([[architecture]]) runs `mdsenv; mdsquerydb MDSs`
over SSH, not `$MDSVERUTIL AllMdssInfo`.

**Why:** `AllMdssInfo` is not a real `mdsverutil` sub-command — it was invented rather
than verified, and failed against a live MDS with `Error: Illegal command
'AllMdssInfo'` (reported 2026-07-21). Checked against Check Point docs
(documentation-tool MCP): `mdsverutil`'s real sub-commands are all
`AllCMAs`/`CMA*`/`MDS*` path/version helpers — none enumerate MDS/MLM peers.
`mdsquerydb`'s `MDSs` key ("Get names and IPs of all MDSs") is the real, documented
way to do it.

**Limitation to remember:** `mdsquerydb MDSs` output is only name + IP — it does
**not** report Primary/Secondary MDS or MLM role. `parse_mdsquerydb_mdss()` can only
infer the primary (the address discovery already connected to); every other peer is
returned as `SECONDARY_MDS` with `needs_review=True` for the operator to reclassify
(could be a Secondary MDS or an MLM). Don't reintroduce keyword-based role guessing
for this path — there's nothing in the output to guess from.

**How to apply:** if MDS discovery is touched again, verify any new command against
the documentation-tool MCP (or a live box) before shipping — this bug shipped because
the original command was assumed, not verified. General lesson: Check Point CLI
surfaces are large and version-dependent; don't guess sub-command names.

**SmartEvent discovery on MDS (added 2026-07-21):** SmartEvent servers shared across
a Multi-Domain deployment live in the **Global domain**, not any one Domain/CMA's
view — `discovery.py`'s `_discover_via_api` now logs into the Management API with
`domain="Global"` when the primary is an MDS role (`ManagementAPIClient` gained a
`domain` constructor kwarg, sent as `"domain"` in the login payload only when set).
This is the best match for the operator-described "global domain" concept per
Check Point's docs, but the Global-domain object list for `show-gateways-and-servers`
wasn't independently confirmed against a live MDS — if it comes back empty or errors
on real gear, that's the first thing to re-verify (same as the `AllMdssInfo` mistake
above: confirm before trusting).
