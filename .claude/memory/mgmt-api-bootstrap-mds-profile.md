---
name: mgmt-api-bootstrap-mds-profile
description: The bootstrap Management API admin uses multi-domain-profile "Multi-Domain Super User" (not permissions-profile "Super User") when the target environment is MDS
metadata:
  type: project
---

`render_mgmt_api_commands()` in `services/provisioning.py` takes an `is_mds` flag.
A Multi-Domain Server has no single-domain `permissions-profile` object of its
own — a global administrator (what estate-wide discovery needs) is granted via
the separate `multi-domain-profile` parameter to `mgmt_cli add administrator`
instead, with its own distinctly-named built-in profile: `"Multi-Domain Super
User"` (not just "Super User").

**History:** the docs-tool (2026-07-24) first answered `multi-domain-permissions-profile`
with profile name "Super User" (same name as the SMS profile) — shipped as v0.44.1.
The operator corrected both the key (`multi-domain-profile`, no `-permissions`) and
the value (`"Multi-Domain Super User"`, a distinctly-named profile) from direct
product knowledge, immediately after. Fixed same day, not yet re-verified against
live MDS gear.

**Why:** the bootstrap flow's Management API admin previously always used
`permissions-profile "Super User"`, which is the single-domain form — wrong
for a Multi-Domain environment's global admin.

**How to apply:** don't trust the docs-tool's answer on `mgmt_cli` parameter
names/values as final for niche multi-domain syntax — treat it as a first draft
pending operator confirmation. `web/app.py`'s `ProvisionRequest.is_mds` is
client-supplied (the JS sends `envIsMds[currentEnv]`) rather than looked up
server-side — the `/api/provision` endpoint is pure rendering and never reads
the store, per [[environment-kind]]'s `is_mds` pattern. If a future change makes
this endpoint store-aware, prefer reading `environments.is_mds` directly over
trusting the client value.
