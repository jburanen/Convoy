---
name: mgmt-api-bootstrap-mds-profile
description: The bootstrap Management API admin uses multi-domain-permissions-profile (not permissions-profile) when the target environment is MDS
metadata:
  type: project
---

`render_mgmt_api_commands()` in `services/provisioning.py` takes an `is_mds` flag.
A Multi-Domain Server has no single-domain `permissions-profile` object of its
own — a global administrator (what estate-wide discovery needs) is granted via
the separate `multi-domain-permissions-profile` parameter to `mgmt_cli add
administrator` instead, even though the built-in profile is named the same
("Super User") in both places. Confirmed via the Check Point docs tool
(2026-07-24), not against live MDS gear.

**Why:** the bootstrap flow's Management API admin previously always used
`permissions-profile "Super User"`, which is the single-domain form — wrong
for a Multi-Domain environment's global admin.

**How to apply:** `web/app.py`'s `ProvisionRequest.is_mds` is client-supplied
(the JS sends `envIsMds[currentEnv]`) rather than looked up server-side — the
`/api/provision` endpoint is pure rendering and never reads the store, per
[[environment-kind]]'s `is_mds` pattern. If a future change makes this endpoint
store-aware, prefer reading `environments.is_mds` directly over trusting the
client value.
