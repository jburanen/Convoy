---
name: mgmt-api-sms-system-data-domain
description: On a standalone SMS, the bootstrap admin/api-key login must add `--domain "System Data"` — plain `mgmt_cli login -r true` lands in the box's own "Domain" context, where add administrator/add api-key fail with err_inappropriate_domain_type
metadata:
  type: project
---

`render_mgmt_api_commands()` in `services/provisioning.py` (`is_mds=False` path)
now logs in with `mgmt_cli login -r true --domain "System Data" > <sid>` instead
of a bare root login.

**History:** operator-reported (2026-07-25), pasted from a real standalone SMS
(`sms01`, confirmed non-MDS per the [[environment-kind]] invariant — an
environment is never a mix of SMS and MDS hosts):

```
mgmt_cli -s <sid> add administrator name svc-admin authentication-method "api key" permissions-profile "Super User"
code: "err_inappropriate_domain_type"
message: "This command can work only on domains of type MDS. Cannot execute it
in the current domain (current domain type is Domain)."
```

Same failure for the standalone `add api-key admin-name` call. The operator
diagnosed it from direct product knowledge and supplied the fix
(`--domain "System Data"` on login) — this is the same kind of niche
`mgmt_cli` domain-parameter correction as [[mgmt-api-bootstrap-mds-profile]]
and [[mgmt-api-add-api-key-command]], both from the same operator the same
day.

**Why:** without an explicit domain, a root `mgmt_cli login` on this box lands
the session in its own "Domain" context. `add administrator`/`add api-key`
only work in the "System Data" (MDS-type) domain — which exists even on a
non-MDS SMS — so it must be requested explicitly.

**How to apply:** the `is_mds=True` (genuine MDS) login is deliberately left
as a plain root login — not reported broken, and per
[[mgmt-api-bootstrap-mds-profile]] the MDS path is "not yet re-verified
against live MDS gear" anyway. If a future report shows the MDS login needs
`--domain "System Data"` too, add it there rather than assuming it already
does. Don't remove the flag from the SMS path — it's confirmed against real
gear, unlike the MDS command sequence.
