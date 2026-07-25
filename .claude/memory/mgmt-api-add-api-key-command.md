---
name: mgmt-api-add-api-key-command
description: The bootstrap API-key admin needs a separate `add api-key admin-name <name>` call — `add administrator ... authentication-method "api key"` only sets the auth method, it doesn't issue a key. No `api restart` needed either.
metadata:
  type: project
---

`render_mgmt_api_commands()` in `services/provisioning.py` runs `mgmt_cli add
api-key admin-name <username> --format json` in the same session, right after
`add administrator`, before `publish`. The operator (2026-07-24) pointed at the
official CLI reference (`add-api-key` v2.1, sc1.checkpoint.com Management API
docs) to correct this — `add administrator ... authentication-method "api
key"` only sets the administrator's auth *method*; it does not generate a key.
The key value is only produced (and printed once, in JSON) by the separate
`add api-key` command, run against an admin created earlier in the same
uncommitted session (session-scoped visibility is why it works before
`publish`).

The operator also said the trailing `api restart` in the rendered script is
unnecessary — removed. Neither `add administrator` nor `add api-key` needs a
service restart to take effect.

**Why:** the bootstrap script would have created an administrator whose auth
method was API key but which had no actual key attached — the JSON output the
UI told the operator to copy from (`add administrator`'s output) never
contained one.

**How to apply:** `MGMT_API_NOTES` in `provisioning.py` now attributes the
"copy the key from JSON output" instruction to `add api-key`, not `add
administrator`. If this script's command sequence changes again, keep `add
api-key` after `add administrator` and before `publish`, in the same `-s <sid>`
session. See [[mgmt-api-bootstrap-mds-profile]] for the related MDS
`multi-domain-profile` fix shipped the same day.
