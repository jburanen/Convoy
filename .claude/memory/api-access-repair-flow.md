---
name: api-access-repair-flow
description: services/api_access.py diagnoses/repairs a Management API 403 over SSH, triggered proactively right after Connect to Primary succeeds — a confirm-gated, narrow exception to "this tool doesn't auto-manage API access settings"
metadata:
  type: project
---

A Management API 403 (during estate discovery or elsewhere) almost always
means the API isn't started, or its `accessibility` setting is
`require-local` (loopback only). `services/api_access.py` offers an
SSH-based diagnose (`api status`, read-only) and repair (`mgmt_cli
set-api-settings accessibility "minimize"` + publish + `api restart`) for
the second case.

**Trigger point: right after Connect to Primary succeeds**, not the
discover-servers modal (where this first shipped 2026-07-25, then moved same
day). The web UI (`app.js`'s `checkApiAccessAfterConnect`) calls
`POST .../api-access/diagnose` automatically the moment a connect-primary
job finishes — proactively confirming the API it just provisioned is
actually reachable, instead of leaving a broken accessibility setting to
surface later as a confusing 403 during discovery. The repair itself stays
confirm-gated: a "Repair over SSH" button only appears when restricted, and
opens a preview-then-confirm modal (`api-access-repair-confirm-modal`,
styled after `connect-primary-confirm-modal`) before
`prov.repair_api_access` actually runs.

**Why this isn't a contradiction of the 2026-07-20 decision** (commit
`c6d8ca3`, see `test_provisioning.py::test_mgmt_api_commands_single_session_and_api_key`'s
"the API-settings change was removed — the operator manages that
separately") to drop `set api-settings accepted-api-calls-from` from
`render_mgmt_api_commands`: that decision was about not silently folding an
API-accessibility change into the single mgmt_cli session Connect to
Primary already runs (login → add administrator → add api-key → publish →
logout). This flow is a deliberately separate diagnose call and a
separate job (`prov.repair_api_access`, its own SSH connection, its own
confirm dialog) — the *check* is proactive/automatic, but the *write* is
never bundled into the provisioning command sequence itself and never runs
without the operator reviewing the preview and clicking Run.

**How to apply:** don't fold `render_repair_commands`'s commands into
`render_mgmt_api_commands`/`PrimaryConnectService._do_connect`'s own mgmt_cli
session, and don't remove the preview+confirm step from the repair job —
either would reintroduce exactly what the 2026-07-20 change deliberately
removed. The diagnose *call* itself running automatically (no click needed)
is fine and intentional; it's read-only.
