---
name: clusterxl-live-state
description: How live ClusterXL role/name is detected and shown on the Firewalls panel (clusterxl.py, added 2026-07-23)
metadata:
  type: project
---

The Firewalls panel's status line shows a live ClusterXL role prefix
("Active member of ..." / "Standby member of ...", green/orange) when a
refresh detects the host is a cluster member.

- Detection: `CPUSE.cluster_state()` runs `show cluster state` and
  `clusterxl.parse_cluster_state()` parses it (new module, mirrors
  `cpuse.py`'s parsing style). Best-effort — a failed/unparseable command is
  treated as "not a cluster member," never raised, since this is a display
  add-on to `PatchingService.detect()`/`_refresh_state()`, not a gate.
- **"Cluster name" is NOT the SmartConsole cluster object name** — Check
  Point doesn't expose that via CLI on the member itself (confirmed against
  Check Point's docs). It's a stand-in: every member hostname `show cluster
  state` lists, comma-joined (operator-chosen tradeoff, 2026-07-23, over
  adding a manual "cluster name" field to the firewall record).
- Cached on `ServerStateRow.cluster_role`/`cluster_name` (store schema v18;
  same cache row type is shared by servers and firewalls, so both `/servers`
  and `/firewalls` endpoints carry these fields even though only the
  Firewalls panel currently renders them).
- Distinct from `checks.py`'s `HealthChecks.cluster_state` (still
  `NotImplementedError`) — that one is deployment-gating (pass/fail against
  an *expected* role), a different consumer with different requirements.

See [[cdt-cpuse-domain]] for the broader CPUSE/CDT context.
