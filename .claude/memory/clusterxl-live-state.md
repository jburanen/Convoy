---
name: clusterxl-live-state
description: How ClusterXL role (live) and cluster name (static) are detected and shown on the Firewalls panel
metadata:
  type: project
---

The Firewalls panel's status line shows a ClusterXL prefix ("Active in
`<cluster>`" / "Standby in `<cluster>`", green/orange) when a firewall is a
cluster member. Role and name come from two different places and update on
different triggers — this split was deliberate (operator-directed,
2026-07-23, superseding an earlier same-day design where both were
re-derived from `cphaprob` on every refresh):

- **Role** (`ServerStateRow.cluster_role`, e.g. "ACTIVE(!)", "STANDBY") is
  *live* — refreshed every time the table's per-row Refresh runs (`detect()`
  calls `CPUSE.cluster_state()`, which runs `show cluster state` and parses
  it via `clusterxl.parse_cluster_state()`). Best-effort: an unparseable or
  failing check is just "not a cluster member," never raised.
- **Name** (`FirewallRow.cluster_name`, store schema v19) doesn't change
  refresh-to-refresh, so it's resolved once and stored on the firewall
  record itself, not re-derived on every check:
  - At **discovery time**: `DiscoveryService._discover_firewalls_via_api`
    calls the Management API's `show-simple-clusters` (new
    `ManagementAPIClient.show_simple_clusters`) in the same session as
    `show-gateways-and-servers`, and `find_cluster_for_gateway()` matches
    each discovered gateway against a cluster's `members` list (tolerant of
    both string and `{"name": ...}` member shapes — the real shape isn't
    confirmed against live gear). This is the *real* SmartConsole cluster
    object name. The discover-firewalls import flow threads it through
    `FirewallIn.cluster_name` → `submit_put_firewall` → `_do_put`, which
    applies it **only when `ctx.job.kind == JOB_ADD`** — an ordinary edit
    never sends this field, and the kind gate means even a caller mistake
    can't clobber a previously-detected name (see
    `test_cluster_name_is_never_applied_on_a_later_edit`).
  - Via the **Firewalls panel's edit-modal "Re-check cluster membership"
    button** (`POST .../firewalls/{name}/cluster-recheck`): prefers
    `DiscoveryService.find_cluster_name()` (Management API, no SSH); falls
    back to `PatchingService.check_cluster_membership()` (live
    `cphaprob`/SSH — same mechanism as the role check, but standalone) only
    if the API path finds nothing (no primary configured, no credentials,
    older management version, or an MDS domain that isn't tracked
    per-firewall today). Always persists what it finds, including clearing a
    stale name back to `None` if the host is no longer clustered.
- `Store.set_firewall_cluster_name` is a **targeted UPDATE**, deliberately
  separate from `upsert_firewall` (mirrors `assign_firewall_credential_set`)
  — `upsert_firewall` must never touch this column, or every ordinary
  add/edit would wipe out a previously-detected name.
- `ServerStateRow.cluster_name` (store schema v18) was **removed** the same
  day it shipped, once this design landed — `cluster_role` stayed there
  (still live), the name moved to `FirewallRow`.
- The Management API path can't resolve a cluster name for MDS environments
  during a post-hoc re-check (no Domain/CMA is tracked per-firewall) — it
  works at discovery time only, since discovery already has the operator-
  picked Domain in scope. The re-check button silently skips straight to the
  SSH fallback there.
- Distinct from `checks.py`'s `HealthChecks.cluster_state` (still
  `NotImplementedError`) — that one is deployment-gating (pass/fail against
  an *expected* role), a different consumer with different requirements.

See [[cdt-cpuse-domain]] for the broader CPUSE/CDT context.
