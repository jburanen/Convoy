---
name: clusterxl-live-state
description: How ClusterXL role (live) and cluster name (static, Management-API-only) are detected and shown on the Firewalls panel
metadata:
  type: project
---

The Firewalls panel's status line shows a ClusterXL prefix ("Active in
`<cluster>`" / "Standby in `<cluster>`", green/orange) when a firewall is a
cluster member. Role and name come from two different places and update on
different triggers — this split was deliberate (operator-directed,
2026-07-23, superseding an earlier same-day design where both were
re-derived from `cphaprob` on every refresh).

**Cluster *name* resolution is Management-API-only, never SSH** (operator
correction, 2026-07-23, superseding the same-day cphaprob-fallback design
below the fold): Check Point doesn't expose the SmartConsole cluster
object's own name over the CLI on the member itself — `show cluster state`
only lists member hostnames, not the configured cluster name — so no SSH
command could ever answer this, and trying is a dead end, not a fallback.
`PatchingService.check_cluster_membership` (the SSH/cphaprob path) was
removed. The Firewalls panel's edit-modal "Re-check via Management API"
button now only calls `DiscoveryService.find_cluster_name`; when that
resolves nothing (no primary configured, no usable credentials, older
management version, or an MDS domain not tracked per-firewall) it leaves
the previously stored name untouched rather than clearing it — ambiguous
"couldn't tell" and confirmed "not a cluster member" are indistinguishable
from that call, so clearing on `None` would risk wiping a good name on a
transient failure. The fallback is a manual text field in the same modal
("Cluster name" + Save button, `POST .../firewalls/{name}/cluster-name`)
that lets the operator type in the real object name by hand — this reuses
`FirewallManager.set_cluster_name` (the same targeted-UPDATE method
discovery/re-check already used), it's just a new caller.

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
  - Via the **Firewalls panel's edit-modal "Re-check via Management API"
    button** (`POST .../firewalls/{name}/cluster-recheck`): calls
    `DiscoveryService.find_cluster_name()` only. Persists the name only when
    resolved (`resolved: true` in the response); when it can't resolve
    anything, the previously stored name is left alone and `resolved: false`
    tells the UI to prompt for manual entry instead.
  - Via the **manual "Cluster name" field + Save button** in the same modal
    (`POST .../firewalls/{name}/cluster-name`, body `{"cluster_name": ... |
    null}`): the fallback for when the API can't resolve one. Calls
    `FirewallManager.set_cluster_name` directly — a deliberate, separate
    action from the generic firewall edit save, same reasoning as the
    kind-gate above (ordinary edits must never touch this field).
- `Store.set_firewall_cluster_name` is a **targeted UPDATE**, deliberately
  separate from `upsert_firewall` (mirrors `assign_firewall_credential_set`)
  — `upsert_firewall` must never touch this column, or every ordinary
  add/edit would wipe out a previously-detected name.
- `ServerStateRow.cluster_name` (store schema v18) was **removed** the same
  day it shipped, once this design landed — `cluster_role` stayed there
  (still live), the name moved to `FirewallRow`.
- The Management API path resolves a cluster name for MDS environments
  during a post-hoc re-check by logging into the firewall's stored
  `FirewallRow.mds_domain` (store schema v20 — see
  [[mds-domain-per-firewall]]). Before that shipped (2026-07-23), no
  Domain/CMA was tracked per-firewall and the re-check button always
  reported `resolved: false` on MDS; the manual field was the only way to
  set the name there. It's still the fallback when `mds_domain` itself is
  unset (never discovered/imported, or manually added without setting it).
- Distinct from `checks.py`'s `HealthChecks.cluster_state` (still
  `NotImplementedError`) — that one is deployment-gating (pass/fail against
  an *expected* role), a different consumer with different requirements.

See [[cdt-cpuse-domain]] for the broader CPUSE/CDT context.
