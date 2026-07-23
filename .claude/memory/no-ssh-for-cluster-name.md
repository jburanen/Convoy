---
name: no-ssh-for-cluster-name
description: Never design any SmartConsole-cluster-name discovery around SSH/CLI commands on the firewall — only the Management API can name it
metadata:
  type: feedback
---

Never try to discover a firewall's real ClusterXL cluster *object* name via
SSH/CLI commands run on the firewall itself. No command on Gaia exposes it —
`show cluster state` only lists member hostnames, not the SmartConsole
object name — so any code path built around parsing it for this purpose is
not a fallback, it's a dead end that happens to return a plausible-looking
string (a comma-joined hostname list masquerading as a cluster name).

**Why:** Operator correction, 2026-07-23, after `PatchingService.check_cluster_membership`
(cphaprob-based) had shipped earlier the same day as the "fallback" half of
the Firewalls panel's cluster-recheck flow — see [[clusterxl-live-state]].
It was removed once flagged.

**How to apply:** Cluster *name* resolution must go through the Management
API (`DiscoveryService.find_cluster_name` / `show-simple-clusters`) only. If
the API can't resolve one, the correct fallback is a manual operator-entered
field (the Firewalls panel edit modal's "Cluster name" input), never a live
SSH/CLI probe. This does not apply to ClusterXL *role* (Active/Standby),
which genuinely is live and SSH-derived (`cphaprob`/`show cluster state`) —
only the object *name* is off-limits to SSH.
