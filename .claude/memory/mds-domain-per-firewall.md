---
name: mds-domain-per-firewall
description: FirewallRow.mds_domain tracks which MDS Domain/CMA a firewall lives in, so post-hoc Management API lookups (cluster-name re-check) can log into the right Domain instead of failing on MDS
metadata:
  type: project
---

Operator-reported bug (2026-07-23): cluster-name re-check
(`DiscoveryService.find_cluster_name`, see [[clusterxl-live-state]]) was
failing on the operator's Multi-Domain environment because the Management
API login had no `domain` to log into — `show-simple-clusters` needs a
specific Domain/CMA context on an MDS, and nothing tracked which Domain a
given firewall belonged to after discovery-import time.

**Fix — `FirewallRow.mds_domain`** (store schema v20, `Store.set_firewall_mds_domain`):
same targeted-UPDATE pattern as `cluster_name` (v19) — deliberately kept out
of `upsert_firewall` so an ordinary add/edit can never clobber it.

- **Set at discovery-import time**: `discover_firewalls(env, domain=...)`
  scans one Domain per call (the operator picks it — see
  [[firewall-discovery-domain-picker]]), so every row in that scan's result
  carries the same domain. The web layer threads it straight from the
  request (`body.domain`) into each returned server's `mds_domain`, not
  tracked per-`DiscoveredServer` in `discovery.py` itself (unlike
  `cluster_name`, which genuinely varies row-to-row and *is* resolved in
  `discovery.py`). `FirewallIn.mds_domain` rides into the add-firewall
  payload the same way `cluster_name` does, JOB_ADD-gated in
  `services/prov_ops.py`'s `_do_put` — an edit can never overwrite it.
- **Editable by hand**: Firewalls panel edit modal, MDS environments only
  (`envIsMds[currentEnv]`) — a Domain `<select>` populated from the same
  `GET .../domains` endpoint the discover-firewalls modal uses, plus a
  dedicated Save button (`POST .../firewalls/{name}/mds-domain`, body
  `{"mds_domain": ... | null}`) calling `FirewallManager.set_domain`
  directly. Same separate-action pattern as the manual cluster-name field —
  not part of the ordinary Save-changes submit.
- **Consumed by**: `POST .../firewalls/{name}/cluster-recheck` now reads
  `fw_row.mds_domain` before calling `find_cluster_name(..., domain=...)`,
  instead of never passing a domain at all. Any *future* per-Domain
  Management API call for an existing firewall should read this field the
  same way rather than asking the operator to pick a Domain again.

**How to apply:** don't reintroduce a "no domain tracked for this firewall"
limitation — it's tracked now. If a new MDS-scoped lookup needs a Domain for
an already-known firewall, read `FirewallRow.mds_domain` (or
`HostConnector`/`Store.get_firewall(...).mds_domain`) before falling back to
asking the operator.
