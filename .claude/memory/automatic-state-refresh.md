---
name: automatic-state-refresh
description: A host's detected state is refreshed out-of-band after it is added and after any job that could have changed it (any outcome); the UI notices via a state-version token
metadata:
  type: project
---

`services/state_refresh.py` (`StateRefreshService`) keeps the Management Servers
and Firewalls tables from showing stale or blank state, in the two places nothing
else covered (operator-directed, 2026-08-28):

- **a host that was just added or discovered** — every path goes through a
  `prov.add` job, so `ProvisioningJobService` takes an `on_host_added` callback
  (fired only on a genuine add, never an edit, and never allowed to fail the add);
- **a job that did not succeed** — `patching.py`'s in-job `_refresh_state` only
  runs on the success path, and a failure is often the connection itself.
  `JobRunner.on_job_finished` fires for every terminal status, so the web app's
  hook composes `vault.discard` with `StateRefreshService.after_job`.

`REFRESH_AFTER_JOB_KINDS` = cpuse.import / import_cloud / install / uninstall,
spark.scp, spark.install, pkgs.push_to_repo, prov.connect_primary. `cdt.*` is
deliberately excluded — a CDT run acts on a fleet of firewalls, not on the job's
target host. `app.js` mirrors this list as `STATE_REFRESH_JOB_KINDS`; a test in
`tests/test_state_refresh.py` pins the set so the two don't drift.

**A cluster member drags its peers in.** `schedule()` fans out: it queues the
host, then queues every other firewall in the environment sharing its
`FirewallRow.cluster_name` (matched case-insensitively and trimmed, the same way
`services/discovery.py` matches cluster objects). Patching one member moves the
cluster's live roles, so refreshing it alone leaves the peers' cached
Active/Standby wrong until someone clicks Refresh on each — see
[[clusterxl-live-state]]. A member whose cluster name has not been discovered
yet refreshes alone: without a name there is nothing to group by, and "every
cluster member in the environment" is far too wide a net (added 2026-09-09,
operator-directed). `_cluster_peers` swallows any lookup failure so the host's
own refresh still happens; `_schedule_one` holds the per-host in-flight guard,
so peers get the same one-at-a-time treatment and there is no recursion.

Each refresh runs on its own daemon thread (`spawn` is injectable, so tests run
it inline), one per host at a time, and **never raises**. It is silent when there
is nothing to connect with — storage-disabled environments hold only per-job
in-memory credentials, purged at job end, and a Smart-1 Cloud management server
has no SSH account at all. Those keep refreshing the operator's way, via the
Refresh link's credential prompt. See [[safety-constraints]]: a refresh is
read-only (`show installer packages` / `cphaprob` / `fw ver`).

The UI learns a refresh landed by polling `GET /api/env/{env}/state-version` —
`Store.latest_state_check`, a MAX(checked_at) change-detection token, not a
timestamp to display. `watchForStateRefresh()` in app.js polls it only inside a
90s window opened by a finished job or an add, never continuously.
