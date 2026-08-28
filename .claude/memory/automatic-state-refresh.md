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
deliberately excluded — a CDT run acts on a fleet of gateways, not on the job's
target host. `app.js` mirrors this list as `STATE_REFRESH_JOB_KINDS`; a test in
`tests/test_state_refresh.py` pins the set so the two don't drift.

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
