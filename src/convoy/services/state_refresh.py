"""Automatic, best-effort refresh of one host's detected state.

The Management Servers and Firewalls tables show *cached* state (version, JHF,
CPUSE agent build, packages ready to install — ``server_state`` in the DB),
filled in by an explicit Refresh and, on the way out of a successful import or
install, by the job itself (patching.py's ``_refresh_state``, which reuses the
connection it already has). That leaves two moments where a row shows something
other than what is really on the box:

* **a host that has just been added or discovered** has never been queried, so it
  reads "Not yet checked." until an operator clicks Refresh;
* **a job that did NOT succeed** — failed, timed out, cancelled — never reaches
  the in-job refresh, and its failure may well be *because* the host changed
  (a half-finished install, a package that imported but then errored). The
  in-job refresh cannot cover it: the failure is often the connection itself,
  so the refresh needs its own attempt.

This module closes both, out-of-band: each refresh runs on its own thread, never
blocks the job that triggered it or the request that added the host, and never
raises. It is deliberately silent when there is nothing to connect with — an
environment with credential storage disabled keeps only per-job, in-memory
credentials, which are purged the moment the job ends (see JobCredentialVault),
and a Smart-1 Cloud management server has no SSH account at all. Those
environments keep refreshing the way they always have: the operator's own
Refresh, which can prompt for credentials.

The refreshed state lands in the same ``server_state`` cache every other path
writes, so the UI picks it up by polling ``Store.latest_state_check`` — see
``/api/env/{env}/state-version`` and ``watchForStateRefresh`` in app.js.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from ..errors import CredentialError, OrchestratorError
from ..inventory import Role
from ..reporting import get_logger
from .connect_primary import JOB_CONNECT_PRIMARY
from .patching import JOB_IMPORT, JOB_IMPORT_CLOUD, JOB_INSTALL, JOB_UNINSTALL
from .pkg_repo_ops import JOB_PKG_PUSH_TO_REPO
from .spark_patching import JOB_INSTALL as JOB_SPARK_INSTALL
from .spark_patching import JOB_TRANSFER as JOB_SPARK_TRANSFER

if TYPE_CHECKING:  # types only — nothing here is needed at runtime
    from ..store import Store
    from .patching import PatchingService
    from .spark_patching import SparkPatchingService

logger = get_logger(__name__)

# Every job kind that moves a package onto a host or changes what is installed
# on it — refreshed on ANY terminal status, not just success (operator-directed,
# 2026-08-28). cdt.* is deliberately absent: a CDT run acts on a fleet of
# gateways discovered at deploy time, none of which is the job's target host.
REFRESH_AFTER_JOB_KINDS = frozenset(
    {
        JOB_IMPORT,
        JOB_IMPORT_CLOUD,
        JOB_INSTALL,
        JOB_UNINSTALL,
        JOB_SPARK_TRANSFER,
        JOB_SPARK_INSTALL,
        JOB_PKG_PUSH_TO_REPO,
        # Connect to Primary is how an environment's first management server
        # arrives — the "initial discovery" case, for servers.
        JOB_CONNECT_PRIMARY,
    }
)


def _spawn_thread(work: Callable[[], None]) -> None:
    """Default runner: a daemon thread, so a refresh in flight never holds up
    process shutdown (its result is a cache row, nothing waits on it)."""
    threading.Thread(target=work, name="state-refresh", daemon=True).start()


class StateRefreshService:
    """Schedules background state refreshes. Nothing here ever raises."""

    def __init__(
        self,
        *,
        patching: PatchingService,
        spark: SparkPatchingService,
        store: Store,
        spawn: Callable[[Callable[[], None]], None] = _spawn_thread,
    ) -> None:
        self._patching = patching
        self._spark = spark
        self._store = store
        self._spawn = spawn
        # One refresh per host at a time: an import finishing while an earlier
        # refresh for the same host is still connecting should not open a
        # second SSH session to ask the same questions.
        self._lock = threading.Lock()
        self._in_flight: set[tuple[str, str]] = set()

    def after_job(self, job_id: str) -> None:
        """``JobRunner.on_job_finished`` hook: refresh the target of a job that
        may have changed it, whatever the job's outcome. Must never raise —
        the runner calls this in a finally block."""
        try:
            job = self._store.get_job(job_id)
        except Exception as exc:  # the job row is all we need; never crash the runner
            logger.warning("could not read finished job for state refresh", error=str(exc))
            return
        if job.kind not in REFRESH_AFTER_JOB_KINDS or not job.target:
            return
        self.schedule(job.environment, job.target, reason=f"{job.kind} {job.status.value}")

    def after_host_added(self, environment: str, host_name: str) -> None:
        """A management server or firewall has just been added to inventory
        (manually, in bulk, or imported from a discovery scan) — query it once
        so its row shows real state instead of "Not yet checked."."""
        self.schedule(environment, host_name, reason="host added")

    def schedule(self, environment: str, host_name: str, *, reason: str) -> None:
        """Queue a refresh and return immediately. A no-op while one is already
        in flight for the same host."""
        key = (environment, host_name)
        with self._lock:
            if key in self._in_flight:
                logger.debug(
                    "state refresh already in flight", environment=environment, host=host_name
                )
                return
            self._in_flight.add(key)

        def work() -> None:
            try:
                self.refresh(environment, host_name, reason=reason)
            finally:
                with self._lock:
                    self._in_flight.discard(key)

        try:
            self._spawn(work)
        except Exception as exc:  # e.g. a thread cannot be started under load
            with self._lock:
                self._in_flight.discard(key)
            logger.warning("could not start state refresh", host=host_name, error=str(exc))

    def refresh(self, environment: str, host_name: str, *, reason: str) -> bool:
        """Query one host and cache what comes back. Returns whether it landed;
        never raises, whatever the host does."""
        try:
            role = self._patching.host_role(environment, host_name)
        except OrchestratorError as exc:
            # Deleted between scheduling and running, or never in inventory —
            # nothing to refresh, and nothing wrong either.
            logger.debug(
                "state refresh skipped: host not in inventory",
                environment=environment,
                host=host_name,
                error=str(exc),
            )
            return False
        try:
            if role == Role.SPARK_FIREWALL.value:
                # No CPUSE agent on Spark — its own `fw ver` detect, same as
                # the Refresh link picks (see web/app.py's firewall_state).
                self._spark.detect(environment, host_name)
            else:
                self._patching.detect(environment, host_name)
        except CredentialError as exc:
            # Storage disabled, no set assigned, or an API-only management
            # server: expected, not a fault. The operator's own Refresh (which
            # can prompt) still works.
            logger.info(
                "automatic state refresh skipped: no usable stored credentials",
                environment=environment,
                host=host_name,
                reason=reason,
                detail=str(exc),
            )
            return False
        except Exception as exc:
            # Unreachable, mid-reboot after an install, wrong password — the
            # operator sees the last known state, exactly as before this ran.
            logger.warning(
                "automatic state refresh failed",
                environment=environment,
                host=host_name,
                reason=reason,
                error=f"{type(exc).__name__}: {exc}",
            )
            return False
        logger.info(
            "detected state refreshed automatically",
            environment=environment,
            host=host_name,
            reason=reason,
        )
        return True


__all__ = ["REFRESH_AFTER_JOB_KINDS", "StateRefreshService"]
