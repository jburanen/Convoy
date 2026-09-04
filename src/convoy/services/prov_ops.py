"""Provisioning: add/edit/delete of management servers and CPUSE-patched
firewalls.

Unlike CDT/CPUSE operations, these run **synchronously** — a local DB write
with no SSH host involved, so there's no reason to make the operator wait on
the async job queue the way a real device operation must (same rationale as
``services/cred_ops.py`` and ``services/pkgs_ops.py`` before it,
operator-directed, 2026-08-18). The old queued shape shared ``JobRunner``'s
concurrency slots with genuinely slow ``cpuse.*``/``cdt.*`` device jobs, so an
unrelated prov.add (e.g. importing a firewall found by discovery) could sit
behind an in-progress install with nothing to do with it. Each call still
records a ``JobRecord`` (already terminal by the time it returns) purely for
Jobs-tab visibility and audit history — no PENDING state, no background
pickup, no ``JobRunner`` involvement.

Servers and firewalls share one set of job kinds (``prov.add``/``prov.edit``/
``prov.delete`` — operator-directed, 2026-07-23: no server/firewall split in
the Kind column) rather than one pair per entity; ``params["entity"]`` is the
internal discriminator the single ``_do_put``/``_do_delete`` pair uses to call
the right manager, invisible on the Jobs tab.

Whether an add is really an add or an edit is decided the same way
CredentialJobService decides it: a cheap existence read *before* the kind is
picked. Unlike credentials, none of these fields are secret, so everything —
including an explicit credential-set assignment made in the same Add/Edit
modal submit — rides in ``JobRecord.params``, no vault needed. Folding that
assignment into the same job (rather than a separate follow-up call) closes a
race the frontend used to have to work around. ``credential_set`` is
therefore tri-state — omitted (leave any existing/default-on-create
assignment alone), explicit ``None`` (clear it), or a set name — using the
``UNSET`` sentinel below to tell "omitted" from "explicitly cleared" apart,
since both are spelled ``None`` in Python.

Validation (bad role, name colliding with the other entity table, etc.)
happens inside ``EnvironmentManager``/``FirewallManager`` as before, which
means it still surfaces as a **failed job**, not a synchronous 400/409
(matches ``cred.*``). Only environment existence and (for delete) target
existence are cheap enough to keep as an instant, pre-submit check (mirrors
``CredentialJobService.submit_delete``'s "don't defer an obviously-doomed
job").
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from ..errors import InventoryError
from ..reporting import get_logger
from ..store import JobRecord, JobStatus, Store, utcnow
from .environments import EnvironmentManager
from .firewalls import FirewallManager

logger = get_logger(__name__)

JOB_ADD = "prov.add"
JOB_EDIT = "prov.edit"
JOB_DELETE = "prov.delete"


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<unset>"


UNSET: Final = _Unset()


class ProvisioningJobService:
    """Wraps EnvironmentManager/FirewallManager server+firewall CRUD with
    immediate execution and Jobs-tab tracking."""

    def __init__(
        self,
        *,
        store: Store,
        env_manager: EnvironmentManager,
        firewall_manager: FirewallManager,
        on_host_added: Callable[[str, str], None] | None = None,
    ) -> None:
        self._store = store
        self._env_manager = env_manager
        self._firewall_manager = firewall_manager
        # Called with (environment, host name) after a server or firewall is
        # genuinely created — not on an edit. The web app points it at
        # StateRefreshService, so a freshly added or discovered host is queried
        # once instead of sitting at "Not yet checked." until someone clicks
        # Refresh. Optional so the CLI/tests can leave it off; never allowed to
        # fail the add itself (see _do_put).
        self._on_host_added = on_host_added

    # -- submit: management servers ----------------------------------------------

    def submit_put_server(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int,
        notes: str | None,
        credential_set: str | _Unset | None = UNSET,
        triggered_by: str | None = None,
    ) -> JobRecord:
        kind = JOB_ADD if self._store.get_env_host(environment, name) is None else JOB_EDIT
        params = _put_params("server", address, role, ssh_user, ssh_port, notes, credential_set)
        job = self._start(
            kind, target=name, environment=environment, params=params, triggered_by=triggered_by
        )
        try:
            self._do_put(job)
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    def submit_delete_server(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._store.get_env_host(environment, name) is None:
            raise InventoryError(f"server {name!r} not found in environment {environment!r}")
        job = self._start(
            JOB_DELETE,
            target=name,
            environment=environment,
            params={"entity": "server"},
            triggered_by=triggered_by,
        )
        try:
            self._do_delete(job)
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    # -- submit: firewalls --------------------------------------------------------

    def submit_put_firewall(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int,
        notes: str | None,
        credential_set: str | _Unset | None = UNSET,
        cluster_name: str | None = None,
        mds_domain: str | None = None,
        tags: list[str] | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        kind = JOB_ADD if self._store.get_firewall(environment, name) is None else JOB_EDIT
        params = _put_params("firewall", address, role, ssh_user, ssh_port, notes, credential_set)
        # Only meaningful on a genuine creation — see _do_put, which applies it
        # solely when kind is JOB_ADD. Riding along on every edit's params
        # would be harmless in isolation, but gating in one place (there,
        # not here) is what actually guarantees an edit can never overwrite a
        # previously-detected cluster name (or MDS domain) back to None.
        params["cluster_name"] = cluster_name
        params["mds_domain"] = mds_domain
        # Unlike cluster_name/mds_domain, tags are plain operator-edited data
        # (like notes) — applied on every add AND edit in _do_put, never
        # kind-gated.
        params["tags"] = tags or []
        job = self._start(
            kind, target=name, environment=environment, params=params, triggered_by=triggered_by
        )
        try:
            self._do_put(job)
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    def submit_delete_firewall(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._store.get_firewall(environment, name) is None:
            raise InventoryError(f"firewall {name!r} not found in environment {environment!r}")
        job = self._start(
            JOB_DELETE,
            target=name,
            environment=environment,
            params={"entity": "firewall"},
            triggered_by=triggered_by,
        )
        try:
            self._do_delete(job)
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    # -- execution ------------------------------------------------------------------

    def _do_put(self, job: JobRecord) -> None:
        name = job.target
        assert name is not None
        p = job.params
        environment = job.environment
        credential_set = p.get("credential_set", UNSET)
        if p["entity"] == "server":
            self._env_manager.add_server(
                environment,
                name=name,
                address=p["address"],
                role=p["role"],
                ssh_user=p["ssh_user"],
                ssh_port=p["ssh_port"],
                notes=p.get("notes"),
            )
            if credential_set is not UNSET:
                self._env_manager.assign_credential(environment, name, credential_set)
            noun = "management server"
        else:
            self._firewall_manager.add_firewall(
                environment,
                name=name,
                address=p["address"],
                role=p["role"],
                ssh_user=p["ssh_user"],
                ssh_port=p["ssh_port"],
                notes=p.get("notes"),
                tags=p.get("tags"),
            )
            if credential_set is not UNSET:
                self._firewall_manager.assign_credential(environment, name, credential_set)
            cluster_name = p.get("cluster_name")
            mds_domain = p.get("mds_domain")
            # Only on genuine creation — an edit's params always carry these
            # keys too (see submit_put_firewall), but applying them here only
            # for JOB_ADD is what stops an unrelated edit (e.g. changing the
            # SSH port) from wiping out a previously-detected cluster name or
            # MDS domain. Manual correction of either goes through its own
            # dedicated endpoint instead (set_cluster_name / set_domain).
            if job.kind == JOB_ADD and cluster_name:
                self._firewall_manager.set_cluster_name(environment, name, cluster_name)
            if job.kind == JOB_ADD and mds_domain:
                self._firewall_manager.set_domain(environment, name, mds_domain)
            noun = "firewall"
        verb = "added" if job.kind == JOB_ADD else "updated"
        self._succeed(job, f"{verb} {noun} {name!r}")
        if job.kind == JOB_ADD and self._on_host_added is not None:
            # After the job is recorded as succeeded: this is a follow-on
            # nicety, and a hiccup in it must never turn a completed add into
            # a failed one.
            try:
                self._on_host_added(environment, name)
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning(
                    "post-add state refresh could not be scheduled",
                    host=name,
                    error=str(exc),
                )

    def _do_delete(self, job: JobRecord) -> None:
        name = job.target
        assert name is not None
        if job.params["entity"] == "server":
            self._env_manager.remove_server(job.environment, name)
            noun = "management server"
        else:
            self._firewall_manager.remove_firewall(job.environment, name)
            noun = "firewall"
        self._succeed(job, f"deleted {noun} {name!r}")

    # -- internals --------------------------------------------------------------

    def _start(
        self,
        kind: str,
        *,
        target: str,
        environment: str,
        params: dict[str, object],
        triggered_by: str | None,
    ) -> JobRecord:
        job = JobRecord(
            kind=kind,
            target=target,
            environment=environment,
            params=params,
            username=triggered_by,
            status=JobStatus.RUNNING,
            started_at=utcnow(),
        )
        self._store.insert_job(job)
        return job

    def _succeed(self, job: JobRecord, message: str) -> None:
        self._store.append_event(job.id, message)
        self._store.finish_job(job.id, JobStatus.SUCCEEDED)

    def _fail(self, job: JobRecord, exc: Exception) -> None:
        error = f"{type(exc).__name__}: {exc}"
        self._store.append_event(job.id, f"job failed: {error}", level="error")
        self._store.finish_job(job.id, JobStatus.FAILED, error=error)


def _put_params(
    entity: str,
    address: str,
    role: str,
    ssh_user: str,
    ssh_port: int,
    notes: str | None,
    credential_set: str | _Unset | None,
) -> dict[str, object]:
    params: dict[str, object] = {
        "entity": entity,
        "address": address,
        "role": role,
        "ssh_user": ssh_user,
        "ssh_port": ssh_port,
        "notes": notes,
    }
    if credential_set is not UNSET:
        params["credential_set"] = credential_set
    return params


__all__ = ["JOB_ADD", "JOB_DELETE", "JOB_EDIT", "UNSET", "ProvisioningJobService"]
