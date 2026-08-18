"""Credential-set operations: add/edit/delete.

Unlike CPUSE/CDT/pkgs/prov operations, these run **synchronously** — a local
encrypt+DB write with no SSH host involved, so there's no reason to make the
operator wait on the async job queue the way a real device operation must
(operator-directed, 2026-07-24). Each call still records a ``JobRecord`` (already
terminal by the time it returns) purely for Jobs-tab visibility and audit
history, matching every other kind of change — it just never goes through
``JobRunner``: no PENDING state, no background pickup, nothing to poll.

The plaintext secrets themselves must never reach ``JobRecord.params`` (it's
persisted as plain JSON in the jobs table — see store.py — and later archived
to a flat file), which would defeat the whole point of encrypting credentials
at rest. Since execution is synchronous, they simply pass straight through to
``CredentialStore.put_set`` in this same call stack and are never stored
anywhere but the encrypted row itself — no vault or other cross-call ferrying
needed.
"""

from __future__ import annotations

from ..credentials import CredentialStore
from ..errors import InventoryError
from ..store import JobRecord, JobStatus, Store, utcnow

JOB_ADD = "cred.add"
JOB_EDIT = "cred.edit"
JOB_DELETE = "cred.delete"


class CredentialJobService:
    """Wraps CredentialStore's write operations with immediate execution and
    Jobs-tab tracking."""

    def __init__(self, *, credentials: CredentialStore, store: Store) -> None:
        self._credentials = credentials
        self._store = store

    # -- submit ---------------------------------------------------------------

    def submit_put(
        self,
        environment: str,
        *,
        name: str,
        ssh_username: str | None,
        ssh_password: str | None,
        ssh_private_key: str | None,
        api_key: str | None,
        default_if_none: bool,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Whether this is an add or an edit is decided here (a secret-free
        read), before the kind is picked — the job kind itself is what the
        Jobs tab's Env/Target columns key off of."""
        kind = JOB_ADD if self._credentials.get_info(environment, name) is None else JOB_EDIT
        job = self._start(
            kind,
            target=name,
            environment=environment,
            params={"ssh_username": ssh_username, "default_if_none": default_if_none},
            triggered_by=triggered_by,
        )
        try:
            info = self._credentials.put_set(
                environment,
                name,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                ssh_private_key=ssh_private_key,
                api_key=api_key,
            )
            no_default_yet = self._credentials.default_set_name(environment) is None
            if default_if_none and no_default_yet:
                self._credentials.set_default(environment, name)
            verb = "added" if kind == JOB_ADD else "updated"
            self._succeed(job, f"{verb} credential set {name!r} (ssh_auth={info.ssh_auth})")
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    def submit_delete(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._credentials.get_info(environment, name) is None:
            raise InventoryError(
                f"credential set {name!r} not found in environment {environment!r}"
            )
        job = self._start(
            JOB_DELETE, target=name, environment=environment, params={}, triggered_by=triggered_by
        )
        try:
            deleted = self._credentials.delete_set(environment, name)
            message = (
                f"deleted credential set {name!r}" if deleted else "credential set was already gone"
            )
            self._succeed(job, message)
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

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


__all__ = ["JOB_ADD", "JOB_DELETE", "JOB_EDIT", "CredentialJobService"]
