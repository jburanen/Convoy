"""Package operations: upload, keep/unkeep (retention pin), and delete.

Unlike CPUSE/CDT operations, these run **synchronously** — local disk+DB
operations with no SSH host or credentials involved, so there's no reason to
make the operator wait on the async job queue (operator-directed, 2026-07-24;
same change as credential-set CRUD, see services/cred_ops.py). Each call
still records a ``JobRecord`` (already terminal by the time it returns)
purely for Jobs-tab visibility and audit history — no PENDING state, no
background pickup, nothing to poll.

Upload is the one wrinkle: the file's bytes arrive over HTTP *during* the
request, so they can't be read from the request directly here — the route
stages the upload to a stable temp file inside the package directory first (a
cheap disk copy, no hashing), then calls in with that path; this service does
the real work (hash, dedupe, move into place) via ``PackageStore.add_stream``
in the same call, and removes the staging file itself when done.
"""

from __future__ import annotations

from pathlib import Path

from ..packages import PackageStore
from ..store import JobRecord, JobStatus, Store, utcnow

JOB_UPLOAD = "pkgs.upload"
JOB_KEEP = "pkgs.keep"
JOB_NOTKEEP = "pkgs.notkeep"
JOB_DELETE = "pkgs.delete"


class PackageJobService:
    """Wraps PackageStore's write operations with immediate execution and
    Jobs-tab tracking."""

    def __init__(self, *, packages: PackageStore, store: Store) -> None:
        self._packages = packages
        self._store = store

    # -- submit ---------------------------------------------------------------

    def submit_upload(
        self, filename: str, staged_path: Path, *, triggered_by: str | None = None
    ) -> JobRecord:
        """``staged_path`` is a file already fully received and safely stored
        outside the request's own lifetime — see web/app.py."""
        job = self._start(JOB_UPLOAD, target=filename, params={}, triggered_by=triggered_by)
        try:
            with staged_path.open("rb") as fh:
                rec = self._packages.add_stream(filename, fh)
            self._succeed(
                job, f"stored {rec.filename} ({rec.size} bytes, sha256 {rec.sha256[:12]}…)"
            )
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        finally:
            staged_path.unlink(missing_ok=True)
        return self._store.get_job(job.id)

    def submit_retention(
        self, filename: str, pinned: bool, *, triggered_by: str | None = None
    ) -> JobRecord:
        """Raises PackageError (404-mapped by the route) synchronously if the
        package doesn't exist — no job created for an obviously-doomed
        request."""
        self._packages.get(filename)
        kind = JOB_KEEP if pinned else JOB_NOTKEEP
        job = self._start(
            kind, target=filename, params={"pinned": pinned}, triggered_by=triggered_by
        )
        try:
            rec = self._packages.set_pinned(filename, pinned)
            self._succeed(job, f"{'pinned' if pinned else 'unpinned'} {rec.filename}")
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    def submit_delete(self, filename: str, *, triggered_by: str | None = None) -> JobRecord:
        self._packages.get(filename)
        job = self._start(JOB_DELETE, target=filename, params={}, triggered_by=triggered_by)
        try:
            self._packages.delete(filename)
            self._succeed(job, f"deleted {filename}")
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    # -- internals --------------------------------------------------------------

    def _start(
        self,
        kind: str,
        *,
        target: str,
        params: dict[str, object],
        triggered_by: str | None,
    ) -> JobRecord:
        job = JobRecord(
            kind=kind,
            target=target,
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


__all__ = ["JOB_DELETE", "JOB_KEEP", "JOB_NOTKEEP", "JOB_UPLOAD", "PackageJobService"]
