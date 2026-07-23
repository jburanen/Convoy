"""Package-action jobs: upload, keep/unkeep (retention pin), and delete — run
through the shared job runner, like CPUSE/CDT jobs, for Jobs-tab visibility
and audit history (see .claude/memory/patching-web-design.md). Unlike those,
these are local disk+DB operations with no SSH host or credentials involved,
so they're submitted directly via ``JobRunner.submit`` rather than
``services.common.submit_host_job``.

Upload is the one wrinkle: the file's bytes arrive over HTTP *during* the
request, so they can't be handed to a job as-is — the route stages the
upload to a stable temp file inside the package directory first (a cheap
disk copy, no hashing), then submits the job with that path; the job handler
does the real work (hash, dedupe, move into place) via
``PackageStore.add_stream`` and removes the staging file when done.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord

JOB_UPLOAD = "pkgs.upload"
JOB_KEEP = "pkgs.keep"
JOB_NOTKEEP = "pkgs.notkeep"
JOB_DELETE = "pkgs.delete"


class PackageJobService:
    """Wraps PackageStore's write operations as background jobs."""

    def __init__(self, *, packages: PackageStore, runner: JobRunner) -> None:
        self._packages = packages
        self.runner = runner
        runner.register(JOB_UPLOAD, self._upload_job)
        runner.register(JOB_KEEP, self._retention_job)
        runner.register(JOB_NOTKEEP, self._retention_job)
        runner.register(JOB_DELETE, self._delete_job)

    # -- submit -------------------------------------------------------------

    def submit_upload(self, filename: str, staged_path: Path) -> JobRecord:
        """``staged_path`` is a file already fully received and safely stored
        outside the request's own lifetime — see the module docstring."""
        return self.runner.submit(
            JOB_UPLOAD, target=filename, params={"staged_path": str(staged_path)}
        )

    def submit_retention(self, filename: str, pinned: bool) -> JobRecord:
        """Raises PackageError (404-mapped by the route) synchronously if the
        package doesn't exist, instead of deferring an obviously-doomed job
        to the runner — mirrors the old synchronous endpoint's immediate 404."""
        self._packages.get(filename)
        kind = JOB_KEEP if pinned else JOB_NOTKEEP
        return self.runner.submit(kind, target=filename, params={"pinned": pinned})

    def submit_delete(self, filename: str) -> JobRecord:
        self._packages.get(filename)
        return self.runner.submit(JOB_DELETE, target=filename)

    # -- handlers -------------------------------------------------------------

    async def _upload_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_upload, ctx)

    def _do_upload(self, ctx: JobContext) -> None:
        staged_path = Path(ctx.job.params["staged_path"])
        filename = ctx.job.target
        assert filename is not None
        try:
            with staged_path.open("rb") as fh:
                rec = self._packages.add_stream(filename, fh)
            ctx.log(f"stored {rec.filename} ({rec.size} bytes, sha256 {rec.sha256[:12]}…)")
        finally:
            staged_path.unlink(missing_ok=True)

    async def _retention_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_retention, ctx)

    def _do_retention(self, ctx: JobContext) -> None:
        filename = ctx.job.target
        assert filename is not None
        pinned = bool(ctx.job.params["pinned"])
        rec = self._packages.set_pinned(filename, pinned)
        ctx.log(f"{'pinned' if pinned else 'unpinned'} {rec.filename}")

    async def _delete_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_delete, ctx)

    def _do_delete(self, ctx: JobContext) -> None:
        filename = ctx.job.target
        assert filename is not None
        self._packages.delete(filename)
        ctx.log(f"deleted {filename}")
