"""Background job runner: a persisted state machine for long-running operations.

A web click (or CLI call) *enqueues* a job and returns immediately; this runner
executes registered handlers with bounded concurrency and streams progress events
to the store, where the UI polls/SSEs them. Jobs survive restarts: anything still
RUNNING at startup is marked INTERRUPTED (never auto-resumed — the operator must
re-check host state first; installs may have half-happened). See
.claude/memory/patching-web-design.md.

Handlers are ``async``; blocking transport work (paramiko, scp) belongs in
``asyncio.to_thread`` inside the handler. Cancellation is cooperative: handlers
call ``ctx.raise_if_cancelled()`` between steps — we never hard-kill a handler
mid-install on a firewall.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Any

from .errors import JobError
from .reporting import get_logger
from .store import JobRecord, JobStatus, Store

logger = get_logger(__name__)


class JobCancelled(Exception):
    """Raised inside a handler when cancellation was requested (control flow)."""


class JobContext:
    """What a handler gets: its job row, progress logging, and cancel checks."""

    def __init__(self, store: Store, job: JobRecord) -> None:
        self._store = store
        self.job = job

    def log(self, message: str, level: str = "info") -> None:
        """Record one progress line — persisted for the UI/audit, mirrored to logs."""
        self._store.append_event(self.job.id, message, level=level)
        logger.info(message, job_id=self.job.id, kind=self.job.kind, target=self.job.target)

    def raise_if_cancelled(self) -> None:
        """Call between steps; safe points are where a job may stop."""
        if self._store.is_cancel_requested(self.job.id):
            raise JobCancelled(self.job.id)


Handler = Callable[[JobContext], Awaitable[None]]


class JobRunner:
    """Claims PENDING jobs from the store and runs them, ``max_concurrent`` at a
    time. Instantiate once per process; share the ``Store`` with the web app."""

    def __init__(self, store: Store, *, max_concurrent: int = 2) -> None:
        if max_concurrent < 1:
            raise JobError("max_concurrent must be >= 1")
        self._store = store
        self._max_concurrent = max_concurrent
        self._handlers: dict[str, Handler] = {}
        self._wake = asyncio.Event()
        self._stopping = False

    def register(self, kind: str, handler: Handler) -> Handler:
        """Bind a handler to a job kind (usable as ``runner.register("x", fn)``)."""
        if kind in self._handlers:
            raise JobError(f"handler already registered for job kind {kind!r}")
        self._handlers[kind] = handler
        return handler

    def recover(self) -> list[JobRecord]:
        """Run once at startup, before serving: fail-over jobs orphaned by a crash."""
        interrupted = self._store.mark_interrupted()
        for job in interrupted:
            logger.warning(
                "job interrupted by restart", job_id=job.id, kind=job.kind, target=job.target
            )
        return interrupted

    def submit(
        self,
        kind: str,
        *,
        target: str | None = None,
        params: dict[str, Any] | None = None,
        environment: str = "default",
    ) -> JobRecord:
        """Persist a PENDING job and wake the runner. Returns immediately."""
        if kind not in self._handlers:
            raise JobError(f"no handler registered for job kind {kind!r}")
        job = JobRecord(kind=kind, target=target, params=params or {}, environment=environment)
        self._store.insert_job(job)
        self._wake.set()
        logger.info(
            "job submitted", job_id=job.id, kind=kind, target=target, environment=environment
        )
        return job

    def request_cancel(self, job_id: str) -> None:
        """Cooperative cancel: takes effect at the handler's next safe point."""
        self._store.request_cancel(job_id)
        logger.info("job cancel requested", job_id=job_id)

    async def run_until_idle(self) -> None:
        """Process jobs until none are pending or running. For tests and CLI runs."""
        tasks: set[asyncio.Task[None]] = set()
        while True:
            while len(tasks) < self._max_concurrent:
                job = self._store.claim_next_pending()
                if job is None:
                    break
                tasks.add(asyncio.create_task(self._run(job)))
            if not tasks:
                return
            _done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    async def serve(self, poll_interval: float = 1.0) -> None:
        """Long-running loop for the web app. Polls as well as waking on submit,
        since submits may come from other threads (sync FastAPI routes)."""
        self._stopping = False
        while not self._stopping:
            await self.run_until_idle()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=poll_interval)
            self._wake.clear()

    def stop(self) -> None:
        """Ask ``serve`` to exit after the current drain finishes."""
        self._stopping = True
        self._wake.set()

    async def _run(self, job: JobRecord) -> None:
        ctx = JobContext(self._store, job)
        try:
            ctx.raise_if_cancelled()  # cancelled while still queued
            await self._handlers[job.kind](ctx)
        except JobCancelled:
            self._store.finish_job(job.id, JobStatus.CANCELLED)
            ctx.log("job cancelled", level="warning")
        except Exception as exc:  # job boundary: record the failure, don't crash the runner
            error = f"{type(exc).__name__}: {exc}"
            self._store.finish_job(job.id, JobStatus.FAILED, error=error)
            ctx.log(f"job failed: {error}", level="error")
        else:
            self._store.finish_job(job.id, JobStatus.SUCCEEDED)
            ctx.log("job succeeded")
