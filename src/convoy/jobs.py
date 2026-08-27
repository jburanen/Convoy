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
from .store import JobEvent, JobRecord, JobStatus, Store

logger = get_logger(__name__)


class JobCancelled(Exception):
    """Raised inside a handler when cancellation was requested (control flow)."""


class JobTimedOut(Exception):
    """Raised inside a handler when a poll loop gave up waiting for a slow,
    asynchronous confirmation without seeing an outright failure — finishes
    the job as TIMED_OUT (not FAILED), leaving it eligible for a later manual
    recheck (see services/patching.py's recheck_import)."""


class JobContext:
    """What a handler gets: its job row, progress logging, and cancel checks."""

    def __init__(self, store: Store, job: JobRecord) -> None:
        self._store = store
        self.job = job

    def log(self, message: str, level: str = "info", *, replace: int | None = None) -> JobEvent:
        """Record one progress line — persisted for the UI/audit, mirrored to
        logs. Pass ``replace`` (the ``seq`` returned by a previous call) to
        overwrite that line in place instead of appending a new one — for a
        poll loop whose only real change between iterations is an attempt
        counter, so the job log doesn't accumulate one line per attempt (see
        PatchingService._wait_until_imported). Returns the event so the
        caller can chain further replacements off its ``seq``."""
        event = (
            self._store.update_event(self.job.id, replace, message, level=level)
            if replace is not None
            else self._store.append_event(self.job.id, message, level=level)
        )
        # Honour the caller's level. This was hardcoded to info(), so every
        # ctx.log(..., level="error") — job failures included — was emitted at
        # INFO and therefore filtered out by the default WARNING threshold.
        # Job failures were correctly recorded in the DB but never reached
        # `docker compose logs`, which is exactly where an operator looks first
        # and precisely the case log-level alerting exists for.
        log_at = getattr(logger, level, None)
        if not callable(log_at):
            log_at = logger.info
        log_at(message, job_id=self.job.id, kind=self.job.kind, target=self.job.target)
        return event

    def raise_if_cancelled(self) -> None:
        """Call between steps; safe points are where a job may stop."""
        if self._store.is_cancel_requested(self.job.id):
            raise JobCancelled(self.job.id)

    def set_status(self, text: str | None) -> None:
        """Overwrite the short "what's happening now" headline shown live in
        the Jobs tab's Output column while the job runs (JobRecord.
        status_text) — a single overwritten field, not an event log entry.
        Independent of ``log()``: call both at a milestone worth recording in
        each place, or either alone for a headline-only or log-only update."""
        self._store.set_status_text(self.job.id, text)


Handler = Callable[[JobContext], Awaitable[None]]


class JobRunner:
    """Claims PENDING jobs from the store and runs them, ``max_concurrent`` at a
    time. Instantiate once per process; share the ``Store`` with the web app."""

    def __init__(
        self,
        store: Store,
        *,
        max_concurrent: int = 2,
        on_job_finished: Callable[[str], None] | None = None,
    ) -> None:
        if max_concurrent < 1:
            raise JobError("max_concurrent must be >= 1")
        self._store = store
        self._max_concurrent = max_concurrent
        self._handlers: dict[str, Handler] = {}
        self._wake = asyncio.Event()
        self._stopping = False
        # Called with the job id after every job reaches a terminal state, for
        # any status. Used to purge in-memory job credentials; must not raise.
        self._on_job_finished = on_job_finished

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
        job_id: str | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Persist a PENDING job and wake the runner. Returns immediately.

        ``job_id`` lets the caller pre-register per-job state (e.g. in-memory
        credentials) *before* the job becomes claimable, closing the race where
        the runner would start it before that state exists. ``triggered_by`` is
        the logged-in username (None when auth is off), recorded for the Jobs
        tab's User column/filter."""
        if kind not in self._handlers:
            raise JobError(f"no handler registered for job kind {kind!r}")
        fields: dict[str, Any] = dict(
            kind=kind,
            target=target,
            params=params or {},
            environment=environment,
            username=triggered_by,
        )
        if job_id is not None:
            fields["id"] = job_id
        job = JobRecord(**fields)
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
            done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            # Retrieve every completed task's result. _run catches broadly, but
            # an exception from the terminal-status write ITSELF (a StoreError
            # on a full disk, say) escapes it — and an un-retrieved task
            # exception surfaces only as a "Task exception was never retrieved"
            # warning at GC, leaving the job stuck RUNNING with no explanation.
            for task in done:
                exc = task.exception()
                if exc is not None:
                    logger.error("job task failed outside its own error handling", error=str(exc))

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
            try:
                ctx.raise_if_cancelled()  # cancelled while still queued
                await self._handlers[job.kind](ctx)
            except JobCancelled:
                self._store.finish_job(job.id, JobStatus.CANCELLED)
                ctx.log("job cancelled", level="warning")
            except JobTimedOut as exc:
                self._store.finish_job(job.id, JobStatus.TIMED_OUT, error=str(exc))
                ctx.log(f"job timed out: {exc}", level="warning")
            except Exception as exc:  # job boundary: record failure, don't crash the runner
                error = f"{type(exc).__name__}: {exc}"
                self._store.finish_job(job.id, JobStatus.FAILED, error=error)
                ctx.log(f"job failed: {error}", level="error")
            else:
                self._store.finish_job(job.id, JobStatus.SUCCEEDED)
                ctx.log("job succeeded")
        finally:
            # Always drop any in-memory per-job state, whatever the outcome —
            # including cancellation while still queued (handler never ran).
            if self._on_job_finished is not None:
                try:
                    self._on_job_finished(job.id)
                except Exception as exc:  # never let cleanup crash the runner
                    logger.warning("job finalizer failed", job_id=job.id, error=str(exc))
