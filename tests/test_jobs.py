from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from convoy.errors import JobError
from convoy.jobs import JobContext, JobRunner, JobTimedOut
from convoy.store import JobRecord, JobStatus, Store


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def runner(store: Store) -> JobRunner:
    return JobRunner(store, max_concurrent=2)


def test_submit_run_succeed_with_events(store: Store, runner: JobRunner) -> None:
    async def handler(ctx: JobContext) -> None:
        ctx.log("step 1")
        ctx.log("step 2")

    runner.register("ok", handler)
    job = runner.submit("ok", target="mgmt-01", params={"x": 1})
    asyncio.run(runner.run_until_idle())

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    assert finished.finished_at is not None
    messages = [e.message for e in store.events(job.id)]
    assert messages == ["step 1", "step 2", "job succeeded"]


def test_failing_handler_marks_failed_and_keeps_runner_alive(
    store: Store, runner: JobRunner
) -> None:
    async def bad(ctx: JobContext) -> None:
        raise RuntimeError("kaboom")

    async def good(ctx: JobContext) -> None:
        ctx.log("fine")

    runner.register("bad", bad)
    runner.register("good", good)
    failed = runner.submit("bad")
    ok = runner.submit("good")
    asyncio.run(runner.run_until_idle())

    assert store.get_job(failed.id).status is JobStatus.FAILED
    assert store.get_job(failed.id).error == "RuntimeError: kaboom"
    assert store.get_job(ok.id).status is JobStatus.SUCCEEDED


def test_cooperative_cancel_between_steps(store: Store, runner: JobRunner) -> None:
    async def handler(ctx: JobContext) -> None:
        ctx.log("before cancel point")
        runner.request_cancel(ctx.job.id)  # simulate an operator clicking cancel
        ctx.raise_if_cancelled()
        ctx.log("never reached")

    runner.register("cancellable", handler)
    job = runner.submit("cancellable")
    asyncio.run(runner.run_until_idle())

    assert store.get_job(job.id).status is JobStatus.CANCELLED
    messages = [e.message for e in store.events(job.id)]
    assert "never reached" not in messages
    assert "job cancelled" in messages


def test_log_replace_overwrites_the_previous_line_instead_of_appending(
    store: Store, runner: JobRunner
) -> None:
    async def handler(ctx: JobContext) -> None:
        ctx.log("before")
        seq = None
        for attempt in range(1, 6):
            event = ctx.log(f"still waiting (check {attempt}/5)", replace=seq)
            seq = event.seq
        ctx.log("after")

    runner.register("chatty-poll", handler)
    job = runner.submit("chatty-poll")
    asyncio.run(runner.run_until_idle())

    messages = [e.message for e in store.events(job.id)]
    # 5 replace calls collapse to one line — not one line per attempt.
    assert messages == ["before", "still waiting (check 5/5)", "after", "job succeeded"]


def test_handler_raising_job_timed_out_marks_timed_out_not_failed(
    store: Store, runner: JobRunner
) -> None:
    async def handler(ctx: JobContext) -> None:
        raise JobTimedOut("gave up waiting for confirmation")

    runner.register("slow", handler)
    job = runner.submit("slow")
    asyncio.run(runner.run_until_idle())

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.TIMED_OUT
    assert finished.error == "gave up waiting for confirmation"
    messages = [e.message for e in store.events(job.id)]
    assert "job timed out: gave up waiting for confirmation" in messages


def test_cancel_while_still_pending_never_runs(store: Store, runner: JobRunner) -> None:
    ran = False

    async def handler(ctx: JobContext) -> None:
        nonlocal ran
        ran = True

    runner.register("queued", handler)
    job = runner.submit("queued")
    runner.request_cancel(job.id)
    asyncio.run(runner.run_until_idle())

    assert ran is False
    assert store.get_job(job.id).status is JobStatus.CANCELLED


def test_submit_records_triggered_by(store: Store, runner: JobRunner) -> None:
    async def handler(ctx: JobContext) -> None: ...

    runner.register("ok", handler)
    job = runner.submit("ok", triggered_by="alice")
    assert job.username == "alice"
    assert store.get_job(job.id).username == "alice"

    anon = runner.submit("ok")
    assert anon.username is None


def test_unknown_kind_rejected_at_submit(runner: JobRunner) -> None:
    with pytest.raises(JobError, match="no handler"):
        runner.submit("not.registered")


def test_duplicate_registration_rejected(runner: JobRunner) -> None:
    async def handler(ctx: JobContext) -> None: ...

    runner.register("dup", handler)
    with pytest.raises(JobError, match="already registered"):
        runner.register("dup", handler)


def test_concurrency_is_bounded(store: Store) -> None:
    runner = JobRunner(store, max_concurrent=2)
    running = 0
    peak = 0

    async def handler(ctx: JobContext) -> None:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.02)
        running -= 1

    runner.register("slow", handler)
    for _ in range(5):
        runner.submit("slow")
    asyncio.run(runner.run_until_idle())

    assert peak == 2
    assert all(j.status is JobStatus.SUCCEEDED for j in store.list_jobs())


def test_recover_marks_orphaned_running_jobs(store: Store, runner: JobRunner) -> None:
    # Simulate a job that was mid-flight when the previous process died.
    orphan = JobRecord(kind="cpuse.install", target="mgmt-01")
    store.insert_job(orphan)
    assert store.claim_next_pending() is not None  # now RUNNING, no live task

    interrupted = runner.recover()
    assert [j.id for j in interrupted] == [orphan.id]
    assert store.get_job(orphan.id).status is JobStatus.INTERRUPTED


def test_serve_processes_and_stops(store: Store, runner: JobRunner) -> None:
    async def handler(ctx: JobContext) -> None:
        ctx.log("served")
        runner.stop()

    runner.register("one-shot", handler)
    job = runner.submit("one-shot")
    asyncio.run(asyncio.wait_for(runner.serve(poll_interval=0.05), timeout=5))

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED


def test_max_concurrent_validated(store: Store) -> None:
    with pytest.raises(JobError):
        JobRunner(store, max_concurrent=0)
