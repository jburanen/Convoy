from __future__ import annotations

from collections.abc import Callable
from typing import Any

from convoy.errors import CredentialError, InventoryError
from convoy.services.state_refresh import REFRESH_AFTER_JOB_KINDS, StateRefreshService
from convoy.store import JobRecord, JobStatus, Store


class FakePatching:
    """Stands in for PatchingService — only the two calls this service makes."""

    def __init__(self, *, role: str = "primary_sms", error: Exception | None = None) -> None:
        self.role = role
        self.error = error
        self.detected: list[tuple[str, str]] = []

    def host_role(self, environment: str, host_name: str) -> str:
        if isinstance(self.role, Exception):
            raise self.role
        return self.role

    def detect(self, environment: str, host_name: str, **kwargs: Any) -> None:
        if self.error is not None:
            raise self.error
        self.detected.append((environment, host_name))


class FakeSpark:
    def __init__(self) -> None:
        self.detected: list[tuple[str, str]] = []

    def detect(self, environment: str, host_name: str, **kwargs: Any) -> None:
        self.detected.append((environment, host_name))


def _service(
    store: Store,
    patching: FakePatching,
    spark: FakeSpark,
    spawn: Callable[[Callable[[], None]], None] = lambda work: work(),
) -> StateRefreshService:
    # Default spawn runs the work inline, so tests never deal with threads.
    return StateRefreshService(
        patching=patching,  # type: ignore[arg-type]
        spark=spark,  # type: ignore[arg-type]
        store=store,
        spawn=spawn,
    )


def _job(
    store: Store, kind: str, *, status: JobStatus, target: str | None = "mgmt-01"
) -> JobRecord:
    job = JobRecord(kind=kind, target=target, environment="default", status=status)
    store.insert_job(job)
    return job


def test_refresh_queries_a_cpuse_host(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching, spark = FakePatching(), FakeSpark()
    assert _service(store, patching, spark).refresh("default", "mgmt-01", reason="test") is True
    assert patching.detected == [("default", "mgmt-01")]
    assert spark.detected == []


def test_refresh_uses_the_spark_path_for_a_spark_firewall(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    # No CPUSE agent on Spark — PatchingService.detect must never be called.
    patching, spark = FakePatching(role="spark_firewall"), FakeSpark()
    assert _service(store, patching, spark).refresh("default", "spark-01", reason="test") is True
    assert spark.detected == [("default", "spark-01")]
    assert patching.detected == []


def test_missing_credentials_are_not_an_error(tmp_path: Any) -> None:
    # Storage-disabled environments and API-only management servers land here;
    # the operator's own Refresh (which can prompt) is still the way in.
    store = Store(tmp_path / "s.db")
    patching = FakePatching(error=CredentialError("no credential set assigned"))
    assert _service(store, patching, FakeSpark()).refresh("default", "x", reason="t") is False


def test_an_unreachable_host_never_raises(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching = FakePatching(error=OSError("connection refused"))
    assert _service(store, patching, FakeSpark()).refresh("default", "x", reason="t") is False


def test_a_host_deleted_before_the_refresh_ran_is_skipped(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching = FakePatching()
    patching.role = InventoryError("unknown host")  # type: ignore[assignment]
    assert _service(store, patching, FakeSpark()).refresh("default", "gone", reason="t") is False


def test_after_job_refreshes_on_failure_not_just_success(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching, spark = FakePatching(), FakeSpark()
    service = _service(store, patching, spark)
    for status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.TIMED_OUT):
        job = _job(store, "cpuse.install", status=status)
        service.after_job(job.id)
    assert patching.detected == [("default", "mgmt-01")] * 4


def test_after_job_ignores_kinds_that_change_nothing_on_a_host(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching = FakePatching()
    service = _service(store, patching, FakeSpark())
    for kind in ("pkgs.upload", "cred.add", "prov.edit", "prov.delete", "cdt.execute"):
        service.after_job(_job(store, kind, status=JobStatus.SUCCEEDED).id)
    # ...and a job with no host target (a pkgs.* job's target is a filename).
    service.after_job(_job(store, "cpuse.install", status=JobStatus.FAILED, target=None).id)
    assert patching.detected == []


def test_the_job_kinds_that_trigger_a_refresh() -> None:
    # Guards the frontend's STATE_REFRESH_JOB_KINDS mirror in app.js.
    assert set(REFRESH_AFTER_JOB_KINDS) == {
        "cpuse.import",
        "cpuse.import_cloud",
        "cpuse.install",
        "cpuse.uninstall",
        "spark.scp",
        "spark.install",
        "pkgs.push_to_repo",
        "prov.connect_primary",
    }


def test_one_refresh_per_host_at_a_time(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching = FakePatching()
    queued: list[Callable[[], None]] = []
    service = _service(store, patching, FakeSpark(), spawn=queued.append)

    service.schedule("default", "mgmt-01", reason="first")
    service.schedule("default", "mgmt-01", reason="second")  # still in flight — dropped
    service.schedule("default", "mgmt-02", reason="other host")
    assert len(queued) == 2

    for work in queued:
        work()
    assert patching.detected == [("default", "mgmt-01"), ("default", "mgmt-02")]

    # Once the first one finished, the host can be refreshed again.
    service.schedule("default", "mgmt-01", reason="later")
    assert len(queued) == 3


def test_a_spawn_that_fails_releases_the_host(tmp_path: Any) -> None:
    store = Store(tmp_path / "s.db")
    patching = FakePatching()

    def boom(work: Callable[[], None]) -> None:
        raise RuntimeError("can't start thread")

    service = _service(store, patching, FakeSpark(), spawn=boom)
    service.schedule("default", "mgmt-01", reason="t")  # swallowed, not raised
    # Not stuck "in flight": a later schedule for the same host still runs.
    ran: list[Callable[[], None]] = []
    service._spawn = ran.append  # type: ignore[attr-defined]
    service.schedule("default", "mgmt-01", reason="t")
    assert len(ran) == 1
