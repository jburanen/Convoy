from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from chkp_cpuse_orch.archive import JobArchiver
from chkp_cpuse_orch.errors import StoreError
from chkp_cpuse_orch.store import JobRecord, JobStatus, Store, utcnow


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


def _old_finished_job(
    store: Store, *, age_days: int = 400, status: JobStatus = JobStatus.SUCCEEDED
) -> JobRecord:
    job = JobRecord(
        kind="cpuse.install", target="mgmt-01", created_at=utcnow() - timedelta(days=age_days)
    )
    store.insert_job(job)
    store.append_event(job.id, "installing")
    store.append_event(job.id, "confirmed: package is installed")
    if status.is_terminal:
        store.finish_job(job.id, status)
    return job


def test_archives_and_deletes_old_terminal_jobs(store: Store, tmp_path: Path) -> None:
    archive_path = tmp_path / "job_archive.log"
    job = _old_finished_job(store)

    archived = JobArchiver(store, archive_path).run()

    assert archived == 1
    with pytest.raises(StoreError):
        store.get_job(job.id)

    lines = archive_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["id"] == job.id
    assert record["kind"] == "cpuse.install"
    assert record["status"] == "succeeded"
    assert [e["message"] for e in record["events"]] == [
        "installing",
        "confirmed: package is installed",
    ]


def test_leaves_recent_jobs_alone(store: Store, tmp_path: Path) -> None:
    job = _old_finished_job(store, age_days=10)  # well under the 366-day default
    archived = JobArchiver(store, tmp_path / "job_archive.log").run()
    assert archived == 0
    assert store.get_job(job.id) is not None  # still there, untouched


def test_leaves_old_but_still_active_jobs_alone(store: Store, tmp_path: Path) -> None:
    # PENDING is non-terminal by construction (finish_job is never called) —
    # however old, it isn't actually finished yet.
    job = _old_finished_job(store, age_days=400, status=JobStatus.PENDING)
    archived = JobArchiver(store, tmp_path / "job_archive.log").run()
    assert archived == 0
    assert store.get_job(job.id).status is JobStatus.PENDING


def test_install_log_is_included_in_the_archived_record(store: Store, tmp_path: Path) -> None:
    job = _old_finished_job(store)
    store.set_install_log(job.id, "captured log text\nsecond line")
    archive_path = tmp_path / "job_archive.log"

    JobArchiver(store, archive_path).run()

    record = json.loads(archive_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["install_log"] == "captured log text\nsecond line"


def test_enforces_max_bytes_by_dropping_oldest_entries(store: Store, tmp_path: Path) -> None:
    # Three archivable jobs, oldest first, each with a long install_log so
    # every archived line is a predictable, substantial size.
    job_ids = []
    for age in (403, 402, 401):  # oldest to newest
        job = _old_finished_job(store, age_days=age)
        store.set_install_log(job.id, "x" * 500)
        job_ids.append(job.id)

    archive_path = tmp_path / "job_archive.log"
    # Each archived line is ~1KB here (500-byte install_log + JSON overhead) —
    # 1500 bytes leaves room for exactly one of the three.
    archived = JobArchiver(store, archive_path, max_bytes=1500).run()

    assert archived == 3  # all three were archived (and removed from the DB)...
    assert archive_path.stat().st_size <= 1500  # ...but the file stayed bounded

    surviving_ids = [json.loads(line)["id"] for line in archive_path.read_text().splitlines()]
    # Whatever survived is a suffix of the oldest-to-newest write order — the
    # oldest entries were the ones dropped, not the newest.
    assert surviving_ids == job_ids[len(job_ids) - len(surviving_ids) :]
    assert job_ids[-1] in surviving_ids  # the newest always survives


def test_run_is_a_noop_with_nothing_to_archive(store: Store, tmp_path: Path) -> None:
    archive_path = tmp_path / "job_archive.log"
    assert JobArchiver(store, archive_path).run() == 0
    assert not archive_path.exists()  # never created if there's nothing to write
