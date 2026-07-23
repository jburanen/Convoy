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


def test_prunes_archived_entries_past_the_retention_window(store: Store, tmp_path: Path) -> None:
    # Two jobs, both aged out of the DB (>366 days), but one is older than the
    # 3-year archive-retention window and the other isn't. Both get archived out
    # of the DB in this pass; only the within-window one stays in the file.
    stale = _old_finished_job(store, age_days=4 * 366)  # older than 3-year retention
    recent = _old_finished_job(store, age_days=400)  # aged out of the DB, within retention
    archive_path = tmp_path / "job_archive.log"

    archived = JobArchiver(store, archive_path, archive_retention_days=3 * 366).run()

    assert archived == 2  # both were archived out of the DB...
    surviving_ids = [json.loads(line)["id"] for line in archive_path.read_text().splitlines()]
    assert surviving_ids == [recent.id]  # ...but the >3-year-old entry was pruned from the file
    assert stale.id not in surviving_ids


def test_appending_prunes_preexisting_stale_entries(store: Store, tmp_path: Path) -> None:
    # An entry archived long ago (job created 4 years back) already sits in the
    # file. Archiving a freshly-aged-out job must, in the same pass, drop it.
    archive_path = tmp_path / "job_archive.log"
    stale_ts = (utcnow() - timedelta(days=4 * 366)).isoformat()
    archive_path.write_text(
        json.dumps({"id": "stale", "created_at": stale_ts}) + "\n", encoding="utf-8"
    )

    fresh = _old_finished_job(store, age_days=400)
    JobArchiver(store, archive_path, archive_retention_days=3 * 366).run()

    surviving_ids = [json.loads(line)["id"] for line in archive_path.read_text().splitlines()]
    assert surviving_ids == [fresh.id]  # the stale entry is gone, the new one remains


def test_unparseable_archive_lines_are_never_dropped(store: Store, tmp_path: Path) -> None:
    # A legacy/hand-edited line without a parseable created_at is kept even when
    # a prune runs, so pruning never silently loses audit data.
    archive_path = tmp_path / "job_archive.log"
    archive_path.write_text("not json at all\n", encoding="utf-8")

    _old_finished_job(store, age_days=400)  # forces an append + prune pass
    JobArchiver(store, archive_path, archive_retention_days=3 * 366).run()

    lines = archive_path.read_text().splitlines()
    assert "not json at all" in lines


def test_run_is_a_noop_with_nothing_to_archive(store: Store, tmp_path: Path) -> None:
    archive_path = tmp_path / "job_archive.log"
    assert JobArchiver(store, archive_path).run() == 0
    assert not archive_path.exists()  # never created if there's nothing to write
