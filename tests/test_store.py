from __future__ import annotations

from pathlib import Path

import pytest

from chkp_cpuse_orch.errors import StoreError
from chkp_cpuse_orch.store import (
    _MIGRATIONS,
    CredentialRecord,
    JobRecord,
    JobStatus,
    PackageRecord,
    Store,
)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


def test_reopen_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "orch.db"
    Store(path).set_meta("k", "v")
    # Second open must not re-run migrations or lose data.
    assert Store(path).get_meta("k") == "v"


def test_meta_roundtrip_and_overwrite(store: Store) -> None:
    assert store.get_meta("missing") is None
    store.set_meta("k", "v1")
    store.set_meta("k", "v2")
    assert store.get_meta("k") == "v2"


def test_job_roundtrip(store: Store) -> None:
    job = JobRecord(kind="cpuse.import", target="mgmt-01", params={"package": "jhf.tgz"})
    store.insert_job(job)
    loaded = store.get_job(job.id)
    assert loaded.kind == "cpuse.import"
    assert loaded.target == "mgmt-01"
    assert loaded.params == {"package": "jhf.tgz"}
    assert loaded.status is JobStatus.PENDING
    assert loaded.created_at == job.created_at  # tz-aware datetime survives storage


def test_get_missing_job_raises(store: Store) -> None:
    with pytest.raises(StoreError):
        store.get_job("nope")


def test_claim_is_fifo_and_moves_to_running(store: Store) -> None:
    first = JobRecord(kind="a")
    second = JobRecord(kind="b")
    store.insert_job(first)
    store.insert_job(second)
    claimed = store.claim_next_pending()
    assert claimed is not None
    assert claimed.id == first.id
    assert claimed.status is JobStatus.RUNNING
    assert claimed.started_at is not None
    # Claiming drains the queue in order, then returns None.
    next_claim = store.claim_next_pending()
    assert next_claim is not None and next_claim.id == second.id
    assert store.claim_next_pending() is None


def test_finish_job_requires_terminal_status(store: Store) -> None:
    job = JobRecord(kind="a")
    store.insert_job(job)
    with pytest.raises(StoreError):
        store.finish_job(job.id, JobStatus.RUNNING)
    store.finish_job(job.id, JobStatus.FAILED, error="boom")
    loaded = store.get_job(job.id)
    assert loaded.status is JobStatus.FAILED
    assert loaded.error == "boom"
    assert loaded.finished_at is not None


def test_cancel_flag_roundtrip_and_finished_jobs_rejected(store: Store) -> None:
    job = JobRecord(kind="a")
    store.insert_job(job)
    assert store.is_cancel_requested(job.id) is False
    store.request_cancel(job.id)
    assert store.is_cancel_requested(job.id) is True
    store.finish_job(job.id, JobStatus.CANCELLED)
    with pytest.raises(StoreError):
        store.request_cancel(job.id)  # already terminal


def test_mark_interrupted_only_touches_running(store: Store) -> None:
    running = JobRecord(kind="a")
    pending = JobRecord(kind="b")
    store.insert_job(running)
    store.insert_job(pending)
    assert store.claim_next_pending() is not None  # `running` → RUNNING
    interrupted = store.mark_interrupted()
    assert [j.id for j in interrupted] == [running.id]
    assert store.get_job(running.id).status is JobStatus.INTERRUPTED
    assert store.get_job(pending.id).status is JobStatus.PENDING


def test_list_jobs_filters_by_status(store: Store) -> None:
    a = JobRecord(kind="a")
    b = JobRecord(kind="b")
    store.insert_job(a)
    store.insert_job(b)
    store.claim_next_pending()
    assert {j.id for j in store.list_jobs(JobStatus.PENDING)} == {b.id}
    assert len(store.list_jobs()) == 2


def test_events_append_and_resume_from_seq(store: Store) -> None:
    job = JobRecord(kind="a")
    store.insert_job(job)
    e1 = store.append_event(job.id, "one")
    e2 = store.append_event(job.id, "two", level="warning")
    all_events = store.events(job.id)
    assert [e.message for e in all_events] == ["one", "two"]
    assert all_events[1].level == "warning"
    # A poller that saw e1 resumes and gets only e2.
    assert [e.seq for e in store.events(job.id, after_seq=e1.seq)] == [e2.seq]


def test_credential_upsert_get_delete(store: Store) -> None:
    rec = CredentialRecord(host="mgmt-01", kind="ssh_password", username="admin", ciphertext=b"x")
    store.upsert_credential(rec)
    # Upsert on same (host, kind) replaces ciphertext/username.
    store.upsert_credential(
        CredentialRecord(host="mgmt-01", kind="ssh_password", username="admin2", ciphertext=b"y")
    )
    loaded = store.get_credential("mgmt-01", "ssh_password")
    assert loaded is not None
    assert loaded.username == "admin2"
    assert loaded.ciphertext == b"y"
    assert len(store.list_credentials()) == 1
    assert store.delete_credential("mgmt-01", "ssh_password") is True
    assert store.delete_credential("mgmt-01", "ssh_password") is False
    assert store.get_credential("mgmt-01", "ssh_password") is None


def test_list_credentials_filters_by_host(store: Store) -> None:
    store.upsert_credential(CredentialRecord(host="a", kind="ssh_password", ciphertext=b"1"))
    store.upsert_credential(CredentialRecord(host="a", kind="api_key", ciphertext=b"2"))
    store.upsert_credential(CredentialRecord(host="b", kind="ssh_password", ciphertext=b"3"))
    assert len(store.list_credentials("a")) == 2
    assert len(store.list_credentials()) == 3


def test_package_roundtrip_and_unique_filename(store: Store) -> None:
    rec = PackageRecord(filename="jhf.tgz", sha1="a" * 40, sha256="b" * 64, size=123)
    store.insert_package(rec)
    loaded = store.get_package("jhf.tgz")
    assert loaded is not None
    assert loaded.sha256 == "b" * 64
    assert loaded.size == 123
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        store.insert_package(
            PackageRecord(filename="jhf.tgz", sha1="c" * 40, sha256="d" * 64, size=1)
        )
    assert [p.filename for p in store.list_packages()] == ["jhf.tgz"]
    assert store.delete_package("jhf.tgz") is True
    assert store.get_package("jhf.tgz") is None


def test_v1_database_upgrades_in_place(tmp_path: Path) -> None:
    # Build a schema-v1 DB by hand (as Phase 1 shipped it), then reopen: the
    # packages table must appear without disturbing existing data.
    import sqlite3

    path = tmp_path / "orch.db"
    conn = sqlite3.connect(path)
    conn.executescript(_MIGRATIONS[0])
    conn.execute("PRAGMA user_version = 1")
    conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
    conn.commit()
    conn.close()

    store = Store(path)
    assert store.get_meta("k") == "v"  # survived the upgrade
    store.insert_package(PackageRecord(filename="p.tgz", sha1="a" * 40, sha256="b" * 64, size=1))
    assert store.get_package("p.tgz") is not None


def test_future_schema_version_refused(tmp_path: Path) -> None:
    path = tmp_path / "orch.db"
    Store(path)
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(StoreError, match="newer"):
        Store(path)
