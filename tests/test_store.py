from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from chkp_cpuse_orch.errors import StoreError
from chkp_cpuse_orch.store import (
    _MIGRATIONS,
    CredentialSetRow,
    EnvHostRow,
    FirewallRow,
    JobRecord,
    JobStatus,
    PackageRecord,
    SessionRow,
    Store,
    utcnow,
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


def test_list_jobs_limit_zero_or_less_is_unlimited(store: Store) -> None:
    for _ in range(3):
        store.insert_job(JobRecord(kind="a"))
    assert len(store.list_jobs(limit=2)) == 2
    assert len(store.list_jobs(limit=0)) == 3  # the Jobs tab's "All" option
    assert len(store.list_jobs(limit=-1)) == 3


def test_list_jobs_multi_value_filters(store: Store) -> None:
    a = JobRecord(kind="cpuse.install", target="mgmt-01", environment="corp", username="alice")
    b = JobRecord(kind="cpuse.import", target="mgmt-02", environment="corp", username="bob")
    c = JobRecord(kind="cpuse.install", target="mgmt-01", environment="dmz", username="alice")
    for job in (a, b, c):
        store.insert_job(job)
    store.claim_next_pending()  # a -> RUNNING
    store.finish_job(a.id, JobStatus.SUCCEEDED)

    # Each field is OR'd within itself...
    assert {j.id for j in store.list_jobs(kinds=["cpuse.install"])} == {a.id, c.id}
    assert {j.id for j in store.list_jobs(targets=["mgmt-01", "mgmt-02"])} == {a.id, b.id, c.id}
    assert {j.id for j in store.list_jobs(usernames=["alice"])} == {a.id, c.id}
    # ...and AND'd across fields.
    assert {j.id for j in store.list_jobs(kinds=["cpuse.install"], environments=["dmz"])} == {c.id}
    assert {j.id for j in store.list_jobs(usernames=["alice"], environments=["dmz"])} == {c.id}
    assert {j.id for j in store.list_jobs(statuses=[JobStatus.SUCCEEDED])} == {a.id}
    assert store.list_jobs(kinds=["nonexistent"]) == []


def test_list_job_facets_reflects_every_job_not_just_the_display_limit(store: Store) -> None:
    a = JobRecord(kind="cpuse.install", target="mgmt-01", environment="corp", username="alice")
    b = JobRecord(kind="cpuse.import", target=None, environment="dmz")  # no target, no username
    store.insert_job(a)
    store.insert_job(b)
    store.claim_next_pending()  # a (oldest) -> RUNNING
    store.finish_job(a.id, JobStatus.SUCCEEDED)  # b stays PENDING, untouched

    facets = store.list_job_facets()
    assert facets["kinds"] == ["cpuse.import", "cpuse.install"]
    assert facets["targets"] == ["mgmt-01"]  # null target excluded, not a selectable option
    assert facets["environments"] == ["corp", "dmz"]
    assert set(facets["statuses"]) == {"succeeded", "pending"}
    assert facets["usernames"] == ["alice"]  # null username excluded
    # A limit=1 fetch would only surface one job's kind — facets must not be
    # derived from a limited/paginated query.
    assert len(store.list_jobs(limit=1)) == 1
    assert len(facets["kinds"]) == 2


def test_delete_job_cascades_its_events(store: Store) -> None:
    job = JobRecord(kind="a")
    store.insert_job(job)
    store.append_event(job.id, "one")
    assert store.delete_job(job.id) is True
    with pytest.raises(StoreError):
        store.get_job(job.id)
    assert store.events(job.id) == []  # cascaded, not orphaned
    assert store.delete_job(job.id) is False  # already gone


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


def test_credential_set_crud(store: Store) -> None:
    store.insert_environment("default", credential_storage_enabled=True)
    store.upsert_credential_set(
        CredentialSetRow(
            environment="default", name="primary", ssh_username="admin", ssh_password_ct=b"ct"
        )
    )
    got = store.get_credential_set_by_name("default", "primary")
    assert got is not None and got.ssh_password_ct == b"ct" and got.ssh_username == "admin"
    # Upsert on the same (environment, name) replaces every secret column.
    store.upsert_credential_set(
        CredentialSetRow(environment="default", name="primary", ssh_private_key_ct=b"key")
    )
    got = store.get_credential_set_by_name("default", "primary")
    assert got is not None and got.ssh_password_ct is None and got.ssh_private_key_ct == b"key"
    assert len(store.list_credential_sets("default")) == 1
    assert store.delete_credential_set("default", "primary") is True
    assert store.delete_credential_set("default", "primary") is False


def test_assign_credential_set_and_fk_set_null(store: Store) -> None:
    store.insert_environment("default", credential_storage_enabled=True)
    store.upsert_env_host(
        EnvHostRow(environment="default", name="mgmt-01", address="1.2.3.4", role="management")
    )
    store.upsert_credential_set(
        CredentialSetRow(environment="default", name="primary", ssh_password_ct=b"ct")
    )
    set_id = store.get_credential_set_by_name("default", "primary").id  # type: ignore[union-attr]

    assert store.assign_credential_set("default", "mgmt-01", set_id) is True
    assert store.list_env_hosts("default")[0].credential_set_id == set_id
    # A server edit must not clear the assignment.
    store.upsert_env_host(
        EnvHostRow(environment="default", name="mgmt-01", address="9.9.9.9", role="management")
    )
    assert store.list_env_hosts("default")[0].credential_set_id == set_id
    # Deleting the set auto-unassigns via ON DELETE SET NULL.
    store.delete_credential_set("default", "primary")
    assert store.list_env_hosts("default")[0].credential_set_id is None
    # Assigning against an unknown server reports no row updated.
    assert store.assign_credential_set("default", "ghost", None) is False


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


def test_package_expiry_roundtrip_and_listing(store: Store) -> None:
    from datetime import timedelta

    from chkp_cpuse_orch.store import utcnow

    now = utcnow()
    store.insert_package(
        PackageRecord(
            filename="soon.tgz",
            sha1="a" * 40,
            sha256="b" * 64,
            size=1,
            expires_at=now - timedelta(minutes=1),  # already past
        )
    )
    store.insert_package(
        PackageRecord(filename="pinned.tgz", sha1="c" * 40, sha256="d" * 64, size=1)
    )  # expires_at defaults to None → never listed as expired

    expired = store.list_expired_packages(now)
    assert [p.filename for p in expired] == ["soon.tgz"]

    # Pinning clears the deadline; unpinning sets one again.
    assert store.set_package_expiry("soon.tgz", None) is True
    assert store.list_expired_packages(now) == []
    assert store.set_package_expiry("ghost.tgz", None) is False


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


def test_environment_and_env_host_crud(store: Store) -> None:
    store.insert_environment("corp")
    assert store.environment_exists("corp") is True
    assert [e.name for e in store.list_environments()] == ["corp"]

    store.upsert_env_host(
        EnvHostRow(environment="corp", name="mgmt-01", address="10.0.0.1", role="management")
    )
    # Upsert on (environment, name) updates in place.
    store.upsert_env_host(
        EnvHostRow(
            environment="corp",
            name="mgmt-01",
            address="10.0.0.9",
            role="management",
            ssh_user="svc",
        )
    )
    hosts = store.list_env_hosts("corp")
    assert len(hosts) == 1
    assert hosts[0].address == "10.0.0.9"
    assert hosts[0].ssh_user == "svc"


def test_firewall_crud(store: Store) -> None:
    store.insert_environment("corp")
    assert store.list_firewalls("corp") == []

    store.upsert_firewall(
        FirewallRow(environment="corp", name="fw-01", address="10.0.0.1", role="gateway")
    )
    # Upsert on (environment, name) updates in place.
    store.upsert_firewall(
        FirewallRow(
            environment="corp",
            name="fw-01",
            address="10.0.0.9",
            role="gateway",
            ssh_user="svc",
        )
    )
    firewalls = store.list_firewalls("corp")
    assert len(firewalls) == 1
    assert firewalls[0].address == "10.0.0.9"
    assert firewalls[0].ssh_user == "svc"
    assert store.get_firewall("corp", "fw-01") is not None
    assert store.get_firewall("corp", "ghost") is None

    assert store.delete_firewall("corp", "fw-01") is True
    assert store.delete_firewall("corp", "fw-01") is False
    assert store.list_firewalls("corp") == []


def test_firewall_credential_assignment_and_fk_set_null(store: Store) -> None:
    store.insert_environment("corp", credential_storage_enabled=True)
    store.upsert_firewall(
        FirewallRow(environment="corp", name="fw-01", address="10.0.0.1", role="gateway")
    )
    store.upsert_credential_set(
        CredentialSetRow(environment="corp", name="primary", ssh_password_ct=b"ct")
    )
    set_id = store.get_credential_set_by_name("corp", "primary").id  # type: ignore[union-attr]

    assert store.assign_firewall_credential_set("corp", "fw-01", set_id) is True
    assert store.list_firewalls("corp")[0].credential_set_id == set_id
    # Deleting the set auto-unassigns via ON DELETE SET NULL.
    store.delete_credential_set("corp", "primary")
    assert store.list_firewalls("corp")[0].credential_set_id is None
    assert store.assign_firewall_credential_set("corp", "ghost", None) is False


def test_deleting_environment_cascades_to_firewalls(store: Store) -> None:
    store.insert_environment("corp")
    store.upsert_firewall(
        FirewallRow(environment="corp", name="fw-01", address="10.0.0.1", role="gateway")
    )
    store.delete_environment("corp")
    store.insert_environment("corp")
    assert store.list_firewalls("corp") == []  # cascade removed the row


def test_environment_is_mds_defaults_false_and_toggles(store: Store) -> None:
    store.insert_environment("corp")
    assert store.get_environment("corp").is_mds is False  # type: ignore[union-attr]

    store.insert_environment("mds-estate", is_mds=True)
    assert store.get_environment("mds-estate").is_mds is True  # type: ignore[union-attr]

    assert store.set_environment_kind("corp", True) is True
    assert store.get_environment("corp").is_mds is True  # type: ignore[union-attr]
    assert store.set_environment_kind("ghost", True) is False


def test_rename_environment_carries_is_mds(store: Store) -> None:
    store.insert_environment("corp", is_mds=True)
    assert store.rename_environment("corp", "Corp HQ") is True
    assert store.get_environment("Corp HQ").is_mds is True  # type: ignore[union-attr]


def test_deleting_environment_cascades_to_hosts(store: Store) -> None:
    store.insert_environment("corp")
    store.upsert_env_host(EnvHostRow(environment="corp", name="m1", address="10.0.0.1", role="mds"))
    assert store.delete_environment("corp") is True
    assert store.list_env_hosts("corp") == []  # cascade removed the host row
    assert store.environment_exists("corp") is False


def test_duplicate_environment_raises(store: Store) -> None:
    import sqlite3

    store.insert_environment("corp")
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_environment("corp")


def test_rename_environment_moves_children(store: Store) -> None:
    store.insert_environment("corp")
    store.upsert_env_host(EnvHostRow(environment="corp", name="m1", address="10.0.0.1", role="mds"))
    store.upsert_credential_set(
        CredentialSetRow(environment="corp", name="primary", ssh_password_ct=b"x")
    )
    store.insert_job(JobRecord(kind="cpuse.import", target="m1", environment="corp"))

    assert store.rename_environment("corp", "Corp HQ") is True

    assert store.environment_exists("corp") is False
    assert [h.name for h in store.list_env_hosts("Corp HQ")] == ["m1"]
    assert len(store.list_credential_sets("Corp HQ")) == 1
    assert store.list_credential_sets("corp") == []
    jobs = store.list_jobs()
    assert jobs and all(j.environment == "Corp HQ" for j in jobs)


def test_rename_environment_errors(store: Store) -> None:
    import sqlite3

    assert store.rename_environment("ghost", "x") is False
    store.insert_environment("a")
    store.insert_environment("b")
    with pytest.raises(sqlite3.IntegrityError):
        store.rename_environment("a", "b")
    # The failed rename rolled back atomically — "a" is intact.
    assert store.environment_exists("a") is True


def test_v3_database_upgrades_to_env_tables(tmp_path: Path) -> None:
    # A v3 DB (as deployed before this feature) must gain the environments +
    # env_hosts tables on reopen, keeping existing data.
    import sqlite3

    path = tmp_path / "orch.db"
    conn = sqlite3.connect(path)
    for script in _MIGRATIONS[:3]:
        conn.executescript(script)
    conn.execute("PRAGMA user_version = 3")
    conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
    conn.commit()
    conn.close()

    store = Store(path)
    assert store.get_meta("k") == "v"
    store.insert_environment("corp")  # new table works
    assert [e.name for e in store.list_environments()] == ["corp"]


def test_session_roundtrip_touch_delete_and_purge(store: Store) -> None:
    now = utcnow()
    fresh = SessionRow(token_hash="h-fresh", username="alice", last_seen_at=now)
    stale = SessionRow(token_hash="h-stale", username="bob", last_seen_at=now - timedelta(hours=2))
    store.create_session(fresh)
    store.create_session(stale)

    got = store.get_session("h-fresh")
    assert got is not None and got.username == "alice"

    # Touch advances last_seen_at.
    later = now + timedelta(minutes=5)
    store.touch_session("h-fresh", now=later)
    assert store.get_session("h-fresh").last_seen_at == later  # type: ignore[union-attr]

    # Purge removes only rows idle past the cutoff.
    assert store.purge_idle_sessions(now - timedelta(minutes=30)) == 1
    assert store.get_session("h-stale") is None
    assert store.get_session("h-fresh") is not None

    assert store.delete_session("h-fresh") is True
    assert store.get_session("h-fresh") is None


def test_future_schema_version_refused(tmp_path: Path) -> None:
    path = tmp_path / "orch.db"
    Store(path)
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(StoreError, match="newer"):
        Store(path)
