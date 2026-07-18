"""SQLite persistence on the git-ignored data volume.

Holds background-job state, credential *ciphertext*, and (later) package metadata.
Secrets are stored only as ciphertext — encryption lives in ``credentials.py`` and
the master key never touches this module or the disk. Implemented on stdlib
``sqlite3`` (connection-per-call + WAL) to keep dependencies minimal; the schema is
small enough that an ORM would be more code than the SQL. See
.claude/memory/patching-web-design.md and security-hygiene.md.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .errors import StoreError


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    # Was RUNNING when the process died (container restart mid-install).
    # Never resumed automatically — the operator re-checks host state first.
    INTERRUPTED = "interrupted"

    @property
    def is_terminal(self) -> bool:
        return self not in (JobStatus.PENDING, JobStatus.RUNNING)


class JobRecord(BaseModel):
    """One long-running operation (e.g. ``cpuse.import`` on one mgmt server)."""

    id: str = Field(default_factory=new_id)
    kind: str
    target: str | None = None  # inventory Host.name this job acts on
    params: dict[str, Any] = Field(default_factory=dict)
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    cancel_requested: bool = False


class JobEvent(BaseModel):
    """One progress line of a job; streamed to the UI, kept for audit."""

    seq: int
    job_id: str
    ts: datetime
    level: str
    message: str


class CredentialRecord(BaseModel):
    """Ciphertext row — the store never sees plaintext secrets."""

    id: str = Field(default_factory=new_id)
    host: str  # inventory Host.name, or "*" for a fleet-wide default
    kind: str  # CredentialKind value; kept as str so the schema stays dumb
    username: str | None = None
    ciphertext: bytes
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# Append-only: each entry is one schema version, applied in order. Never edit an
# entry that has shipped — add a new one.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE credentials (
        id         TEXT PRIMARY KEY,
        host       TEXT NOT NULL,
        kind       TEXT NOT NULL,
        username   TEXT,
        ciphertext BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (host, kind)
    );

    CREATE TABLE jobs (
        id               TEXT PRIMARY KEY,
        kind             TEXT NOT NULL,
        target           TEXT,
        params           TEXT NOT NULL DEFAULT '{}',
        status           TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        started_at       TEXT,
        finished_at      TEXT,
        error            TEXT,
        cancel_requested INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_jobs_status_created ON jobs (status, created_at);

    CREATE TABLE job_events (
        seq     INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id  TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
        ts      TEXT NOT NULL,
        level   TEXT NOT NULL,
        message TEXT NOT NULL
    );
    CREATE INDEX idx_job_events_job ON job_events (job_id, seq);
    """,
)


class Store:
    """Typed facade over the SQLite file. Connection-per-call, WAL mode, so it is
    safe to share one instance across threads (FastAPI workers + job runner)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:  # commit on success, rollback on error
                yield conn
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self._connect() as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version > len(_MIGRATIONS):
                raise StoreError(
                    f"database {self.path} is at schema v{version}, newer than this "
                    f"build understands (v{len(_MIGRATIONS)}) — refusing to touch it"
                )
            for i, script in enumerate(_MIGRATIONS[version:], start=version + 1):
                conn.executescript(script)
                conn.execute(f"PRAGMA user_version = {i}")

    # -- meta ----------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # -- credentials (ciphertext only) ----------------------------------------

    def upsert_credential(self, rec: CredentialRecord) -> CredentialRecord:
        now = utcnow()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO credentials (id, host, kind, username, ciphertext,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (host, kind) DO UPDATE SET"
                " username = excluded.username, ciphertext = excluded.ciphertext,"
                " updated_at = excluded.updated_at",
                (
                    rec.id,
                    rec.host,
                    rec.kind,
                    rec.username,
                    rec.ciphertext,
                    rec.created_at.isoformat(),
                    now.isoformat(),
                ),
            )
        stored = self.get_credential(rec.host, rec.kind)
        assert stored is not None  # just written
        return stored

    def get_credential(self, host: str, kind: str) -> CredentialRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM credentials WHERE host = ? AND kind = ?", (host, kind)
            ).fetchone()
        return None if row is None else _credential_from_row(row)

    def list_credentials(self, host: str | None = None) -> list[CredentialRecord]:
        query = "SELECT * FROM credentials"
        args: tuple[Any, ...] = ()
        if host is not None:
            query += " WHERE host = ?"
            args = (host,)
        query += " ORDER BY host, kind"
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [_credential_from_row(r) for r in rows]

    def delete_credential(self, host: str, kind: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM credentials WHERE host = ? AND kind = ?", (host, kind))
        return cur.rowcount > 0

    # -- jobs ------------------------------------------------------------------

    def insert_job(self, job: JobRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO jobs (id, kind, target, params, status, created_at,"
                " started_at, finished_at, error, cancel_requested)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job.id,
                    job.kind,
                    job.target,
                    json.dumps(job.params),
                    job.status.value,
                    job.created_at.isoformat(),
                    _iso(job.started_at),
                    _iso(job.finished_at),
                    job.error,
                    int(job.cancel_requested),
                ),
            )

    def get_job(self, job_id: str) -> JobRecord:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise StoreError(f"job not found: {job_id!r}")
        return _job_from_row(row)

    def list_jobs(self, status: JobStatus | None = None, limit: int = 100) -> list[JobRecord]:
        query = "SELECT * FROM jobs"
        args: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            args = (status.value,)
        # rowid breaks created_at ties (clock granularity) in true insertion order.
        query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, (*args, limit)).fetchall()
        return [_job_from_row(r) for r in rows]

    def claim_next_pending(self) -> JobRecord | None:
        """Atomically move the oldest PENDING job to RUNNING and return it."""
        with self._connect() as conn:
            row = conn.execute(
                "UPDATE jobs SET status = ?, started_at = ? WHERE id ="
                " (SELECT id FROM jobs WHERE status = ? ORDER BY created_at, rowid LIMIT 1)"
                " RETURNING *",
                (JobStatus.RUNNING.value, utcnow().isoformat(), JobStatus.PENDING.value),
            ).fetchone()
        return None if row is None else _job_from_row(row)

    def finish_job(self, job_id: str, status: JobStatus, error: str | None = None) -> None:
        if not status.is_terminal:
            raise StoreError(f"finish_job called with non-terminal status {status}")
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?",
                (status.value, utcnow().isoformat(), error, job_id),
            )

    def request_cancel(self, job_id: str) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE jobs SET cancel_requested = 1 WHERE id = ? AND status IN (?, ?)",
                (job_id, JobStatus.PENDING.value, JobStatus.RUNNING.value),
            )
        if cur.rowcount == 0:
            raise StoreError(f"job {job_id!r} not found or already finished")

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT cancel_requested FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if row is None:
            raise StoreError(f"job not found: {job_id!r}")
        return bool(row["cancel_requested"])

    def mark_interrupted(self) -> list[JobRecord]:
        """Startup recovery: anything still RUNNING died with the previous process."""
        with self._connect() as conn:
            rows = conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?,"
                " error = COALESCE(error, 'process exited while job was running')"
                " WHERE status = ? RETURNING *",
                (JobStatus.INTERRUPTED.value, utcnow().isoformat(), JobStatus.RUNNING.value),
            ).fetchall()
        return [_job_from_row(r) for r in rows]

    # -- job events --------------------------------------------------------------

    def append_event(self, job_id: str, message: str, level: str = "info") -> JobEvent:
        ts = utcnow()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO job_events (job_id, ts, level, message) VALUES (?, ?, ?, ?)",
                (job_id, ts.isoformat(), level, message),
            )
            seq = cur.lastrowid
        assert seq is not None
        return JobEvent(seq=seq, job_id=job_id, ts=ts, level=level, message=message)

    def events(self, job_id: str, after_seq: int = 0) -> list[JobEvent]:
        """Events for a job, oldest first. ``after_seq`` lets pollers resume."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM job_events WHERE job_id = ? AND seq > ? ORDER BY seq",
                (job_id, after_seq),
            ).fetchall()
        return [
            JobEvent(
                seq=r["seq"],
                job_id=r["job_id"],
                ts=datetime.fromisoformat(r["ts"]),
                level=r["level"],
                message=r["message"],
            )
            for r in rows
        ]


def _iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.isoformat()


def _dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _job_from_row(row: sqlite3.Row) -> JobRecord:
    return JobRecord(
        id=row["id"],
        kind=row["kind"],
        target=row["target"],
        params=json.loads(row["params"]),
        status=JobStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=_dt(row["started_at"]),
        finished_at=_dt(row["finished_at"]),
        error=row["error"],
        cancel_requested=bool(row["cancel_requested"]),
    )


def _credential_from_row(row: sqlite3.Row) -> CredentialRecord:
    return CredentialRecord(
        id=row["id"],
        host=row["host"],
        kind=row["kind"],
        username=row["username"],
        ciphertext=row["ciphertext"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )
