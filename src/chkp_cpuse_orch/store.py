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
    environment: str = "default"  # which management environment it ran against
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


class PackageRecord(BaseModel):
    """Metadata for one uploaded package file (content lives on the data volume)."""

    id: str = Field(default_factory=new_id)
    filename: str
    sha1: str  # Check Point publishes SHA-1 (and SHA-256) per package — the UI
    sha256: str  # shows both so the operator can compare before distributing
    size: int
    created_at: datetime = Field(default_factory=utcnow)
    # When this package is auto-deleted. ``None`` means "keep indefinitely"
    # (pinned by the operator, or expiry disabled). Set at upload time from the
    # configured retention window.
    expires_at: datetime | None = None

    @property
    def pinned(self) -> bool:
        """Kept indefinitely — no retention deadline set."""
        return self.expires_at is None


class EnvironmentRow(BaseModel):
    """A management environment (name only; its servers live in env_hosts)."""

    name: str
    created_at: datetime = Field(default_factory=utcnow)
    # When False, credentials are NOT persisted for this environment: each job
    # (and live-state query) supplies them at request time and they live only in
    # memory until the operation finishes. New environments default to False.
    credential_storage_enabled: bool = False


class EnvHostRow(BaseModel):
    """One management server belonging to an environment. Gateways are not
    stored here — CDT discovers them at deploy time."""

    id: str = Field(default_factory=new_id)
    environment: str
    name: str
    address: str
    role: str  # inventory Role value (management / mds)
    ssh_port: int = 22
    ssh_user: str = "admin"
    notes: str | None = None
    # Assigned credential set (credential_sets.id), or None when unassigned.
    credential_set_id: str | None = None


class CredentialSetRow(BaseModel):
    """A named "login set" — ciphertext only; the store never sees plaintext.
    Each secret column is Fernet ciphertext (or None when that secret is unset).
    One of ssh_password_ct / ssh_private_key_ct is expected in practice."""

    id: str = Field(default_factory=new_id)
    environment: str = "default"  # credential namespaces are per-environment
    name: str  # operator-chosen label, unique within the environment
    ssh_username: str | None = None
    ssh_password_ct: bytes | None = None
    ssh_private_key_ct: bytes | None = None
    expert_password_ct: bytes | None = None
    api_key_ct: bytes | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class SessionRow(BaseModel):
    """One authenticated web session. ``token_hash`` is the SHA-256 of the opaque
    cookie token — the raw token is never persisted."""

    token_hash: str
    username: str
    display_name: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    last_seen_at: datetime = Field(default_factory=utcnow)


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
    # v2: package metadata (Phase 2 — package store).
    """
    CREATE TABLE packages (
        id         TEXT PRIMARY KEY,
        filename   TEXT NOT NULL UNIQUE,
        sha1       TEXT NOT NULL,
        sha256     TEXT NOT NULL,
        size       INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    # v3: independent management environments. Credentials get an environment
    # namespace (unique key rebuilt — SQLite can't alter constraints in place);
    # jobs record which environment they ran against. Existing rows land in
    # 'default'. Packages stay shared by design.
    """
    ALTER TABLE jobs ADD COLUMN environment TEXT NOT NULL DEFAULT 'default';

    CREATE TABLE credentials_v3 (
        id          TEXT PRIMARY KEY,
        environment TEXT NOT NULL DEFAULT 'default',
        host        TEXT NOT NULL,
        kind        TEXT NOT NULL,
        username    TEXT,
        ciphertext  BLOB NOT NULL,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        UNIQUE (environment, host, kind)
    );
    INSERT INTO credentials_v3
        (id, environment, host, kind, username, ciphertext, created_at, updated_at)
        SELECT id, 'default', host, kind, username, ciphertext, created_at, updated_at
        FROM credentials;
    DROP TABLE credentials;
    ALTER TABLE credentials_v3 RENAME TO credentials;
    """,
    # v4: environments and their management servers become DB-backed so the web
    # UI can add/edit them. Seeded once from config/inventory files on first run
    # (see services/environments.py); the DB is authoritative thereafter.
    """
    CREATE TABLE environments (
        name       TEXT PRIMARY KEY,
        created_at TEXT NOT NULL
    );

    CREATE TABLE env_hosts (
        id          TEXT PRIMARY KEY,
        environment TEXT NOT NULL REFERENCES environments (name) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        address     TEXT NOT NULL,
        role        TEXT NOT NULL,
        ssh_port    INTEGER NOT NULL DEFAULT 22,
        ssh_user    TEXT NOT NULL DEFAULT 'admin',
        notes       TEXT,
        UNIQUE (environment, name)
    );
    CREATE INDEX idx_env_hosts_env ON env_hosts (environment);
    """,
    # v5: per-package retention. NULL expires_at == keep indefinitely; existing
    # rows default to NULL so nothing already uploaded is retroactively expired.
    # New uploads get a deadline from the configured retention window.
    """
    ALTER TABLE packages ADD COLUMN expires_at TEXT;
    """,
    # v6: optional per-environment credential storage. Existing environments
    # default to 1 (enabled) to preserve behaviour; environments created after
    # this migration default to 0 (disabled) via insert_environment().
    """
    ALTER TABLE environments ADD COLUMN credential_storage_enabled INTEGER NOT NULL DEFAULT 1;
    """,
    # v7: web login sessions. Only the SHA-256 of the opaque session token is
    # stored, never the token itself — a DB leak must not grant a live session.
    # last_seen_at drives the sliding idle-timeout enforced by the auth layer.
    """
    CREATE TABLE sessions (
        token_hash   TEXT PRIMARY KEY,
        username     TEXT NOT NULL,
        display_name TEXT,
        created_at   TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
    );
    CREATE INDEX idx_sessions_last_seen ON sessions (last_seen_at);
    """,
    # v8: credentials become named "login set" objects assigned to servers, instead
    # of being keyed by host. This WIPES the old per-host credentials table (operator
    # chose re-entry over migration); sets are recreated in the new UI. env_hosts
    # gains a credential_set_id FK (ON DELETE SET NULL → deleting a set auto-unassigns
    # its servers; foreign_keys pragma is on per connection).
    """
    DROP TABLE credentials;

    CREATE TABLE credential_sets (
        id                 TEXT PRIMARY KEY,
        environment        TEXT NOT NULL REFERENCES environments (name) ON DELETE CASCADE,
        name               TEXT NOT NULL,
        ssh_username       TEXT,
        ssh_password_ct    BLOB,
        ssh_private_key_ct BLOB,
        expert_password_ct BLOB,
        api_key_ct         BLOB,
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL,
        UNIQUE (environment, name)
    );
    CREATE INDEX idx_credential_sets_env ON credential_sets (environment);

    ALTER TABLE env_hosts ADD COLUMN credential_set_id TEXT
        REFERENCES credential_sets (id) ON DELETE SET NULL;
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

    # -- credential sets (named login objects; ciphertext only) ----------------

    _CRED_SET_COLS = (
        "id, environment, name, ssh_username, ssh_password_ct, ssh_private_key_ct,"
        " expert_password_ct, api_key_ct, created_at, updated_at"
    )

    def upsert_credential_set(self, rec: CredentialSetRow) -> CredentialSetRow:
        """Create or replace a named credential set (keyed by environment+name).
        All secret columns are overwritten, so the caller passes the full set."""
        now = utcnow()
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO credential_sets ({self._CRED_SET_COLS})"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (environment, name) DO UPDATE SET"
                " ssh_username = excluded.ssh_username,"
                " ssh_password_ct = excluded.ssh_password_ct,"
                " ssh_private_key_ct = excluded.ssh_private_key_ct,"
                " expert_password_ct = excluded.expert_password_ct,"
                " api_key_ct = excluded.api_key_ct,"
                " updated_at = excluded.updated_at",
                (
                    rec.id,
                    rec.environment,
                    rec.name,
                    rec.ssh_username,
                    rec.ssh_password_ct,
                    rec.ssh_private_key_ct,
                    rec.expert_password_ct,
                    rec.api_key_ct,
                    rec.created_at.isoformat(),
                    now.isoformat(),
                ),
            )
        stored = self.get_credential_set_by_name(rec.environment, rec.name)
        assert stored is not None  # just written
        return stored

    def get_credential_set(self, set_id: str) -> CredentialSetRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM credential_sets WHERE id = ?", (set_id,)).fetchone()
        return None if row is None else _credential_set_from_row(row)

    def get_credential_set_by_name(self, environment: str, name: str) -> CredentialSetRow | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM credential_sets WHERE environment = ? AND name = ?",
                (environment, name),
            ).fetchone()
        return None if row is None else _credential_set_from_row(row)

    def list_credential_sets(self, environment: str) -> list[CredentialSetRow]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM credential_sets WHERE environment = ? ORDER BY name",
                (environment,),
            ).fetchall()
        return [_credential_set_from_row(r) for r in rows]

    def delete_credential_set(self, environment: str, name: str) -> bool:
        """Delete a set. Any env_hosts pointing at it are auto-unassigned by the
        ON DELETE SET NULL foreign key (foreign_keys pragma is on per connection)."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM credential_sets WHERE environment = ? AND name = ?",
                (environment, name),
            )
        return cur.rowcount > 0

    def delete_environment_credential_sets(self, environment: str) -> int:
        """Purge every credential set in an environment (servers auto-unassign via
        the FK). Works on ciphertext rows, so it runs even with the store locked."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM credential_sets WHERE environment = ?", (environment,))
        return cur.rowcount

    def assign_credential_set(self, environment: str, host_name: str, set_id: str | None) -> bool:
        """Point a management server at a credential set (or ``None`` to clear).
        Returns False if the server doesn't exist in the environment."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE env_hosts SET credential_set_id = ? WHERE environment = ? AND name = ?",
                (set_id, environment, host_name),
            )
        return cur.rowcount > 0

    # -- environments + their management servers (DB-backed inventory) ----------

    def list_environments(self) -> list[EnvironmentRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM environments ORDER BY name").fetchall()
        return [_environment_from_row(r) for r in rows]

    def get_environment(self, name: str) -> EnvironmentRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM environments WHERE name = ?", (name,)).fetchone()
        return None if row is None else _environment_from_row(row)

    def environment_exists(self, name: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM environments WHERE name = ?", (name,)).fetchone()
        return row is not None

    def insert_environment(self, name: str, *, credential_storage_enabled: bool = False) -> None:
        """Raises sqlite3.IntegrityError if the name already exists. New
        environments default to credential storage *disabled*."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO environments (name, created_at, credential_storage_enabled)"
                " VALUES (?, ?, ?)",
                (name, utcnow().isoformat(), int(credential_storage_enabled)),
            )

    def set_environment_credential_storage(self, name: str, enabled: bool) -> bool:
        """Toggle credential storage for an environment. Returns False if unknown."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE environments SET credential_storage_enabled = ? WHERE name = ?",
                (int(enabled), name),
            )
        return cur.rowcount > 0

    def delete_environment(self, name: str) -> bool:
        """Deletes the environment and (via cascade) its env_hosts."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM environments WHERE name = ?", (name,))
        return cur.rowcount > 0

    def rename_environment(self, old: str, new: str) -> bool:
        """Rename an environment, moving its servers, credential sets, and job
        history along in ONE transaction (the FK is ON DELETE CASCADE only, so
        this is insert-new / move-children / delete-old rather than a PK
        update). Server→set assignments survive because set ids are unchanged.
        Returns False if ``old`` doesn't exist; raises sqlite3.IntegrityError if
        ``new`` is already taken."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT created_at, credential_storage_enabled FROM environments WHERE name = ?",
                (old,),
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                "INSERT INTO environments (name, created_at, credential_storage_enabled)"
                " VALUES (?, ?, ?)",
                (new, row["created_at"], row["credential_storage_enabled"]),
            )
            conn.execute("UPDATE env_hosts SET environment = ? WHERE environment = ?", (new, old))
            conn.execute(
                "UPDATE credential_sets SET environment = ? WHERE environment = ?", (new, old)
            )
            conn.execute("UPDATE jobs SET environment = ? WHERE environment = ?", (new, old))
            conn.execute("DELETE FROM environments WHERE name = ?", (old,))
        return True

    def list_env_hosts(self, environment: str) -> list[EnvHostRow]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM env_hosts WHERE environment = ? ORDER BY name", (environment,)
            ).fetchall()
        return [_env_host_from_row(r) for r in rows]

    def upsert_env_host(self, rec: EnvHostRow) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO env_hosts (id, environment, name, address, role, ssh_port,"
                " ssh_user, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (environment, name) DO UPDATE SET"
                " address = excluded.address, role = excluded.role,"
                " ssh_port = excluded.ssh_port, ssh_user = excluded.ssh_user,"
                " notes = excluded.notes",
                (
                    rec.id,
                    rec.environment,
                    rec.name,
                    rec.address,
                    rec.role,
                    rec.ssh_port,
                    rec.ssh_user,
                    rec.notes,
                ),
            )

    def delete_env_host(self, environment: str, name: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM env_hosts WHERE environment = ? AND name = ?", (environment, name)
            )
        return cur.rowcount > 0

    # -- packages (metadata; file content lives in packages.py's directory) ------

    def insert_package(self, rec: PackageRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO packages (id, filename, sha1, sha256, size, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.id,
                    rec.filename,
                    rec.sha1,
                    rec.sha256,
                    rec.size,
                    rec.created_at.isoformat(),
                    _iso(rec.expires_at),
                ),
            )

    def set_package_expiry(self, filename: str, expires_at: datetime | None) -> bool:
        """Set (or clear, with ``None``) a package's retention deadline.
        Returns False if no such package."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE packages SET expires_at = ? WHERE filename = ?",
                (_iso(expires_at), filename),
            )
        return cur.rowcount > 0

    def list_expired_packages(self, now: datetime) -> list[PackageRecord]:
        """Packages whose retention deadline has passed (pinned ones excluded).
        ISO-8601 UTC timestamps compare correctly as strings."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM packages WHERE expires_at IS NOT NULL AND expires_at <= ?"
                " ORDER BY expires_at",
                (now.isoformat(),),
            ).fetchall()
        return [_package_from_row(r) for r in rows]

    def get_package(self, filename: str) -> PackageRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM packages WHERE filename = ?", (filename,)).fetchone()
        return None if row is None else _package_from_row(row)

    def list_packages(self) -> list[PackageRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM packages ORDER BY filename").fetchall()
        return [_package_from_row(r) for r in rows]

    def delete_package(self, filename: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM packages WHERE filename = ?", (filename,))
        return cur.rowcount > 0

    # -- jobs ------------------------------------------------------------------

    def insert_job(self, job: JobRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO jobs (id, kind, target, environment, params, status, created_at,"
                " started_at, finished_at, error, cancel_requested)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job.id,
                    job.kind,
                    job.target,
                    job.environment,
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

    # -- web sessions ------------------------------------------------------------

    def create_session(self, rec: SessionRow) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, username, display_name, created_at,"
                " last_seen_at) VALUES (?, ?, ?, ?, ?)",
                (
                    rec.token_hash,
                    rec.username,
                    rec.display_name,
                    rec.created_at.isoformat(),
                    rec.last_seen_at.isoformat(),
                ),
            )

    def get_session(self, token_hash: str) -> SessionRow | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return None if row is None else _session_from_row(row)

    def touch_session(self, token_hash: str, now: datetime | None = None) -> None:
        """Refresh a session's ``last_seen_at`` (sliding idle window)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                ((now or utcnow()).isoformat(), token_hash),
            )

    def delete_session(self, token_hash: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return cur.rowcount > 0

    def purge_idle_sessions(self, cutoff: datetime) -> int:
        """Delete sessions not seen since ``cutoff``. Returns the count removed."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE last_seen_at < ?", (cutoff.isoformat(),))
        return cur.rowcount


def _iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.isoformat()


def _dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _job_from_row(row: sqlite3.Row) -> JobRecord:
    return JobRecord(
        id=row["id"],
        kind=row["kind"],
        target=row["target"],
        environment=row["environment"],
        params=json.loads(row["params"]),
        status=JobStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=_dt(row["started_at"]),
        finished_at=_dt(row["finished_at"]),
        error=row["error"],
        cancel_requested=bool(row["cancel_requested"]),
    )


def _environment_from_row(row: sqlite3.Row) -> EnvironmentRow:
    return EnvironmentRow(
        name=row["name"],
        created_at=datetime.fromisoformat(row["created_at"]),
        credential_storage_enabled=bool(row["credential_storage_enabled"]),
    )


def _session_from_row(row: sqlite3.Row) -> SessionRow:
    return SessionRow(
        token_hash=row["token_hash"],
        username=row["username"],
        display_name=row["display_name"],
        created_at=datetime.fromisoformat(row["created_at"]),
        last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
    )


def _env_host_from_row(row: sqlite3.Row) -> EnvHostRow:
    return EnvHostRow(
        id=row["id"],
        environment=row["environment"],
        name=row["name"],
        address=row["address"],
        role=row["role"],
        ssh_port=row["ssh_port"],
        ssh_user=row["ssh_user"],
        notes=row["notes"],
        credential_set_id=row["credential_set_id"],
    )


def _package_from_row(row: sqlite3.Row) -> PackageRecord:
    return PackageRecord(
        id=row["id"],
        filename=row["filename"],
        sha1=row["sha1"],
        sha256=row["sha256"],
        size=row["size"],
        created_at=datetime.fromisoformat(row["created_at"]),
        expires_at=_dt(row["expires_at"]),
    )


def _credential_set_from_row(row: sqlite3.Row) -> CredentialSetRow:
    return CredentialSetRow(
        id=row["id"],
        environment=row["environment"],
        name=row["name"],
        ssh_username=row["ssh_username"],
        ssh_password_ct=row["ssh_password_ct"],
        ssh_private_key_ct=row["ssh_private_key_ct"],
        expert_password_ct=row["expert_password_ct"],
        api_key_ct=row["api_key_ct"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )
