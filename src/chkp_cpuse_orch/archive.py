"""Flat-file archive for old job records.

The Jobs tab (and its DB table) are meant for recent operational history, not
an indefinite audit log — so jobs past a retention window are moved out of the
DB into a bounded flat file on disk instead of being kept (or silently
dropped) forever. Not surfaced in the web UI beyond a note of where to find
it; see .claude/memory/patching-web-design.md.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .store import JobRecord, Store, utcnow

DEFAULT_MAX_AGE_DAYS = 366
DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50MB


class JobArchiver:
    """Moves finished jobs older than ``max_age_days`` — their metadata,
    progress log, and any captured CPUSE install-log text — out of the DB
    and appends each as one JSON line to ``archive_path``, then deletes them
    from the DB (their events cascade). The archive file is kept under
    ``max_bytes`` by dropping the oldest lines as new ones are added, so it
    never grows unbounded even across years of operation."""

    def __init__(
        self,
        store: Store,
        archive_path: Path,
        *,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._store = store
        self._path = Path(archive_path)
        self._max_age_days = max_age_days
        self._max_bytes = max_bytes

    def run(self, now: datetime | None = None) -> int:
        """Archive + delete eligible jobs. Returns how many were archived."""
        cutoff = (now or utcnow()) - timedelta(days=self._max_age_days)
        candidates = self._store.list_archivable_jobs(cutoff)
        if not candidates:
            return 0
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            for job in candidates:
                f.write(json.dumps(_archive_record(job, self._store), sort_keys=True))
                f.write("\n")
                self._store.delete_job(job.id)
        _enforce_max_bytes(self._path, self._max_bytes)
        return len(candidates)


def _archive_record(job: JobRecord, store: Store) -> dict[str, object]:
    return {
        "id": job.id,
        "kind": job.kind,
        "target": job.target,
        "environment": job.environment,
        "params": job.params,
        "status": job.status.value,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "error": job.error,
        "install_log": job.install_log,
        "events": [
            {"ts": e.ts.isoformat(), "level": e.level, "message": e.message}
            for e in store.events(job.id)
        ],
    }


def _enforce_max_bytes(path: Path, max_bytes: int) -> None:
    """Drop whole lines from the *front* of the file until it's back under
    ``max_bytes`` — the archive is append-only and time-ordered, so the
    oldest entries are always at the start."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    if size <= max_bytes:
        return
    data = path.read_bytes()
    lines = data.split(b"\n")
    total = len(data)
    start = 0
    # Keep at least the final (possibly empty) element from the trailing
    # newline's split so a well-formed file still ends in a newline.
    while total > max_bytes and start < len(lines) - 1:
        total -= len(lines[start]) + 1  # the line plus its newline
        start += 1
    path.write_bytes(b"\n".join(lines[start:]))
