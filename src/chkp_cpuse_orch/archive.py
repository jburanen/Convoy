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

DEFAULT_MAX_AGE_DAYS = 366  # ~1 year in the DB, then a job ages out to the archive
DEFAULT_ARCHIVE_RETENTION_DAYS = 3 * 366  # ~3 years kept in the archive file, then dropped


class JobArchiver:
    """Moves finished jobs older than ``max_age_days`` — their metadata,
    progress log, and any captured CPUSE install-log text — out of the DB
    and appends each as one JSON line to ``archive_path``, then deletes them
    from the DB (their events cascade). Whenever it appends, it also drops any
    archived entries older than ``archive_retention_days`` (by the same
    ``created_at`` the DB archival keys off), so the file holds a bounded,
    time-based window — the most recent ~3 years — rather than growing forever
    or being trimmed by raw size."""

    def __init__(
        self,
        store: Store,
        archive_path: Path,
        *,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        archive_retention_days: int = DEFAULT_ARCHIVE_RETENTION_DAYS,
    ) -> None:
        self._store = store
        self._path = Path(archive_path)
        self._max_age_days = max_age_days
        self._archive_retention_days = archive_retention_days

    def run(self, now: datetime | None = None) -> int:
        """Archive + delete eligible jobs, then prune archive entries past the
        retention window. Returns how many jobs were archived."""
        now = now or utcnow()
        cutoff = now - timedelta(days=self._max_age_days)
        candidates = self._store.list_archivable_jobs(cutoff)
        if not candidates:
            return 0
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            for job in candidates:
                f.write(json.dumps(_archive_record(job, self._store), sort_keys=True))
                f.write("\n")
                self._store.delete_job(job.id)
        _prune_older_than(self._path, now - timedelta(days=self._archive_retention_days))
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


def _prune_older_than(path: Path, cutoff: datetime) -> None:
    """Drop archived entries whose job was created before ``cutoff`` — the same
    ``created_at`` basis the DB archival uses. The archive is append-only and
    roughly time-ordered, but we parse each line's timestamp rather than assume
    order, so a hand-edited or out-of-order file still prunes correctly. Lines
    that don't parse are kept — we'd rather retain an odd line than lose audit
    data — and the file is only rewritten when something is actually dropped."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    kept: list[str] = []
    dropped = False
    for line in raw.splitlines():
        if not line:
            continue
        try:
            created = datetime.fromisoformat(json.loads(line)["created_at"])
        except (ValueError, KeyError, TypeError):
            kept.append(line)  # unparseable/legacy line — never silently discard
            continue
        if created >= cutoff:
            kept.append(line)
        else:
            dropped = True
    if dropped:
        path.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")
