"""Package store: upload once, distribute to many hosts.

JHF/upgrade packages are GB-scale, so uploads stream to disk while hashing —
never buffered in memory. Files live in a git-ignored directory on the data
volume; metadata (SHA-1/SHA-256/size) lives in the Store so the operator can
compare checksums against Check Point's published values before distributing.
See .claude/memory/patching-web-design.md.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from .errors import PackageError
from .store import PackageRecord, Store

# Package filenames feed remote shell commands and filesystem paths — keep them
# boring. Check Point package names all fit this comfortably.
_SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

_CHUNK = 1024 * 1024  # 1 MiB


class PackageStore:
    """Content on disk + metadata in the Store, kept consistent."""

    def __init__(self, store: Store, directory: str | Path) -> None:
        self._store = store
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    # -- write ------------------------------------------------------------------

    def add_stream(self, filename: str, stream: BinaryIO) -> PackageRecord:
        """Stream an upload to disk, hashing as it goes. Idempotent: re-uploading
        identical content under the same name returns the existing record; the
        same name with *different* content is refused (delete first — packages
        are immutable once distributed)."""
        name = _check_filename(filename)
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0

        tmp_path = self.directory / f".incoming-{uuid.uuid4().hex}"
        try:
            with tmp_path.open("wb") as out:
                while chunk := stream.read(_CHUNK):
                    sha1.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)
                    out.write(chunk)

            if size == 0:
                raise PackageError(f"refusing to store empty package {name!r}")

            digest256 = sha256.hexdigest()
            existing = self._store.get_package(name)
            if existing is not None:
                if existing.sha256 == digest256:
                    return existing  # identical re-upload → no-op
                raise PackageError(
                    f"package {name!r} already exists with different content "
                    f"(stored sha256 {existing.sha256[:12]}…, uploaded {digest256[:12]}…). "
                    "Delete it first if you really mean to replace it."
                )

            rec = PackageRecord(filename=name, sha1=sha1.hexdigest(), sha256=digest256, size=size)
            tmp_path.replace(self.directory / name)
            self._store.insert_package(rec)
            return rec
        finally:
            tmp_path.unlink(missing_ok=True)

    def add_file(self, path: str | Path) -> PackageRecord:
        """Convenience for CLI use: ingest an existing local file."""
        p = Path(path)
        if not p.is_file():
            raise PackageError(f"package file not found: {p}")
        with p.open("rb") as fh:
            return self.add_stream(p.name, fh)

    def delete(self, filename: str) -> bool:
        """Remove metadata and content. Returns False if it wasn't there."""
        name = _check_filename(filename)
        existed = self._store.delete_package(name)
        (self.directory / name).unlink(missing_ok=True)
        return existed

    # -- read -------------------------------------------------------------------

    def list(self) -> list[PackageRecord]:
        return self._store.list_packages()

    def get(self, filename: str) -> PackageRecord:
        rec = self._store.get_package(_check_filename(filename))
        if rec is None:
            raise PackageError(f"no such package: {filename!r}")
        return rec

    def path_for(self, filename: str) -> Path:
        """Absolute path of a stored package (for SFTP upload to a host).
        Verifies the content file actually exists — fail closed on drift."""
        rec = self.get(filename)
        path = self.directory / rec.filename
        if not path.is_file():
            raise PackageError(
                f"metadata exists but content file is missing: {path} — "
                "the data volume and DB are out of sync"
            )
        return path

    def verify(self, filename: str) -> PackageRecord:
        """Re-hash the stored file and compare with recorded metadata."""
        rec = self.get(filename)
        path = self.path_for(filename)
        sha256 = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in _chunks(fh):
                sha256.update(chunk)
        if sha256.hexdigest() != rec.sha256:
            raise PackageError(
                f"stored file {path} no longer matches its recorded sha256 — "
                "content was modified or corrupted on the data volume"
            )
        return rec


def _chunks(fh: BinaryIO) -> Iterator[bytes]:
    while chunk := fh.read(_CHUNK):
        yield chunk


def _check_filename(filename: str) -> str:
    if not _SAFE_FILENAME_RE.fullmatch(filename):
        raise PackageError(
            f"unsafe package filename: {filename!r} — letters, digits, dot, "
            "dash and underscore only (no paths)"
        )
    return filename
