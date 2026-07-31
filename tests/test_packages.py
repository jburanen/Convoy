from __future__ import annotations

import hashlib
import io
import tarfile
from datetime import timedelta
from pathlib import Path
from typing import Literal

import pytest

from chkp_cpuse_orch.errors import PackageError
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.store import Store, utcnow

CONTENT = b"pretend this is a multi-gigabyte JHF bundle"


@pytest.fixture
def pkg_store(tmp_path: Path) -> PackageStore:
    return PackageStore(Store(tmp_path / "orch.db"), tmp_path / "packages")


def test_add_stream_hashes_and_persists(pkg_store: PackageStore) -> None:
    rec = pkg_store.add_stream("jhf_t99.tgz", io.BytesIO(CONTENT))
    assert rec.sha1 == hashlib.sha1(CONTENT).hexdigest()
    assert rec.sha256 == hashlib.sha256(CONTENT).hexdigest()
    assert rec.size == len(CONTENT)
    assert pkg_store.path_for("jhf_t99.tgz").read_bytes() == CONTENT
    assert [p.filename for p in pkg_store.list()] == ["jhf_t99.tgz"]


def test_reupload_identical_is_idempotent(pkg_store: PackageStore) -> None:
    first = pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    second = pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert second.id == first.id
    assert len(pkg_store.list()) == 1


def test_same_name_different_content_refused(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    with pytest.raises(PackageError, match="different content"):
        pkg_store.add_stream("jhf.tgz", io.BytesIO(b"other bytes"))
    # Original content untouched.
    assert pkg_store.path_for("jhf.tgz").read_bytes() == CONTENT


def test_empty_upload_refused_and_leaves_no_debris(pkg_store: PackageStore) -> None:
    with pytest.raises(PackageError, match="empty package"):
        pkg_store.add_stream("empty.tgz", io.BytesIO(b""))
    assert pkg_store.list() == []
    assert list(pkg_store.directory.iterdir()) == []  # no .incoming-* leftovers


def test_unsafe_filenames_rejected(pkg_store: PackageStore) -> None:
    for bad in ("../evil.tgz", "a/b.tgz", "a b.tgz", ".hidden", ""):
        with pytest.raises(PackageError, match="unsafe package filename"):
            pkg_store.add_stream(bad, io.BytesIO(CONTENT))


def test_add_file_convenience(pkg_store: PackageStore, tmp_path: Path) -> None:
    src = tmp_path / "local_jhf.tgz"
    src.write_bytes(CONTENT)
    rec = pkg_store.add_file(src)
    assert rec.filename == "local_jhf.tgz"
    with pytest.raises(PackageError, match="not found"):
        pkg_store.add_file(tmp_path / "nope.tgz")


def test_delete_removes_row_and_content(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    path = pkg_store.path_for("jhf.tgz")
    assert pkg_store.delete("jhf.tgz") is True
    assert not path.exists()
    assert pkg_store.delete("jhf.tgz") is False


def test_get_missing_raises(pkg_store: PackageStore) -> None:
    with pytest.raises(PackageError, match="no such package"):
        pkg_store.get("ghost.tgz")


def test_path_for_detects_missing_content(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    (pkg_store.directory / "jhf.tgz").unlink()  # simulate volume/DB drift
    with pytest.raises(PackageError, match="out of sync"):
        pkg_store.path_for("jhf.tgz")


def test_verify_detects_corruption(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert pkg_store.verify("jhf.tgz").filename == "jhf.tgz"
    (pkg_store.directory / "jhf.tgz").write_bytes(b"bitrot")
    with pytest.raises(PackageError, match="no longer matches"):
        pkg_store.verify("jhf.tgz")


# -- retention --------------------------------------------------------------------


def test_upload_sets_retention_deadline(pkg_store: PackageStore) -> None:
    rec = pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert rec.expires_at is not None
    assert rec.pinned is False
    # ~30 days out (the fixture uses the default retention window).
    assert timedelta(days=29) < rec.expires_at - rec.created_at <= timedelta(days=30)


def test_retention_disabled_keeps_indefinitely(tmp_path: Path) -> None:
    store = Store(tmp_path / "orch.db")
    pkg_store = PackageStore(store, tmp_path / "packages", retention_days=0)
    rec = pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert rec.expires_at is None
    assert rec.pinned is True


def test_pin_and_unpin_toggle_deadline(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    pinned = pkg_store.set_pinned("jhf.tgz", True)
    assert pinned.expires_at is None
    unpinned = pkg_store.set_pinned("jhf.tgz", False)
    assert unpinned.expires_at is not None  # window reapplied from now


def test_set_pinned_missing_raises(pkg_store: PackageStore) -> None:
    with pytest.raises(PackageError, match="no such package"):
        pkg_store.set_pinned("ghost.tgz", True)


def test_purge_expired_deletes_only_past_deadline(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("old.tgz", io.BytesIO(CONTENT))
    pkg_store.add_stream("kept.tgz", io.BytesIO(b"different content"))
    pkg_store.set_pinned("kept.tgz", True)  # pinned — must survive any sweep

    # Sweep as if well past the ~30-day deadline of old.tgz.
    purged = pkg_store.purge_expired(now=utcnow() + timedelta(days=40))

    assert purged == ["old.tgz"]
    assert [p.filename for p in pkg_store.list()] == ["kept.tgz"]
    assert not (pkg_store.directory / "old.tgz").exists()


def test_purge_expired_noop_before_deadline(pkg_store: PackageStore) -> None:
    pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert pkg_store.purge_expired() == []  # deadline is ~30 days out
    assert [p.filename for p in pkg_store.list()] == ["jhf.tgz"]


# -- compatibility metadata extraction (hfconfig.py), wired into add_stream ------


def _make_tar(members: dict[str, bytes], *, mode: Literal["w"] = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


_HF_CONFIG = (
    "2474\n"
    "PATCH_NAME=BUNDLE_R82_10_JUMBO_HF_MAIN\n"
    "TAKE_NUMBER=24\n"
    "PACKAGE_TYPE=BUNDLE\n"
    "ARCH=x86_64\n"
    "CATEGORY=JUMBO\n"
    "DIRECT_BASE_VERSION=R82.10\n"
)
_CONDITIONS_SET = '{"set_description": "This hotfix is supported only for R82.10.\\n"}'


def test_add_stream_extracts_compatibility_metadata_from_a_real_looking_package(
    pkg_store: PackageStore,
) -> None:
    package = _make_tar(
        {"hf.config": _HF_CONFIG.encode(), "conditions_set.json": _CONDITIONS_SET.encode()}
    )
    rec = pkg_store.add_stream("jhf_t24.tgz", io.BytesIO(package))

    assert rec.direct_base_version == "R82.10"
    assert rec.take_number == 24
    assert rec.category == "JUMBO"
    assert rec.arch == "x86_64"
    assert rec.compatibility_note == "This hotfix is supported only for R82.10."
    # Round-trips through the store, not just the in-memory return value.
    stored = pkg_store.get("jhf_t24.tgz")
    assert stored.direct_base_version == "R82.10"
    assert stored.compatibility_note == "This hotfix is supported only for R82.10."


def test_add_stream_leaves_metadata_none_for_a_non_archive_upload(
    pkg_store: PackageStore,
) -> None:
    # CONTENT (used throughout this file) isn't a real tar — extraction must
    # degrade silently rather than fail the upload.
    rec = pkg_store.add_stream("jhf.tgz", io.BytesIO(CONTENT))
    assert rec.direct_base_version is None
    assert rec.take_number is None
    assert rec.category is None
    assert rec.arch is None
    assert rec.compatibility_note is None
