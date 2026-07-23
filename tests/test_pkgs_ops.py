from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest

from chkp_cpuse_orch.errors import PackageError
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.services.pkgs_ops import (
    JOB_DELETE,
    JOB_KEEP,
    JOB_NOTKEEP,
    JOB_UPLOAD,
    PackageJobService,
)
from chkp_cpuse_orch.store import JobStatus, Store

PKG = "jhf_t89.tgz"
PKG_CONTENT = b"fake jumbo hotfix bytes"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def packages(store: Store, tmp_path: Path) -> PackageStore:
    return PackageStore(store, tmp_path / "packages")


@pytest.fixture
def service(store: Store, packages: PackageStore) -> PackageJobService:
    return PackageJobService(packages=packages, runner=JobRunner(store))


def _run(service: PackageJobService) -> None:
    asyncio.run(service.runner.run_until_idle())


def _stage(packages: PackageStore, content: bytes, name: str = "staged") -> Path:
    """Mimic what the route does before submitting a pkgs.upload job: copy the
    (already fully-received) upload to a stable path inside the package dir."""
    path = packages.directory / f".upload-{name}"
    path.write_bytes(content)
    return path


# -- upload -------------------------------------------------------------------------


def test_upload_job_stores_the_package(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    staged = _stage(packages, PKG_CONTENT)
    job = service.submit_upload(PKG, staged)
    assert job.kind == JOB_UPLOAD
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    rec = packages.get(PKG)
    assert rec.size == len(PKG_CONTENT)


def test_upload_job_cleans_up_the_staged_file(
    service: PackageJobService, packages: PackageStore
) -> None:
    staged = _stage(packages, PKG_CONTENT)
    service.submit_upload(PKG, staged)
    _run(service)
    assert not staged.exists()


def test_upload_job_fails_on_conflicting_content(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    packages.add_stream(PKG, io.BytesIO(b"original content"))

    staged = _stage(packages, b"different content")
    job = service.submit_upload(PKG, staged)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status == JobStatus.FAILED
    assert "different content" in (finished.error or "")
    assert not staged.exists()  # cleaned up even on failure


def test_upload_job_logs_progress(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    staged = _stage(packages, PKG_CONTENT)
    job = service.submit_upload(PKG, staged)
    _run(service)
    messages = [e.message for e in store.events(job.id)]
    assert any("stored" in m and PKG in m for m in messages)


# -- retention (keep / notkeep) ------------------------------------------------------


def test_keep_job_pins_the_package(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    job = service.submit_retention(PKG, pinned=True)
    assert job.kind == JOB_KEEP
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    assert packages.get(PKG).pinned


def test_notkeep_job_unpins_the_package(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    packages.set_pinned(PKG, True)

    job = service.submit_retention(PKG, pinned=False)
    assert job.kind == JOB_NOTKEEP
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    assert not packages.get(PKG).pinned


def test_submit_retention_on_missing_package_raises_synchronously(
    service: PackageJobService, store: Store
) -> None:
    """No job should even be created for an obviously-doomed request — matches
    the old synchronous endpoint's immediate 404 instead of a deferred job
    failure."""
    with pytest.raises(PackageError):
        service.submit_retention("ghost.tgz", pinned=True)
    assert store.list_jobs() == []


# -- delete -------------------------------------------------------------------------


def test_delete_job_removes_the_package(
    service: PackageJobService, packages: PackageStore, store: Store
) -> None:
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    job = service.submit_delete(PKG)
    assert job.kind == JOB_DELETE
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    with pytest.raises(PackageError):
        packages.get(PKG)


def test_submit_delete_on_missing_package_raises_synchronously(
    service: PackageJobService, store: Store
) -> None:
    with pytest.raises(PackageError):
        service.submit_delete("ghost.tgz")
    assert store.list_jobs() == []


# -- job target bookkeeping ----------------------------------------------------------


def test_jobs_target_the_filename(service: PackageJobService, packages: PackageStore) -> None:
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    job = service.submit_delete(PKG)
    assert job.target == PKG
