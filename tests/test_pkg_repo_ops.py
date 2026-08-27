from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest

from convoy.credentials import CredentialStore, JobCredentialVault
from convoy.errors import InventoryError, PackageError
from convoy.inventory import Host, Inventory, Role, Site
from convoy.jobs import JobRunner
from convoy.packages import PackageStore
from convoy.services.common import EnvironmentRegistry, HostConnector
from convoy.services.pkg_repo_ops import PackageRepoService
from convoy.store import JobStatus, Store

from .fakes import FakeTransport, make_factory

PKG = "jhf_t89.tgz"
PKG_CONTENT = b"fake repo-push package bytes"


class _FakeRepoClient:
    """Satisfies services.pkg_repo_ops._RepoClient. Replies come straight from
    the constructor — one show-task status for the whole test."""

    def __init__(
        self,
        *,
        task_status: str = "succeeded",
        task_details: list[object] | None = None,
        **kwargs: object,
    ) -> None:
        self.kwargs = kwargs
        self.task_status = task_status
        self.task_details = task_details
        self.add_calls: list[tuple[str, str, str]] = []
        self.show_task_calls = 0

    def __enter__(self) -> _FakeRepoClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def add_repository_package(self, name: str, path: str, *, source: str = "local") -> str:
        self.add_calls.append((name, path, source))
        return "TASK-1"

    def show_task(self, task_id: str) -> dict[str, object]:
        self.show_task_calls += 1
        task: dict[str, object] = {"status": self.task_status, "task-id": task_id}
        if self.task_details is not None:
            task["task-details"] = self.task_details
        return task


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


def _service(
    store: Store, tmp_path: Path, transport: FakeTransport, repo_client: _FakeRepoClient
) -> PackageRepoService:
    store.insert_environment("default", credential_storage_enabled=True)
    creds = CredentialStore(store, master_key="unit test master key")
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="pw",
        expert_password="expert-pw",
    )
    set_id = store.get_credential_set_by_name("default", "primary").id  # type: ignore[union-attr]
    packages = PackageStore(store, tmp_path / "packages")
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    inventory = Inventory(
        sites=[
            Site(
                name="t",
                hosts=[
                    Host(
                        name="mgmt-01",
                        address="192.0.2.10",
                        role=Role.PRIMARY_SMS,
                        credential_set_id=set_id,
                    )
                ],
            )
        ]
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))

    def repo_client_factory(host: object, **kw: object) -> _FakeRepoClient:
        repo_client.kwargs = kw
        return repo_client

    return PackageRepoService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        mgmt_client_factory=repo_client_factory,
        poll_interval=0.01,
    )


def _run(service: PackageRepoService) -> None:
    asyncio.run(service.runner.run_until_idle())


def test_push_uploads_and_registers_package(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    repo_client = _FakeRepoClient(task_status="succeeded")
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status == JobStatus.SUCCEEDED
    assert transport.puts == [(str(tmp_path / "packages" / PKG), "/var/log/upload/" + PKG)]
    assert repo_client.add_calls == [(PKG, "/var/log/upload/", "local")]
    assert repo_client.show_task_calls == 1
    assert transport.closed is True


def test_push_skips_upload_when_already_staged_with_matching_size(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    transport.responses["stat -c %s"] = str(len(PKG_CONTENT))
    repo_client = _FakeRepoClient(task_status="succeeded")
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    assert transport.puts == []  # skipped — already staged with matching size


def test_push_fails_when_task_fails(store: Store, tmp_path: Path, transport: FakeTransport) -> None:
    repo_client = _FakeRepoClient(
        task_status="failed", task_details=[{"statusDescription": "disk full on repository"}]
    )
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status == JobStatus.FAILED
    assert "disk full on repository" in (finished.error or "")


def test_push_cleans_up_staged_package_after_failure(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    """A task failure (post-upload) leaves the file staged on the mgmt server —
    the job should attempt to remove it and log whether that worked."""
    repo_client = _FakeRepoClient(
        task_status="failed", task_details=[{"statusDescription": "disk full on repository"}]
    )
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    assert store.get_job(job.id).status == JobStatus.FAILED
    assert any(f"rm -f /var/log/upload/{PKG}" in cmd for cmd in transport.commands)
    messages = [e.message for e in store.events(job.id)]
    assert any(f"cleanup: removed staged package /var/log/upload/{PKG}" in m for m in messages)


def test_push_logs_cleanup_failure_when_removal_fails(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    transport.responses["rm -f"] = (1, "")
    repo_client = _FakeRepoClient(
        task_status="failed", task_details=[{"statusDescription": "disk full on repository"}]
    )
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    assert store.get_job(job.id).status == JobStatus.FAILED
    messages = [e.message for e in store.events(job.id)]
    assert any(
        f"cleanup: failed to remove staged package /var/log/upload/{PKG}" in m for m in messages
    )


def test_push_uses_ssh_username_password_as_api_auth_fallback(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    """No API key was assigned to the credential set — add_repository_package
    must still work by falling back to the SSH username/password (see
    services/common.py's api_auth)."""
    repo_client = _FakeRepoClient(task_status="succeeded")
    service = _service(store, tmp_path, transport, repo_client)

    job = service.submit_push_to_repo("default", PKG)
    _run(service)

    assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    assert repo_client.kwargs["username"] == "admin"
    assert repo_client.kwargs["password"] == "pw"
    assert repo_client.kwargs["read_only"] is False


def test_submit_push_to_repo_rejects_unknown_package(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    repo_client = _FakeRepoClient()
    service = _service(store, tmp_path, transport, repo_client)

    with pytest.raises(PackageError):
        service.submit_push_to_repo("default", "no-such-package.tgz")


def test_submit_push_to_repo_requires_a_primary(
    store: Store, tmp_path: Path, transport: FakeTransport
) -> None:
    store.insert_environment("default", credential_storage_enabled=True)
    creds = CredentialStore(store, master_key="unit test master key")
    packages = PackageStore(store, tmp_path / "packages")
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(Inventory(sites=[]), creds, make_factory(transport)))
    service = PackageRepoService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        mgmt_client_factory=lambda host, **kw: _FakeRepoClient(),
    )

    with pytest.raises(InventoryError):
        service.submit_push_to_repo("default", PKG)
