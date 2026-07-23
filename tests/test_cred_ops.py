from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from chkp_cpuse_orch.credentials import CredentialStore, JobCredentialVault
from chkp_cpuse_orch.errors import InventoryError
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.services.cred_ops import JOB_ADD, JOB_DELETE, JOB_EDIT, CredentialJobService
from chkp_cpuse_orch.store import Store

ENV = "default"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment(ENV, credential_storage_enabled=True)
    return store


@pytest.fixture
def credentials(store: Store) -> CredentialStore:
    return CredentialStore(store, master_key="unit test master key")


@pytest.fixture
def vault() -> JobCredentialVault:
    return JobCredentialVault()


@pytest.fixture
def service(
    store: Store, credentials: CredentialStore, vault: JobCredentialVault
) -> CredentialJobService:
    return CredentialJobService(
        credentials=credentials, runner=JobRunner(store, on_job_finished=vault.discard), vault=vault
    )


def _run(service: CredentialJobService) -> None:
    asyncio.run(service.runner.run_until_idle())


# -- add / edit -----------------------------------------------------------------------


def test_new_name_submits_as_add(
    service: CredentialJobService, credentials: CredentialStore
) -> None:
    job = service.submit_put(
        ENV,
        name="primary",
        ssh_username="admin",
        ssh_password="pw",
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=False,
    )
    assert job.kind == JOB_ADD
    assert job.target == "primary"
    _run(service)

    info = credentials.get_info(ENV, "primary")
    assert info is not None
    assert info.ssh_username == "admin"
    assert info.ssh_auth == "password"


def test_existing_name_submits_as_edit(
    service: CredentialJobService, credentials: CredentialStore
) -> None:
    credentials.put_set(ENV, "primary", ssh_username="admin", ssh_password="pw")
    job = service.submit_put(
        ENV,
        name="primary",
        ssh_username=None,
        ssh_password=None,
        ssh_private_key=None,
        expert_password=None,
        api_key="APIKEY123",
        default_if_none=False,
    )
    assert job.kind == JOB_EDIT
    _run(service)

    info = credentials.get_info(ENV, "primary")
    assert info is not None
    assert info.has_api is True
    assert info.ssh_auth == "password"  # untouched secret preserved


def test_default_if_none_sets_default_once(
    service: CredentialJobService, credentials: CredentialStore
) -> None:
    service.submit_put(
        ENV,
        name="primary",
        ssh_username="admin",
        ssh_password="pw",
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=True,
    )
    _run(service)
    assert credentials.default_set_name(ENV) == "primary"

    service.submit_put(
        ENV,
        name="backup",
        ssh_username="admin",
        ssh_password="pw2",
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=True,
    )
    _run(service)
    assert credentials.default_set_name(ENV) == "primary"  # not stolen


def test_validation_error_surfaces_as_a_failed_job_not_a_raise(
    service: CredentialJobService, store: Store
) -> None:
    """Adding a set with neither an SSH password nor a private key is invalid
    (CredentialStore.put_set raises) — that happens inside the job handler,
    so submission itself succeeds and the failure shows up on the job."""
    job = service.submit_put(
        ENV,
        name="broken",
        ssh_username="admin",
        ssh_password=None,
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=False,
    )
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert "password or private key" in (finished.error or "")


# -- delete -------------------------------------------------------------------------


def test_delete_removes_the_set(
    service: CredentialJobService, credentials: CredentialStore
) -> None:
    credentials.put_set(ENV, "primary", ssh_username="admin", ssh_password="pw")
    job = service.submit_delete(ENV, "primary")
    assert job.kind == JOB_DELETE
    assert job.target == "primary"
    _run(service)
    assert credentials.get_info(ENV, "primary") is None


def test_submit_delete_on_missing_set_raises_synchronously(
    service: CredentialJobService, store: Store
) -> None:
    """No job should even be created for an obviously-doomed request — same
    convention as PackageJobService.submit_delete/submit_retention."""
    with pytest.raises(InventoryError, match="not found"):
        service.submit_delete(ENV, "ghost")
    assert store.list_jobs() == []


# -- secrets never touch persisted job state -----------------------------------------


def test_secrets_never_land_in_job_params(service: CredentialJobService, store: Store) -> None:
    job = service.submit_put(
        ENV,
        name="primary",
        ssh_username="admin",
        ssh_password="super-secret-password",
        ssh_private_key=None,
        expert_password="expert-secret",
        api_key="api-secret",
        default_if_none=False,
    )
    # Only non-secret fields travel in params (persisted as plain JSON —
    # see store.py); the four secret fields go through the vault instead.
    assert job.params == {"ssh_username": "admin", "default_if_none": False}
    # Round-tripped through the DB, not just the in-memory object.
    assert store.get_job(job.id).params == {"ssh_username": "admin", "default_if_none": False}


def test_vault_entry_put_before_submit_and_discarded_after_completion(
    service: CredentialJobService, vault: JobCredentialVault
) -> None:
    job = service.submit_put(
        ENV,
        name="primary",
        ssh_username="admin",
        ssh_password="pw",
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=False,
    )
    assert vault.get(job.id) is not None  # available to the handler once it runs
    _run(service)
    assert vault.get(job.id) is None  # dropped once the job reaches a terminal state


def test_vault_entry_discarded_even_if_the_job_fails(
    service: CredentialJobService, vault: JobCredentialVault
) -> None:
    job = service.submit_put(
        ENV,
        name="broken",
        ssh_username="admin",
        ssh_password=None,
        ssh_private_key=None,
        expert_password=None,
        api_key=None,
        default_if_none=False,
    )
    _run(service)
    assert vault.get(job.id) is None
