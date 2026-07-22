from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.credentials import (
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
from chkp_cpuse_orch.errors import CredentialError, InventoryError, JobError, PackageError
from chkp_cpuse_orch.inventory import Host, Inventory, Role, Site
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.services.common import EnvironmentRegistry, HostConnector
from chkp_cpuse_orch.services.patching import PatchingService
from chkp_cpuse_orch.store import JobStatus, Store

from .fakes import DA_BUILD, SHOW_PACKAGES_ALL, FakeTransport, make_factory

PKG = "jhf_t89.tgz"
PKG_CONTENT = b"fake jumbo hotfix bytes"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    # credential_sets.environment FKs to environments; create the env row first.
    store.insert_environment("default", credential_storage_enabled=True)
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put_set("default", "primary", ssh_username="admin", ssh_password="gaia-pw")
    return cs


def _assign(store: Store, inventory: Inventory, host_name: str, set_name: str = "primary") -> None:
    """Point an inventory Host at a credential set by id (the resolution key)."""
    row = store.get_credential_set_by_name("default", set_name)
    assert row is not None
    for site in inventory.sites:
        for host in site.hosts:
            if host.name == host_name:
                host.credential_set_id = row.id


@pytest.fixture
def packages(store: Store, tmp_path: Path) -> PackageStore:
    ps = PackageStore(store, tmp_path / "packages")
    ps.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    return ps


@pytest.fixture
def inventory() -> Inventory:
    return Inventory(
        sites=[
            Site(
                name="t",
                hosts=[
                    Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT),
                    Host(name="mgmt-02", address="192.0.2.11", role=Role.MDS),
                    Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY),
                ],
            )
        ]
    )


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(
        responses={
            # More specific key first — FakeTransport._lookup matches in
            # insertion order, and this must win over the generic "show
            # installer packages" below for _wait_until_imported's poll.
            "show installer packages imported": f"{PKG}      Imported",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
        }
    )


@pytest.fixture
def service(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> PatchingService:
    _assign(store, inventory, "mgmt-01")  # mgmt-01 gets the "primary" set; mgmt-02 stays unassigned
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    return PatchingService(
        registry=registry, packages=packages, runner=JobRunner(store), vault=JobCredentialVault()
    )


def _run(service: PatchingService) -> None:
    asyncio.run(service.runner.run_until_idle())


# -- queries ---------------------------------------------------------------------


def test_management_servers_excludes_gateways(service: PatchingService) -> None:
    assert [h.name for h in service.management_servers("default")] == ["mgmt-01", "mgmt-02"]


def test_detect_parses_live_state_and_closes(
    service: PatchingService, transport: FakeTransport
) -> None:
    detected = service.detect("default", "mgmt-01")
    assert detected.agent_build == DA_BUILD
    assert [p.identifier for p in detected.packages] == [
        "Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz",
        "Check_Point_R81_10_JHF_T45.tgz",
    ]
    assert transport.closed is True


def test_detect_requires_credentials(service: PatchingService) -> None:
    with pytest.raises(CredentialError, match="no credential assigned"):
        service.detect("default", "mgmt-02")  # in inventory, but no set assigned


def test_assigned_credential_summary(service: PatchingService) -> None:
    assert service.assigned_credential("default", "mgmt-01") == "primary"
    assert service.assigned_credential("default", "mgmt-02") is None


# -- submission validation --------------------------------------------------------


def test_submit_import_rejects_unknown_and_gateway_hosts(service: PatchingService) -> None:
    with pytest.raises(InventoryError, match="not found"):
        service.submit_import("default", "nope", PKG)
    with pytest.raises(InventoryError, match="patched via CDT"):
        service.submit_import("default", "fw-01", PKG)


def test_submit_import_rejects_missing_package(service: PatchingService) -> None:
    with pytest.raises(PackageError, match="no such package"):
        service.submit_import("default", "mgmt-01", "ghost.tgz")


def test_submit_install_requires_confirmation(service: PatchingService) -> None:
    with pytest.raises(JobError, match="explicit confirmation"):
        service.submit_install("default", "mgmt-01", "Pkg", confirmed=False)


# -- import job -------------------------------------------------------------------


def test_import_job_uploads_then_imports(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    # SFTP upload to the staging dir, then a clish import of that full path.
    assert transport.puts[0][1] == f"/var/log/upload/{PKG}"
    assert any(
        "installer import local /var/log/upload/" in c and "not-interactive" in c
        for c in transport.commands
    )
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "upload complete" in messages
    assert "confirmed: package is listed as imported" in messages
    assert transport.closed is True


def test_import_job_fails_closed_on_size_mismatch(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.put_size = lambda local: 1  # remote reports a short file
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "size mismatch" in finished.error
    # And we never went on to import a corrupt upload.
    assert not any("installer import" in c for c in transport.commands)


def test_import_job_removes_temp_copy_after_import(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    import_idx = next(i for i, c in enumerate(transport.commands) if "installer import local" in c)
    cleanup_idx = next(
        i for i, c in enumerate(transport.commands) if f"rm -f /var/log/upload/{PKG}" in c
    )
    assert cleanup_idx > import_idx  # cleanup happens after, not before, the import
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "removed temp copy" in messages


def test_import_job_cleanup_failure_is_a_warning_not_a_job_failure(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["rm -f"] = (1, "permission denied")
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = [(e.level, e.message) for e in store.events(job.id)]
    assert any(
        level == "warning" and "could not remove temp copy" in msg for level, msg in messages
    )


def test_import_job_fails_and_keeps_temp_copy_if_never_listed_as_imported(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # `installer import local` returns immediately while CPUSE keeps
    # processing in the background — reproduces the observed failure where
    # the temp file was removed before CPUSE finished, and CPUSE then failed
    # with "package file is missing". `show installer packages imported`
    # never mentions PKG here, standing in for that race.
    transport = FakeTransport(
        responses={
            "show installer packages imported": "",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
        }
    )
    _assign(store, inventory, "mgmt-01")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        import_verify_attempts=2,
        import_verify_delay=0,  # keep the test fast — real delay is only for production
    )

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "NOT removing the temp copy" in finished.error
    assert not any("rm -f" in c for c in transport.commands)  # never cleaned up


# -- import-from-cloud job ---------------------------------------------------------


def test_import_cloud_job_imports_by_id_with_no_upload(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_import_cloud("default", "mgmt-01", "Check_Point_R81.20_JHF_T99")
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    assert transport.puts == []  # nothing uploaded — the host fetches it itself
    assert any(
        "installer import Check_Point_R81.20_JHF_T99" in c and "not-interactive" in c
        for c in transport.commands
    )
    # Bare "import <id>", never "import local" (that's the upload-based flow).
    assert not any("import local" in c for c in transport.commands)
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "import finished" in messages


# -- install job ------------------------------------------------------------------


def test_install_job_verifies_then_installs(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_install("default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True)
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    installer_cmds = [c for c in transport.commands if "installer" in c]
    assert "verify" in installer_cmds[0]
    assert "install" in installer_cmds[1]


def test_install_job_can_skip_verify(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_install(
        "default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True, verify_first=False
    )
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    assert not any("installer verify" in c for c in transport.commands)


def test_failed_installer_command_fails_the_job(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.fail_rc = 1
    job = service.submit_install("default", "mgmt-01", "Pkg-1", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "CPUSE" in finished.error


# -- a credential set reused across servers --------------------------------------


def test_credential_set_shared_across_servers(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> None:
    # One set assigned to two servers is the replacement for the old "*" default.
    _assign(store, inventory, "mgmt-01")
    _assign(store, inventory, "mgmt-02")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry, packages=packages, runner=JobRunner(store), vault=JobCredentialVault()
    )
    assert service.detect("default", "mgmt-02").agent_build == DA_BUILD


# -- storage-disabled environments (credentials supplied per job, in memory) ------


def _ssh_bundle(secret: str = "inline-pw") -> dict:
    return {
        CredentialKind.SSH_PASSWORD: Credential(
            host="mgmt-01", kind=CredentialKind.SSH_PASSWORD, secret=SecretStr(secret)
        )
    }


def _disabled_service(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> tuple[PatchingService, JobCredentialVault]:
    vault = JobCredentialVault()
    # No credential store needed at all for a storage-disabled environment.
    registry = EnvironmentRegistry()
    registry.add(
        "default",
        HostConnector(inventory, None, make_factory(transport), credential_storage_enabled=False),
    )
    runner = JobRunner(store, on_job_finished=vault.discard)
    service = PatchingService(registry=registry, packages=packages, runner=runner, vault=vault)
    return service, vault


def test_storage_disabled_submit_requires_inline_credentials(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> None:
    service, _vault = _disabled_service(store, packages, inventory, transport)
    with pytest.raises(CredentialError, match="does not store credentials"):
        service.submit_import("default", "mgmt-01", PKG)  # no credentials supplied


def test_storage_disabled_detect_uses_inline_credentials(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> None:
    service, _vault = _disabled_service(store, packages, inventory, transport)
    detected = service.detect("default", "mgmt-01", credentials=_ssh_bundle())
    assert detected.agent_build == DA_BUILD
    with pytest.raises(CredentialError, match="does not store credentials"):
        service.detect("default", "mgmt-01")  # missing


def test_storage_disabled_job_runs_then_credentials_are_discarded(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> None:
    service, vault = _disabled_service(store, packages, inventory, transport)
    job = service.submit_import("default", "mgmt-01", PKG, credentials=_ssh_bundle())
    # Held in memory until the job runs — never written anywhere.
    assert vault.get(job.id) is not None

    asyncio.run(service.runner.run_until_idle())

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED, store.get_job(job.id).error
    assert transport.puts[0][1] == f"/var/log/upload/{PKG}"
    # The runner finalizer dropped the in-memory credentials the moment it ended.
    assert vault.get(job.id) is None


def test_storage_disabled_job_credentials_discarded_even_on_failure(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> None:
    service, vault = _disabled_service(store, packages, inventory, transport)
    transport.fail_rc = 1  # make the CPUSE import command fail
    job = service.submit_import("default", "mgmt-01", PKG, credentials=_ssh_bundle())
    asyncio.run(service.runner.run_until_idle())

    assert store.get_job(job.id).status is JobStatus.FAILED
    assert vault.get(job.id) is None  # cleared regardless of outcome


def test_set_in_other_environment_does_not_satisfy_unassigned_server(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> None:
    # A credential set in another environment must NOT satisfy an unassigned
    # server here — resolution is strictly per-server assignment.
    store.insert_environment("other")
    creds.put_set("other", "primary", ssh_password="other-env-pw")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry, packages=packages, runner=JobRunner(store), vault=JobCredentialVault()
    )
    with pytest.raises(CredentialError, match="no credential assigned"):
        service.detect("default", "mgmt-02")
