from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.credentials import Credential, CredentialKind, CredentialStore
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
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put(
        Credential(
            host="mgmt-01",
            kind=CredentialKind.SSH_PASSWORD,
            username="admin",
            secret=SecretStr("gaia-pw"),
        )
    )
    return cs


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
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    return PatchingService(registry=registry, packages=packages, runner=JobRunner(store))


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
    with pytest.raises(CredentialError, match="no SSH credential"):
        service.detect("default", "mgmt-02")  # inventory has it, credential store doesn't


def test_credential_kinds_secret_free_summary(service: PatchingService) -> None:
    assert service.credential_kinds("default", "mgmt-01") == ["ssh_password"]
    assert service.credential_kinds("default", "mgmt-02") == []


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
    assert "import finished" in messages
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


# -- fleet-wide credential fallback ----------------------------------------------


def test_wildcard_credential_fallback(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> None:
    creds.put(Credential(host="*", kind=CredentialKind.SSH_PASSWORD, secret=SecretStr("fleet-pw")))
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(registry=registry, packages=packages, runner=JobRunner(store))
    # mgmt-02 has no host-specific credential; the "*" default satisfies it.
    detected = service.detect("default", "mgmt-02")
    assert detected.agent_build == DA_BUILD


def test_wildcard_credential_never_crosses_environments(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> None:
    # A "*" credential stored in another environment must NOT satisfy this one.
    creds.put(
        Credential(
            host="*",
            kind=CredentialKind.SSH_PASSWORD,
            secret=SecretStr("other-env-pw"),
            environment="other",
        )
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(registry=registry, packages=packages, runner=JobRunner(store))
    with pytest.raises(CredentialError, match="no SSH credential"):
        service.detect("default", "mgmt-02")
