from __future__ import annotations

import asyncio
import hashlib
import io
from pathlib import Path

import pytest

from chkp_cpuse_orch.credentials import CredentialStore, JobCredentialVault
from chkp_cpuse_orch.errors import InventoryError, JobError
from chkp_cpuse_orch.inventory import Host, Inventory, Role, Site
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.services.common import EnvironmentRegistry, HostConnector
from chkp_cpuse_orch.services.spark_patching import SparkPatchingService, parse_fw_ver
from chkp_cpuse_orch.store import JobStatus, Store

from .fakes import FakeTransport, make_factory

IMG = "spark_firmware.img"
IMG_CONTENT = b"fake spark firmware bytes"
IMG_SHA1 = hashlib.sha1(IMG_CONTENT).hexdigest()


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    store.insert_environment("default", credential_storage_enabled=True)
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put_set(
        "default",
        "spark-primary",
        ssh_username="admin",
        ssh_password="gaia-pw",
        expert_password="expert-pw",
    )
    cs.put_set("default", "no-expert", ssh_username="admin", ssh_password="gaia-pw")
    return cs


def _assign(store: Store, inventory: Inventory, host_name: str, set_name: str) -> None:
    row = store.get_credential_set_by_name("default", set_name)
    assert row is not None
    for site in inventory.sites:
        for host in site.hosts:
            if host.name == host_name:
                host.credential_set_id = row.id


@pytest.fixture
def packages(store: Store, tmp_path: Path) -> PackageStore:
    ps = PackageStore(store, tmp_path / "packages")
    ps.add_stream(IMG, io.BytesIO(IMG_CONTENT))
    ps.add_stream("gaia_jhf.tgz", io.BytesIO(b"not a spark image"))
    return ps


@pytest.fixture
def inventory() -> Inventory:
    return Inventory(
        sites=[
            Site(
                name="t",
                hosts=[
                    Host(name="spark-01", address="192.0.2.30", role=Role.SPARK_FIREWALL),
                    Host(name="spark-02", address="192.0.2.31", role=Role.SPARK_FIREWALL),
                    Host(name="fw-gaia", address="192.0.2.20", role=Role.GATEWAY),
                ],
            )
        ]
    )


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(
        responses={"sha1sum": f"{IMG_SHA1}  /storage/{IMG}"},
        expert_command_outputs={"bashUser on": "Done.", "bashUser off": "Done."},
    )


@pytest.fixture
def service(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    transport: FakeTransport,
) -> SparkPatchingService:
    _assign(store, inventory, "spark-01", "spark-primary")
    _assign(store, inventory, "spark-02", "no-expert")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    return SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )


def _run(service: SparkPatchingService) -> None:
    asyncio.run(service.runner.run_until_idle())


# -- submission validation --------------------------------------------------------


def test_submit_test_credentials_rejects_unknown_host(service: SparkPatchingService) -> None:
    with pytest.raises(InventoryError, match="not found"):
        service.submit_test_credentials("default", "nope")


def test_submit_test_credentials_rejects_non_spark_host(service: SparkPatchingService) -> None:
    with pytest.raises(InventoryError, match="not a Spark firewall"):
        service.submit_test_credentials("default", "fw-gaia")


def test_submit_transfer_rejects_non_image_package(service: SparkPatchingService) -> None:
    with pytest.raises(JobError, match="isn't a Spark firmware image"):
        service.submit_transfer("default", "spark-01", "gaia_jhf.tgz")


def test_submit_install_requires_confirmation(service: SparkPatchingService) -> None:
    with pytest.raises(JobError, match="confirmation"):
        service.submit_install("default", "spark-01", IMG, confirmed=False)


def test_submit_install_rejects_non_image_package(service: SparkPatchingService) -> None:
    with pytest.raises(JobError, match="isn't a Spark firmware image"):
        service.submit_install("default", "spark-01", "gaia_jhf.tgz", confirmed=True)


def test_submit_test_credentials_rejects_busy_host(
    service: SparkPatchingService, store: Store
) -> None:
    service.submit_test_credentials("default", "spark-01")
    with pytest.raises(JobError, match="already"):
        service.submit_test_credentials("default", "spark-01")


# -- test_credentials job -----------------------------------------------------------


def test_test_credentials_succeeds(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_test_credentials("default", "spark-01")
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    assert transport.closed is True
    assert len(transport.interactive_shells) == 1
    assert transport.interactive_shells[0].closed is True
    # No mutating command was ever run — this job only proves login + expert.
    assert not any("bashUser" in c for c in transport.commands)


def test_test_credentials_short_circuits_without_expert_password(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_test_credentials("default", "spark-02")  # "no-expert" set
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "no expert-mode password" in finished.error
    # No SSH attempted at all — the check happens before any connect.
    assert transport.interactive_shells == []
    assert transport.closed is False


def test_test_credentials_fails_on_wrong_expert_password(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    transport = FakeTransport(expert_wrong_password=True)
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_test_credentials("default", "spark-01")
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "wrong password" in finished.error


# -- transfer job -------------------------------------------------------------------


def test_transfer_happy_path(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    assert len(transport.puts) == 1
    local_path, remote_path = transport.puts[0]
    assert remote_path == f"/storage/{IMG}"
    assert Path(local_path).name == IMG
    # Two interactive (expert-mode) sessions: enabling bashUser and disabling
    # it again afterwards — the transfer itself doesn't need one.
    assert len(transport.interactive_shells) == 2
    events = [e.message for e in store.events(job.id)]
    assert any("bashUser on output" in e and "Done." in e for e in events)
    assert any("bashUser off output" in e and "Done." in e for e in events)
    assert not any("upgrade_revert_image.sh" in e for e in events)  # transfer only
    assert any("staged in /storage" in e and "Install button" in e for e in events)
    cached = store.get_server_state("default", "spark-01")
    assert cached is not None and cached.installable == [IMG]


def test_transfer_fails_on_sha1_mismatch(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    transport = FakeTransport(responses={"sha1sum": "0" * 40 + f"  /storage/{IMG}"})
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "sha1 mismatch" in finished.error
    # Never reached the disable-bashUser phase — only the enable one ran.
    assert len(transport.interactive_shells) == 1
    cached = store.get_server_state("default", "spark-01")
    assert cached is None or IMG not in cached.installable


def test_transfer_fails_without_expert_password(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_transfer("default", "spark-02", IMG)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "no expert-mode password" in finished.error
    assert transport.interactive_shells == []


# -- install job --------------------------------------------------------------------


def test_transfer_then_install_full_flow(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    """The realistic sequence: transfer stages the image and lists it as
    installable, install (a separate, later job) runs the upgrade and drops
    it from that list again."""
    transfer_job = service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    assert store.get_job(transfer_job.id).status is JobStatus.SUCCEEDED
    assert store.get_server_state("default", "spark-01").installable == [IMG]

    install_job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(install_job.id)
    assert finished.status is JobStatus.SUCCEEDED
    events = [e.message for e in store.events(install_job.id)]
    # bashUser off is transfer's job (already ran above) — install doesn't
    # repeat it.
    assert not any("bashUser" in e for e in events)
    assert any("upgrade_revert_image.sh" in e for e in events)
    assert any("does not and cannot fully confirm" in e for e in events)
    assert store.get_server_state("default", "spark-01").installable == []


def test_install_fails_on_stale_mount(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Real-hardware-confirmed 2026-08-19 (see upgrade_revert_image.sh's own
    mount_pfrm_inactive_part(), which checks `mount`'s exit status, not
    mke2fs's): mke2fs refusing because the inactive partition is already
    mounted doesn't necessarily abort the script, so this must fail the job
    itself rather than let a silently-stale upgrade report as succeeded."""
    remote_path = f"/storage/{IMG}"
    transport = FakeTransport(
        expert_command_outputs={
            "bashUser on": "Done.",
            "bashUser off": "Done.",
            f"upgrade_revert_image.sh {remote_path} upgrade safe": (
                "mke2fs 1.44.1 (24-Mar-2018)\n"
                "/dev/mmcblk1p6 is mounted; will not make a filesystem here!\n"
                "yes: Broken pipe\n"
                "tune2fs 1.44.1 (24-Mar-2018)"
            ),
        },
    )
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "already mounted" in finished.error or "mke2fs" in finished.error
    assert "stale mount" in finished.error


def test_install_succeeds_when_connection_drops_on_upgrade(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    transport = FakeTransport(expert_drop_on="upgrade_revert_image.sh")
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    events = [e.message for e in store.events(job.id)]
    assert any("expected if the device began rebooting" in e for e in events)


def test_install_fails_and_leaves_connection_open_on_timeout(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Real-hardware-confirmed 2026-08-20: a deadline elapsing with the SSH
    channel still open is not evidence the device is rebooting (unlike a
    genuine channel-closed drop, see the sibling test above) — the script may
    still be legitimately running (e.g. extracting a large rootfs). This must
    fail the job closed rather than report success, and must NOT force-close
    the still-in-use connection out from under the remote command."""
    transport = FakeTransport(expert_timeout_on="upgrade_revert_image.sh")
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "did not return control" in finished.error
    assert "NOT evidence" in finished.error
    assert transport.closed is False
    assert transport.interactive_shells[-1].closed is False


def test_install_fails_without_expert_password(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_install("default", "spark-02", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "no expert-mode password" in finished.error
    assert transport.interactive_shells == []


# -- detect (refresh) --------------------------------------------------------------


def test_parse_fw_ver_strips_banner_prefix() -> None:
    assert (
        parse_fw_ver("This is Check Point's 1550 Appliance R81.10.17 - Build 892\n")
        == "1550 Appliance R81.10.17 - Build 892"
    )


def test_parse_fw_ver_falls_back_to_trimmed_line_without_prefix() -> None:
    assert parse_fw_ver("  some other banner text  \n") == "some other banner text"


def test_detect_runs_fw_ver_not_cpuse(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["fw ver"] = "This is Check Point's 1550 Appliance R81.10.17 - Build 892"
    version = service.detect("default", "spark-01")
    assert version == "1550 Appliance R81.10.17 - Build 892"
    assert any(c == "fw ver" for c in transport.commands)
    assert not any("installer" in c or "cluster state" in c for c in transport.commands)


def test_detect_caches_state_with_no_jhf_or_agent_build(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["fw ver"] = "This is Check Point's 1550 Appliance R81.10.17 - Build 892"
    service.detect("default", "spark-01")
    cached = store.get_server_state("default", "spark-01")
    assert cached is not None
    assert cached.version == "1550 Appliance R81.10.17 - Build 892"
    assert cached.jhf is None
    assert cached.agent_build is None
    assert cached.cluster_role is None
    assert cached.installable == []
    assert cached.installed == []


def test_detect_rejects_non_spark_host(service: SparkPatchingService) -> None:
    with pytest.raises(InventoryError, match="not a Spark firewall"):
        service.detect("default", "fw-gaia")


def test_detect_preserves_installable_across_refresh(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    """Regression guard: detect() used to build a brand-new ServerStateRow on
    every refresh, silently wiping out whatever a transfer job had staged
    into installable (see submit_transfer / _mark_staged)."""
    service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    assert store.get_server_state("default", "spark-01").installable == [IMG]

    transport.responses["fw ver"] = "This is Check Point's 1550 Appliance R81.10.17 - Build 892"
    service.detect("default", "spark-01")
    cached = store.get_server_state("default", "spark-01")
    assert cached is not None
    assert cached.version == "1550 Appliance R81.10.17 - Build 892"
    assert cached.installable == [IMG]


def test_ensure_host_free_shared_with_cpuse_still_works(store: Store) -> None:
    """Regression guard for the ensure_host_free extraction (moved from
    PatchingService to services.common) — importable and callable the same
    way from either service."""
    from chkp_cpuse_orch.services.common import ensure_host_free

    store.insert_environment("default", credential_storage_enabled=True)
    ensure_host_free(store, "default", "anything")  # no jobs yet — must not raise
