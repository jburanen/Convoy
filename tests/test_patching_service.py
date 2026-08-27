from __future__ import annotations

import asyncio
import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from pydantic import SecretStr

from convoy.credentials import (
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
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
from convoy.services.patching import LOW_SPACE_OVERRIDABLE, PatchingService
from convoy.store import JobStatus, Store

from .fakes import DA_BUILD, SHOW_PACKAGES_ALL, FakeTransport, make_factory

PKG = "jhf_t89.tgz"
PKG_CONTENT = b"fake jumbo hotfix bytes"
PKG_SHA1 = hashlib.sha1(PKG_CONTENT).hexdigest()


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    # credential_sets.environment FKs to environments; create the env row first.
    store.insert_environment("default", credential_storage_enabled=True)
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="gaia-pw",
        expert_password="expert-pw",
    )
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
                    Host(name="spark-01", address="192.0.2.30", role=Role.SPARK_FIREWALL),
                ],
            )
        ]
    )


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(
        responses={
            # More specific keys first — FakeTransport._lookup matches in
            # insertion order, and these must win over the generic "show
            # installer packages" below for _wait_until_imported's poll.
            "show installer packages imported": f"{PKG}      Imported",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer package ": "Status:           Installed",
            "show installer status build": DA_BUILD,
            "sha1sum": f"{PKG_SHA1}  /var/log/upload/{PKG}",
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
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )


def _run(service: PatchingService) -> None:
    asyncio.run(service.runner.run_until_idle())


# -- queries ---------------------------------------------------------------------


def test_management_servers_excludes_gateways(service: PatchingService) -> None:
    assert [h.name for h in service.management_servers("default")] == ["mgmt-01", "mgmt-02"]


def test_firewalls_lists_all_firewall_role_hosts(service: PatchingService) -> None:
    # firewalls() lists every FIREWALL_ROLES member, including Spark.
    assert [h.name for h in service.firewalls("default")] == ["fw-01", "spark-01"]


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


def test_detect_caches_live_cluster_role(
    service: PatchingService, transport: FakeTransport, store: Store
) -> None:
    transport.responses["show cluster state"] = (
        "ID         Unique Address  Assigned Load   State          Name\n"
        "1 (local)  11.22.33.245    100%            ACTIVE(!)      Member1\n"
    )
    service.detect("default", "mgmt-01")
    cached = store.get_server_state("default", "mgmt-01")
    assert cached is not None
    assert cached.cluster_role == "ACTIVE(!)"


def test_detect_requires_credentials(service: PatchingService) -> None:
    with pytest.raises(CredentialError, match="no credential assigned"):
        service.detect("default", "mgmt-02")  # in inventory, but no set assigned


def test_assigned_credential_summary(service: PatchingService) -> None:
    assert service.assigned_credential("default", "mgmt-01") == "primary"
    assert service.assigned_credential("default", "mgmt-02") is None


# -- submission validation --------------------------------------------------------


def test_submit_import_rejects_unknown_host(service: PatchingService) -> None:
    with pytest.raises(InventoryError, match="not found"):
        service.submit_import("default", "nope", PKG)


def test_submit_import_allows_a_credentialed_spark_firewall_host(
    service: PatchingService, store: Store
) -> None:
    # Spark (Gaia Embedded) firewalls are patched directly via CPUSE too now
    # (operator-directed, 2026-08-18) — patchable_host() no longer carves
    # them out, same as any other FIREWALL_ROLES member.
    row = store.get_credential_set_by_name("default", "primary")
    assert row is not None
    service.registry.get("default").inventory.host("spark-01").credential_set_id = row.id
    job = service.submit_import("default", "spark-01", PKG)
    assert job.target == "spark-01"


def test_submit_import_allows_a_credentialed_firewall_host(
    service: PatchingService, store: Store
) -> None:
    # Firewalls (gateway/cluster_member role) are patched directly via CPUSE
    # exactly like management servers — patchable_host doesn't reject them.
    row = store.get_credential_set_by_name("default", "primary")
    assert row is not None
    service.registry.get("default").inventory.host("fw-01").credential_set_id = row.id
    job = service.submit_import("default", "fw-01", PKG)
    assert job.target == "fw-01"


def test_submit_import_rejects_missing_package(service: PatchingService) -> None:
    with pytest.raises(PackageError, match="no such package"):
        service.submit_import("default", "mgmt-01", "ghost.tgz")


# -- host-busy blocking (a second job can't start while one is in flight) ---------


def test_submit_rejects_a_second_job_for_a_busy_host(service: PatchingService) -> None:
    service.submit_import("default", "mgmt-01", PKG)  # left PENDING — runner never run
    with pytest.raises(JobError, match="already pending"):
        service.submit_install("default", "mgmt-01", "Pkg", confirmed=True)
    with pytest.raises(JobError, match="already pending"):
        service.submit_import_cloud("default", "mgmt-01", "Pkg")


def test_submit_allows_a_different_host_while_one_is_busy(
    service: PatchingService, store: Store
) -> None:
    row = store.get_credential_set_by_name("default", "primary")
    assert row is not None
    service.registry.get("default").inventory.host("mgmt-02").credential_set_id = row.id

    service.submit_import("default", "mgmt-01", PKG)  # left PENDING
    job = service.submit_import("default", "mgmt-02", PKG)
    assert job.target == "mgmt-02"


def test_submit_allowed_again_once_the_previous_job_finishes(service: PatchingService) -> None:
    service.submit_import("default", "mgmt-01", PKG)
    _run(service)  # drains the queue — the job reaches a terminal state
    job = service.submit_import("default", "mgmt-01", PKG)
    assert job.status is JobStatus.PENDING


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
    assert "sha1 verified" in messages
    assert "confirmed: package is listed as imported" in messages
    assert transport.closed is True
    # sha1 is checked before the import command ever runs.
    sha1_idx = next(i for i, c in enumerate(transport.commands) if "sha1sum" in c)
    import_idx = next(i for i, c in enumerate(transport.commands) if "installer import" in c)
    assert sha1_idx < import_idx


def test_import_job_matches_by_hf_config_when_cpuse_uses_a_human_readable_identifier(
    store: Store, creds: CredentialStore, inventory: Inventory, tmp_path: Path
) -> None:
    # CPUSE renders some package types (JHFs) in `show installer packages
    # imported` as a human-readable string with no relation to the uploaded
    # filename — filename/stem matching alone would never find this one.
    hf_config_text = (
        b"2474\n"
        b"PATCH_NAME=BUNDLE_R82_10_JUMBO_HF_MAIN\n"
        b"TAKE_NUMBER=24\n"
        b"BRANCH_NAME=R82_10_jumbo_hf_main\n"
        b"PACKAGE_TYPE=BUNDLE\n"
        b"CATEGORY=JUMBO\n"
        b"DIRECT_BASE_VERSION=R82.10\n"
    )
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as tar:
        info = tarfile.TarInfo("hf.config")
        info.size = len(hf_config_text)
        tar.addfile(info, io.BytesIO(hf_config_text))
    inner_bytes = inner.getvalue()

    package_name = "Check_Point_R82_10_JUMBO_HF_MAIN_Bundle_T24_FULL.tgz"
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w:gz") as tar:
        info = tarfile.TarInfo("metadata.tar")
        info.size = len(inner_bytes)
        tar.addfile(info, io.BytesIO(inner_bytes))
    package_content = outer.getvalue()
    package_sha1 = hashlib.sha1(package_content).hexdigest()

    ps = PackageStore(store, tmp_path / "packages-hfconfig")
    ps.add_stream(package_name, io.BytesIO(package_content))

    _assign(store, inventory, "mgmt-01")
    transport = FakeTransport(
        responses={
            "show installer packages imported": (
                "R82.10 Jumbo Hotfix Accumulator Take 24      Imported"
            ),
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
            "sha1sum": f"{package_sha1}  /var/log/upload/{package_name}",
        }
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=ps,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )

    job = service.submit_import("default", "mgmt-01", package_name)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "confirmed: package is listed as imported" in messages


def test_import_job_matches_the_real_device_display_name_type_output(
    store: Store, creds: CredentialStore, inventory: Inventory, tmp_path: Path
) -> None:
    # Reproduces an observed false failure (2026-07-22): this Gaia version's
    # `show installer packages imported` has no per-row status text (a
    # "Display name / Type" table instead — see test_cpuse.py) plus banner
    # noise. The old parser silently returned zero packages for this shape,
    # so the job failed even though the package genuinely was imported.
    real_output = (
        "**  *** **\n"
        "**              Connection error. Packages list might be incomplete **\n"
        "**  *** **\n"
        "Display name                                                    Type\n"
        "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz          Hotfix\n"
        "R82.10 Jumbo Hotfix Accumulator Take 19                         Hotfix\n"
        "R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 24       Hotfix\n"
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz            Hotfix\n"
    )
    # Uploaded as ".tar" — CPUSE lists it as ".tgz". The stem-substring match
    # (unrelated to this bug) already tolerates that; see .claude/memory.
    package_name = "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tar"
    package_content = b"not a real archive, hf.config isn't needed for this test"
    package_sha1 = hashlib.sha1(package_content).hexdigest()

    ps = PackageStore(store, tmp_path / "packages-real-output")
    ps.add_stream(package_name, io.BytesIO(package_content))

    _assign(store, inventory, "mgmt-01")
    transport = FakeTransport(
        responses={
            "show installer packages imported": real_output,
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
            "sha1sum": f"{package_sha1}  /var/log/upload/{package_name}",
        }
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=ps,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )

    job = service.submit_import("default", "mgmt-01", package_name)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error


_PLENTY_DF = (
    "Filesystem     1024-blocks     Used  Available Capacity Mounted on\n"
    "/dev/sda1        999999999     1000  999999999        1% /"
)


def _low_df(mount: str) -> str:
    return (
        "Filesystem     1024-blocks     Used  Available Capacity Mounted on\n"
        f"/dev/sda1               10        9          0       99% {mount}"
    )


def _df_with_available_kb(mount: str, available_kb: int) -> str:
    return (
        "Filesystem     1024-blocks     Used  Available Capacity Mounted on\n"
        f"/dev/sda1        999999999     1000  {available_kb}       1% {mount}"
    )


# A bigger fake package than PKG — needed to land free space between the
# 1.5x-package-size override floor and a path's full requirement, which df's
# integer-KB granularity can't express against PKG's 23 bytes.
_BIG_PKG = "big_jhf.tgz"
_BIG_PKG_CONTENT = b"x" * 100_000
_BIG_PKG_SHA1 = hashlib.sha1(_BIG_PKG_CONTENT).hexdigest()


def test_import_job_fails_if_var_log_has_insufficient_space(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    # PKG_CONTENT is 23 bytes; /var/log needs 3x that (69 bytes) — the more
    # specific key must be registered first, since "df -Pk /" is otherwise a
    # substring match for "df -Pk /var/log" too (see FakeTransport).
    transport.responses["df -Pk /var/log"] = _low_df("/var/log")
    transport.responses["df -Pk /"] = _PLENTY_DF
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "PreCheckError" in finished.error
    assert "not enough free space on /var/log" in finished.error
    # Never got as far as uploading — this is a fail-fast pre-check.
    assert transport.puts == []


def test_import_job_fails_if_root_has_insufficient_space(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["df -Pk /var/log"] = _PLENTY_DF
    transport.responses["df -Pk /"] = _low_df("/")
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "PreCheckError" in finished.error
    assert "not enough free space on /" in finished.error
    assert transport.puts == []


def test_import_job_logs_disk_space_ok_when_sufficient(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "disk space OK on /var/log" in messages
    assert "disk space OK on /" in messages


def test_import_job_offers_override_for_a_soft_shortfall(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    packages.add_stream(_BIG_PKG, io.BytesIO(_BIG_PKG_CONTENT))
    # 100_000-byte package: /var/log needs 300_000 (3x), the override floor is
    # 150_000 (1.5x) — 200KB (204_800 bytes) sits between the two: short of
    # the requirement but still override-eligible.
    transport.responses["df -Pk /var/log"] = _df_with_available_kb("/var/log", 200)
    transport.responses["df -Pk /"] = _PLENTY_DF
    job = service.submit_import("default", "mgmt-01", _BIG_PKG)  # no force_low_space
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "PreCheckError" in finished.error
    assert "can be overridden" in finished.error
    assert transport.puts == []


def test_import_job_succeeds_with_force_low_space_override(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    packages.add_stream(_BIG_PKG, io.BytesIO(_BIG_PKG_CONTENT))
    transport.responses["sha1sum"] = f"{_BIG_PKG_SHA1}  /var/log/upload/{_BIG_PKG}"
    transport.responses["show installer packages imported"] = f"{_BIG_PKG}      Imported"
    transport.responses["df -Pk /var/log"] = _df_with_available_kb("/var/log", 200)
    transport.responses["df -Pk /"] = _PLENTY_DF
    job = service.submit_import("default", "mgmt-01", _BIG_PKG, force_low_space=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "proceeding anyway" in messages


def test_import_job_never_overrides_below_the_hard_floor(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    packages.add_stream(_BIG_PKG, io.BytesIO(_BIG_PKG_CONTENT))
    # 100KB (102_400 bytes) available is below the 150_000-byte override
    # floor — force_low_space must not save this.
    transport.responses["df -Pk /var/log"] = _df_with_available_kb("/var/log", 100)
    transport.responses["df -Pk /"] = _PLENTY_DF
    job = service.submit_import("default", "mgmt-01", _BIG_PKG, force_low_space=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "cannot be overridden" in finished.error
    assert transport.puts == []


# -- disk space is part of the import job (operator-directed, 2026-08-26) ---------
#
# It used to be a synchronous pre-submit probe, so a slow SSH + expert
# escalation left the operator on a spinner with no job to look at, and a
# shortfall surfaced as a browser alert rather than a job they could inspect.
# Now the job owns it: the failure IS the job's failure, and an eligible
# shortfall is retried through retry_import_with_override.


def _fail_import_on_low_space(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> str:
    packages.add_stream(_BIG_PKG, io.BytesIO(_BIG_PKG_CONTENT))
    transport.responses["df -Pk /var/log"] = _df_with_available_kb("/var/log", 200)
    transport.responses["df -Pk /"] = _PLENTY_DF
    # So a retry that gets PAST the gate can complete normally.
    transport.responses["sha1sum"] = f"{_BIG_PKG_SHA1}  /var/log/upload/{_BIG_PKG}"
    transport.responses["show installer packages imported"] = f"{_BIG_PKG}      Imported"
    job = service.submit_import("default", "mgmt-01", _BIG_PKG)
    _run(service)
    return job.id


def test_import_job_fails_on_an_overridable_shortfall_without_uploading(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    job_id = _fail_import_on_low_space(service, store, transport, packages)

    finished = store.get_job(job_id)
    assert finished.status is JobStatus.FAILED
    assert LOW_SPACE_OVERRIDABLE in (finished.error or "")
    assert "/var/log" in (finished.error or "")
    assert transport.puts == []  # failed the gate before uploading anything


def test_retry_with_override_submits_a_new_import_that_proceeds(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    job_id = _fail_import_on_low_space(service, store, transport, packages)

    retried = service.retry_import_with_override(job_id)
    assert retried.id != job_id  # a NEW job; the failure stays as the audit record
    _run(service)

    assert store.get_job(retried.id).status is JobStatus.SUCCEEDED
    assert store.get_job(job_id).status is JobStatus.FAILED  # untouched
    assert transport.puts  # the override actually let the upload happen


def test_retry_with_override_is_refused_for_an_unrelated_failure(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    """The link must not become a way to blanket-force any failed import."""
    transport.put_size = lambda local: 1  # fails on size mismatch, not disk space
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)
    assert store.get_job(job.id).status is JobStatus.FAILED

    with pytest.raises(JobError, match="overridable disk-space shortfall"):
        service.retry_import_with_override(job.id)


def test_retry_with_override_is_refused_below_the_hard_floor(
    service: PatchingService, store: Store, transport: FakeTransport, packages: PackageStore
) -> None:
    """Below 1.5x the package size there is no override, so there is no link —
    and forging the call still fails the job's own re-check."""
    packages.add_stream(_BIG_PKG, io.BytesIO(_BIG_PKG_CONTENT))
    transport.responses["df -Pk /var/log"] = _df_with_available_kb("/var/log", 1)
    transport.responses["df -Pk /"] = _PLENTY_DF
    job = service.submit_import("default", "mgmt-01", _BIG_PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "cannot be overridden" in (finished.error or "")
    assert LOW_SPACE_OVERRIDABLE not in (finished.error or "")
    with pytest.raises(JobError, match="overridable disk-space shortfall"):
        service.retry_import_with_override(job.id)


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


def test_import_job_fails_closed_on_sha1_mismatch(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    # Right size, wrong content — e.g. bit-level corruption in transit, which
    # the size check alone wouldn't catch.
    transport.responses["sha1sum"] = "0" * 40 + "  /var/log/upload/" + PKG
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "sha1 mismatch" in finished.error
    # Never imported (or cleaned up) a copy that failed verification.
    assert not any("installer import" in c for c in transport.commands)
    assert not any("rm -f" in c for c in transport.commands)


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


def test_import_job_refreshes_and_caches_state_after_success(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    # No stored state yet — nothing has queried this server before.
    assert store.get_server_state("default", "mgmt-01") is None

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    cached = store.get_server_state("default", "mgmt-01")
    assert cached is not None
    assert cached.agent_build == DA_BUILD
    # Check_Point_R81_10_JHF_T45.tgz (installed, per SHOW_PACKAGES_ALL) -> R81.10 / Take 45.
    assert cached.version == "R81.10"
    assert cached.jhf == "Take 45"
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "refreshing detected state" in messages
    assert "detected state refreshed" in messages


def test_import_job_refresh_failure_is_a_warning_not_a_job_failure(
    service: PatchingService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["show installer status build"] = (1, "device busy")
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = [(e.level, e.message) for e in store.events(job.id)]
    assert any(
        level == "warning" and "could not refresh detected state" in msg for level, msg in messages
    )
    # The import itself is still confirmed and cleaned up despite the refresh failing.
    assert any("removed temp copy" in msg for _, msg in messages)


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


def test_import_job_collapses_repeated_not_yet_imported_lines_into_one(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    """A slow import polls _wait_until_imported repeatedly before the package
    finally shows up — the "not yet listed as imported" progress line must
    overwrite itself each attempt (ctx.log(..., replace=...)) rather than
    stack up one line per poll, so the job log doesn't fill with near-
    identical lines an operator has to scroll through."""
    transport = FakeTransport(
        responses={
            "show installer packages imported": ["", "", f"{PKG}      Imported"],
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
            "sha1sum": f"{PKG_SHA1}  /var/log/upload/{PKG}",
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
        store=store,
        import_verify_attempts=5,
        import_verify_delay=0,
    )

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    waiting_lines = [e for e in store.events(job.id) if "not yet listed as imported" in e.message]
    assert len(waiting_lines) == 1  # collapsed, not one row per poll
    assert "check 2/5" in waiting_lines[0].message  # the latest attempt survives, not the first


def test_import_job_times_out_and_keeps_temp_copy_if_never_listed_as_imported(
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
            "sha1sum": f"{PKG_SHA1}  /var/log/upload/{PKG}",
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
        store=store,
        import_verify_attempts=2,
        import_verify_delay=0,  # keep the test fast — real delay is only for production
    )

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.TIMED_OUT
    assert finished.error is not None and "NOT removing the temp copy" in finished.error
    assert not any("rm -f" in c for c in transport.commands)  # never cleaned up


def test_recheck_import_resolves_timed_out_job_to_succeeded_once_imported(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    """The Jobs tab's "Check status" link: after a TIMED_OUT import, CPUSE
    finishes processing in the background and the package shows up on a
    later live check — recheck_import should resolve the job, clean up the
    temp copy, and refresh cached state, same as the automatic path would
    have if it had just waited a little longer."""
    transport = FakeTransport(
        responses={
            "show installer packages imported": "",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
            "sha1sum": f"{PKG_SHA1}  /var/log/upload/{PKG}",
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
        store=store,
        import_verify_attempts=2,
        import_verify_delay=0,
    )

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)
    assert store.get_job(job.id).status is JobStatus.TIMED_OUT

    # CPUSE has now caught up — a live check would see it as imported.
    transport.responses["show installer packages imported"] = f"{PKG}      Imported"
    resolved = service.recheck_import(job.id)

    assert resolved.status is JobStatus.SUCCEEDED
    assert any("rm -f" in c for c in transport.commands)  # temp copy cleaned up now
    messages = [e.message for e in store.events(job.id)]
    assert any("manual check: confirmed" in m for m in messages)
    assert any("removed temp copy" in m for m in messages)


def test_recheck_import_leaves_job_timed_out_when_still_not_imported(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    transport = FakeTransport(
        responses={
            "show installer packages imported": "",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
            "sha1sum": f"{PKG_SHA1}  /var/log/upload/{PKG}",
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
        store=store,
        import_verify_attempts=2,
        import_verify_delay=0,
    )

    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)
    assert store.get_job(job.id).status is JobStatus.TIMED_OUT

    resolved = service.recheck_import(job.id)

    assert resolved.status is JobStatus.TIMED_OUT
    assert not any("rm -f" in c for c in transport.commands)  # still not cleaned up
    messages = [e.message for e in store.events(job.id)]
    assert any("manual check: still not listed as imported" in m for m in messages)


def test_recheck_import_rejects_job_that_is_not_an_import_job(
    service: PatchingService, store: Store
) -> None:
    job = service.submit_import_cloud("default", "mgmt-01", "Check_Point_R81.20_JHF_T99")
    _run(service)
    assert store.get_job(job.id).status is JobStatus.SUCCEEDED  # sanity: it did run

    with pytest.raises(JobError, match="not an import job"):
        service.recheck_import(job.id)


def test_recheck_import_rejects_succeeded_import_job(
    service: PatchingService, store: Store
) -> None:
    job = service.submit_import("default", "mgmt-01", PKG)
    _run(service)
    assert store.get_job(job.id).status is JobStatus.SUCCEEDED

    with pytest.raises(JobError, match="isn't timed out"):
        service.recheck_import(job.id)


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
    assert "detected state refreshed" in messages
    cached = store.get_server_state("default", "mgmt-01")
    assert cached is not None and cached.agent_build == DA_BUILD


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
    # Confirmed via `show installer package <id>`, not just installer's own exit code.
    assert any("show installer package Check_Point_R81_20_T89" in c for c in transport.commands)
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "confirmed: package is installed" in messages
    assert "detected state refreshed" in messages
    cached = store.get_server_state("default", "mgmt-01")
    assert cached is not None and cached.agent_build == DA_BUILD


def test_install_job_logs_raw_command_output_and_poll_detail(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # The Jobs tab is the primary troubleshooting surface — CPUSE's own text
    # should show up there verbatim, not just our derived one-word summary.
    transport = FakeTransport(
        responses={
            "installer install ": (0, "Install started; this may take a while."),
            "show installer package ": "Status:           Installed\nInstallation log: /var/log/x",
            # Bounded at the source now (head -c N), not `cat` — an unbounded
            # read pulled the whole remote log into memory before capping it.
            "head -c ": "line one" + chr(10) + "line two" + chr(10),
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
        store=store,
        install_verify_attempts=2,
        install_verify_delay=0,
    )

    job = service.submit_install(
        "default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True, verify_first=False
    )
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "Install started; this may take a while." in messages
    assert "Installation log: /var/log/x" in messages
    assert "captured installation log from /var/log/x" in messages
    # The *content* of CPUSE's own install log file is fetched and captured
    # on the job record — not just its path, which is worthless once CPUSE
    # rotates or deletes the file — though the path is also kept for display.
    assert store.get_job(job.id).install_log == "line one\nline two\n"
    assert store.get_job(job.id).install_log_path == "/var/log/x"


def test_install_job_surfaces_cpuse_progress_as_the_output_headline(
    store: Store,
    creds: CredentialStore,
    packages: PackageStore,
    inventory: Inventory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CPUSE reports its own "Installing NN%" on every poll and it was only ever
    going into the job log, so following an install meant expanding the row.
    Those percentages are now the Jobs tab's Output-column headline, the same
    mechanism the SCP/upload reporters and Spark install already used."""
    written: list[str | None] = []
    original = store.set_status_text

    def spy(job_id: str, text: str | None) -> None:
        written.append(text)
        original(job_id, text)

    monkeypatch.setattr(store, "set_status_text", spy)

    transport = FakeTransport(
        responses={
            "show installer package ": [
                "Status:           Installing 10%",
                "Status:           Installing 10%",  # unchanged — must not rewrite
                "Status:           Installing 90%",
                "Status:           Installed",
            ]
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
        store=store,
        install_verify_attempts=1,
        install_verify_delay=0,
        install_stall_seconds=0,
    )

    job = service.submit_install(
        "default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True, verify_first=False
    )
    _run(service)
    assert store.get_job(job.id).status is JobStatus.SUCCEEDED

    # "installing" covers the gap before CPUSE reports any percentage of its
    # own; the percentages then replace it verbatim.
    assert "installing" in written
    assert "Installing 10%" in written
    assert "Installing 90%" in written
    # Written on change only, matching the log-on-change rule — a long install
    # parked at one percentage must not rewrite the same value every poll.
    assert written.count("Installing 10%") == 1
    # And the headline describes work in progress, so it cannot outlive the job.
    assert written[-1] is None
    assert store.get_job(job.id).status_text is None


def test_install_job_ignores_attempts_budget_once_percentage_progress_seen(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # Once Status shows a real percentage, a real install is underway — the
    # attempts budget (meant to catch installs that never actually started)
    # is dropped entirely, operator-directed. install_verify_attempts=1 would
    # fail this immediately if the cap still applied once progress is seen.
    transport = FakeTransport(
        responses={
            "show installer package ": [
                "Status:           Installing 10%",
                "Status:           Installing 55%",
                "Status:           Installing 90%",
                "Status:           Installed",
            ]
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
        store=store,
        install_verify_attempts=1,
        install_verify_delay=0,
        install_stall_seconds=0,
    )

    job = service.submit_install(
        "default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True, verify_first=False
    )
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    detail_checks = [c for c in transport.commands if "show installer package " in c]
    assert len(detail_checks) == 4  # all four checks ran, well past the attempts=1 budget

    # Each poll logs just the status line (with its own timestamp, like any
    # job log line) — not the full detail block on every check.
    messages = [e.message for e in store.events(job.id)]
    assert "status: Installing 10%" in messages
    assert "status: Installing 55%" in messages
    assert "status: Installing 90%" in messages
    assert not any(m.startswith("install status check") for m in messages)
    # The full block is only logged once, at the end.
    assert any(m.startswith("install complete:") and "Installed" in m for m in messages)


def test_install_job_does_not_repeat_an_unchanged_status_line(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # A long install sitting at the same percentage for many checks in a row
    # (operator-reported, 2026-07-23) shouldn't print that same status line
    # every 30s — only log it again once it actually changes.
    transport = FakeTransport(
        responses={
            "show installer package ": [
                "Status:           Installing 74%",
                "Status:           Installing 74%",
                "Status:           Installing 74%",
                "Status:           Installing 90%",
                "Status:           Installed",
            ]
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
        store=store,
        install_verify_attempts=1,
        install_verify_delay=0,
        install_stall_seconds=0,
    )

    job = service.submit_install(
        "default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True, verify_first=False
    )
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED
    messages = [e.message for e in store.events(job.id)]
    assert messages.count("status: Installing 74%") == 1
    assert messages.count("status: Installing 90%") == 1


def test_install_job_fails_if_status_never_shows_installed(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # Reproduces an observed false success (2026-07-22): `installer install`
    # returned success, but `show installer package <id>` kept reporting
    # "Imported" — the install never actually completed.
    transport = FakeTransport(responses={"show installer package ": "Status:           Imported"})
    _assign(store, inventory, "mgmt-01")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        install_verify_attempts=2,
        install_verify_delay=0,  # keep the test fast — real delay is only for production
    )

    job = service.submit_install("default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None
    assert "does not show as Installed" in finished.error
    # The last full `show installer package <id>` block, not just the status
    # word, so an operator can troubleshoot from the error alone.
    assert "Status:           Imported" in finished.error
    assert "'Imported'" in finished.error


def test_install_job_fails_fast_when_status_stalls_on_imported(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # Status never leaves "Imported" — the install doesn't appear to have
    # started at all — so this should give up well before the full attempts
    # budget instead of polling all the way out. install_stall_seconds=0
    # makes the very first check already count as stalled, without needing
    # to fake the passage of real time.
    transport = FakeTransport(responses={"show installer package ": "Status:           Imported"})
    _assign(store, inventory, "mgmt-01")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        install_verify_attempts=10,  # plenty of budget left...
        install_verify_delay=0,
        install_stall_seconds=0,  # ...but this makes the first check count as stalled
    )

    job = service.submit_install("default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    detail_checks = [c for c in transport.commands if "show installer package " in c]
    assert len(detail_checks) == 1  # gave up after the first check, not all 10
    messages = [(e.level, e.message) for e in store.events(job.id)]
    assert any(
        level == "warning" and "giving up rather than waiting out the full timeout" in msg
        for level, msg in messages
    )


def test_install_job_reconnects_after_a_dropped_connection_mid_reboot(
    store: Store, creds: CredentialStore, packages: PackageStore, inventory: Inventory
) -> None:
    # Reboot-required installs drop the SSH session partway through polling —
    # expected, not a failure. The first status check simulates that; the
    # reconnect that follows should succeed and see the completed install.
    class FlakyTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__(responses={"show installer package ": "Status:           Installed"})
            self._drop_next = True

        def run(self, command: str, *, timeout: float | None = None):  # type: ignore[no-untyped-def]
            if "show installer package " in command and self._drop_next:
                self._drop_next = False
                self.commands.append(command)
                raise TransportError("connection reset (simulated reboot)")
            return super().run(command, timeout=timeout)

    transport = FlakyTransport()
    _assign(store, inventory, "mgmt-01")
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
        install_verify_attempts=3,
        install_verify_delay=0,
    )

    job = service.submit_install("default", "mgmt-01", "Check_Point_R81_20_T89", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = [(e.level, e.message) for e in store.events(job.id)]
    assert any(level == "warning" and "expected mid-reboot" in msg for level, msg in messages)


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
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    assert service.detect("default", "mgmt-02").agent_build == DA_BUILD


# -- storage-disabled environments (credentials supplied per job, in memory) ------


def _ssh_bundle(secret: str = "inline-pw") -> dict:
    return {
        CredentialKind.SSH_PASSWORD: Credential(
            host="mgmt-01", kind=CredentialKind.SSH_PASSWORD, secret=SecretStr(secret)
        ),
        # Several bash-native steps (disk check, sha1 verify, install-log
        # capture) need this — see require_expert=True on submit_import/
        # submit_install.
        CredentialKind.EXPERT_PASSWORD: Credential(
            host="mgmt-01", kind=CredentialKind.EXPERT_PASSWORD, secret=SecretStr("expert-pw")
        ),
    }


def _disabled_service(
    store: Store, packages: PackageStore, inventory: Inventory, transport: FakeTransport
) -> tuple[PatchingService, JobCredentialVault]:
    vault = JobCredentialVault()
    # No credential store needed for a storage-disabled environment, but
    # server_state.environment FKs to environments — create the row so the
    # post-import state refresh (which persists there) doesn't fail closed.
    if not store.environment_exists("default"):
        store.insert_environment("default")
    registry = EnvironmentRegistry()
    registry.add(
        "default",
        HostConnector(inventory, None, make_factory(transport), credential_storage_enabled=False),
    )
    runner = JobRunner(store, on_job_finished=vault.discard)
    service = PatchingService(
        registry=registry, packages=packages, runner=runner, vault=vault, store=store
    )
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
    creds.put_set(
        "other",
        "primary",
        ssh_username="admin",
        ssh_password="other-env-pw",
        expert_password="expert-pw",
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    service = PatchingService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        store=store,
    )
    with pytest.raises(CredentialError, match="no credential assigned"):
        service.detect("default", "mgmt-02")


# ---- CPUSE display name -> file name resolution -----------------------------
# All names below are verbatim from clockwerks, 2026-08-27.

# CPUSE shows some packages under a friendly display name and others under
# their file name, on the same host, regardless of how each got there. clish
# takes only the file name (or an interactive completion number), splitting the
# friendly form on whitespace: "Could not find package R82.10".
JHF_DISPLAY_NAME = "R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 40"
# What actually sits in /var/log/CPda/repository/...#BUNDLE_R82_10_JUMBO_HF_MAIN#40/
JHF_FILENAME = "Check_Point_R82_10_jumbo_hf_main_Bundle_T40_FULL.tgz"


def test_handle_passes_through_a_filename_identifier() -> None:
    """A display name with no spaces IS the file name — that is why some
    packages have always installed fine, and it must not be touched."""
    from convoy.services.patching import resolve_cpuse_handle

    name = "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz"
    assert resolve_cpuse_handle(name, []) == name


def test_handle_resolves_a_display_name_to_the_real_file() -> None:
    from convoy.services.patching import resolve_cpuse_handle

    assert resolve_cpuse_handle(JHF_DISPLAY_NAME, [JHF_FILENAME]) == JHF_FILENAME


def test_handle_matches_on_version_and_take_not_just_substring() -> None:
    """The display name shares no substring with the file name — "Take 40" vs
    "_T40_" — so version+take is what actually resolves this."""
    from convoy.services.patching import resolve_cpuse_handle

    assert JHF_FILENAME.rsplit(".", 1)[0] not in JHF_DISPLAY_NAME  # no overlap at all
    assert resolve_cpuse_handle(JHF_DISPLAY_NAME, [JHF_FILENAME]) == JHF_FILENAME


def test_handle_tolerates_the_upload_extension_differing_from_the_box() -> None:
    """This tool uploads *.tar; CPUSE lists the same package as *.tgz."""
    from convoy.services.patching import resolve_cpuse_handle

    uploaded = "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tar"
    listed = "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz"
    assert resolve_cpuse_handle(listed, [uploaded]) == listed  # no spaces: passthrough
    spaced = "R82.10 GA Time Fix Take 9"
    assert resolve_cpuse_handle(spaced, [uploaded]) == uploaded


def test_handle_does_not_match_a_different_take() -> None:
    """Takes 24, 36 and 40 all sit in the repository on this host — resolving to
    the wrong one would install a package the operator did not choose, onto a
    box that then reboots."""
    from convoy.cpuse import CPUSEError
    from convoy.services.patching import resolve_cpuse_handle

    others = [
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T24_FULL.tgz",
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz",
    ]
    with pytest.raises(CPUSEError, match="display name"):
        resolve_cpuse_handle(JHF_DISPLAY_NAME, others)


def test_handle_picks_the_matching_take_among_the_whole_repository() -> None:
    from convoy.services.patching import resolve_cpuse_handle

    repository = [
        "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz",
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T24_FULL.tgz",
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz",
        JHF_FILENAME,
    ]
    assert resolve_cpuse_handle(JHF_DISPLAY_NAME, repository) == JHF_FILENAME


def test_handle_raises_actionably_when_nothing_matches() -> None:
    from convoy.cpuse import CPUSEError
    from convoy.services.patching import resolve_cpuse_handle

    with pytest.raises(CPUSEError, match="no usable identifier"):
        resolve_cpuse_handle(JHF_DISPLAY_NAME, [])


# ---- reading the file names off the host ------------------------------------

# Real `ls` output shape: the repository nests each package one directory deep.
REPOSITORY_LS = (
    "/var/log/CPda/repository/CheckPoint#CPUpdates#All#6.0#5#6#"
    "BUNDLE_R82_10_JUMBO_HF_MAIN#40/Check_Point_R82_10_jumbo_hf_main_Bundle_T40_FULL.tgz\n"
    "/var/log/CPda/repository/CheckPoint#CPUpdates#All#6.0#5#6#"
    "BUNDLE_R82_10_JUMBO_HF_MAIN#24/Check_Point_R82_10_jumbo_hf_main_Bundle_T24_FULL.tgz\n"
)


class _BashClient:
    def __init__(self, stdout: str = "", exc: Exception | None = None) -> None:
        self._stdout, self._exc = stdout, exc
        self.commands: list[str] = []

    def run_bash(self, command: str):
        self.commands.append(command)
        if self._exc is not None:
            raise self._exc
        from convoy.transport.ssh import CommandResult

        return CommandResult(command=command, exit_status=0, stdout=self._stdout, stderr="")


class _Ctx:
    def __init__(self) -> None:
        self.logs: list[str] = []

    def log(self, message: str, level: str = "info") -> None:
        self.logs.append(message)


def test_on_box_package_files_reads_basenames_out_of_the_repository() -> None:
    from convoy.services.patching import _on_box_package_files

    client = _BashClient(REPOSITORY_LS)
    assert _on_box_package_files(client, _Ctx()) == [
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T40_FULL.tgz",
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T24_FULL.tgz",
    ]
    assert "/var/log/CPda/repository" in client.commands[0]


def test_on_box_package_files_strips_terminal_colour_codes() -> None:
    """Regression, live gear 2026-08-27: these sessions run under a pty, so a
    colourising `ls` returned "...FULL.tgz\x1b[0m". The escape is invisible in
    a log and surfaced much later as CPUSE rejecting the identifier for
    containing control characters, after the install had already been logged as
    starting. The command is `find` now (which never colourises) and the parse
    strips SGR sequences anyway."""
    from convoy.cpuse import _check_id
    from convoy.services.patching import _on_box_package_files

    coloured = (
        "/var/log/CPda/repository/CheckPoint#CPUpdates#All#6.0#5#6#"
        "BUNDLE_R82_10_JUMBO_HF_MAIN#40/"
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T40_FULL.tgz\x1b[0m\n"
    )
    files = _on_box_package_files(_BashClient(coloured), _Ctx())
    assert files == ["Check_Point_R82_10_jumbo_hf_main_Bundle_T40_FULL.tgz"]
    # The whole point: what comes out has to survive CPUSE's own validation.
    assert _check_id(files[0]) == files[0]


def test_on_box_package_files_uses_find_not_ls() -> None:
    """`ls` is what colourised under a pty; `find` never does."""
    from convoy.services.patching import _on_box_package_files

    client = _BashClient(REPOSITORY_LS)
    _on_box_package_files(client, _Ctx())
    assert client.commands[0].startswith("find ")


def test_on_box_package_files_is_best_effort_on_a_shell_failure() -> None:
    """A host whose repository lives elsewhere, or a session that never reached
    expert, contributes no candidates rather than failing the job."""
    from convoy.errors import TransportError
    from convoy.services.patching import _on_box_package_files

    ctx = _Ctx()
    assert _on_box_package_files(_BashClient(exc=TransportError("no expert")), ctx) == []
    assert any("CPUSE repository" in m for m in ctx.logs)


def test_on_box_package_files_without_a_bash_capable_client() -> None:
    from convoy.services.patching import _on_box_package_files

    assert _on_box_package_files(object(), _Ctx()) == []
