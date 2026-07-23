from __future__ import annotations

import asyncio
import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.credentials import (
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
from chkp_cpuse_orch.errors import (
    CredentialError,
    InventoryError,
    JobError,
    PackageError,
    TransportError,
)
from chkp_cpuse_orch.inventory import Host, Inventory, Role, Site
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.services.common import EnvironmentRegistry, HostConnector
from chkp_cpuse_orch.services.patching import PatchingService
from chkp_cpuse_orch.store import JobStatus, Store

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


def test_firewalls_lists_only_gateway_role_hosts(service: PatchingService) -> None:
    assert [h.name for h in service.firewalls("default")] == ["fw-01"]


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


def test_submit_import_rejects_unknown_host(service: PatchingService) -> None:
    with pytest.raises(InventoryError, match="not found"):
        service.submit_import("default", "nope", PKG)


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
            "cat /var/log/x": "line one\nline two\n",
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
        )
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
    creds.put_set("other", "primary", ssh_password="other-env-pw")
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
