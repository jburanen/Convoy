from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.cdt import CandidatesFile
from chkp_cpuse_orch.credentials import (
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
from chkp_cpuse_orch.errors import CDTError, JobError
from chkp_cpuse_orch.inventory import Host, Inventory, Role, Site
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.packages import PackageStore
from chkp_cpuse_orch.services.cdt_ops import CDTService
from chkp_cpuse_orch.services.common import EnvironmentRegistry, HostConnector
from chkp_cpuse_orch.store import JobStatus, Store

from .fakes import FakeTransport, make_factory

PKG = "jhf_t89.tgz"
PKG_CONTENT = b"fake cdt package bytes"

CANDIDATES_CSV = "Object Name,IP,Upgrade Order\nfw-a1,192.0.2.31,1\nfw-a2,192.0.2.32,2\n"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(
        {
            "cat /opt/CPcdt/orch_candidates.csv": CANDIDATES_CSV,
            # Unmatched commands default to rc 0, which would make pgrep report
            # a running CDT — be explicit that nothing is running by default.
            "pgrep": (1, ""),
        }
    )


@pytest.fixture
def service(store: Store, tmp_path: Path, transport: FakeTransport) -> CDTService:
    creds = CredentialStore(store, master_key="unit test master key")
    creds.put(Credential(host="mgmt-01", kind=CredentialKind.SSH_PASSWORD, secret=SecretStr("pw")))
    packages = PackageStore(store, tmp_path / "packages")
    packages.add_stream(PKG, io.BytesIO(PKG_CONTENT))
    inventory = Inventory(
        sites=[
            Site(
                name="t",
                hosts=[Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)],
            )
        ]
    )
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds, make_factory(transport)))
    return CDTService(
        registry=registry,
        packages=packages,
        runner=JobRunner(store),
        vault=JobCredentialVault(),
        poll_interval=0.01,  # fast execute polling in tests
    )


def _run(service: CDTService) -> None:
    asyncio.run(service.runner.run_until_idle())


# -- sync queries ------------------------------------------------------------------


def test_get_candidates(service: CDTService) -> None:
    cands = service.get_candidates("default", "mgmt-01")
    assert [r[0] for r in cands.rows] == ["fw-a1", "fw-a2"]


def test_save_candidates_pushes_csv(service: CDTService, transport: FakeTransport) -> None:
    count = service.save_candidates(
        "default", "mgmt-01", CandidatesFile(header=["Object Name"], rows=[["fw-a2"], ["fw-a1"]])
    )
    assert count == 2
    assert transport.puts[-1][1] == "/opt/CPcdt/orch_candidates.csv"


def test_save_candidates_refused_while_running(
    service: CDTService, transport: FakeTransport
) -> None:
    transport.responses["pgrep"] = (0, "")  # CDT process alive
    with pytest.raises(CDTError, match="refusing to change candidates"):
        service.save_candidates("default", "mgmt-01", CandidatesFile(header=["x"], rows=[["y"]]))


def test_get_status(service: CDTService, transport: FakeTransport) -> None:
    transport.responses["test -x"] = (0, "")
    transport.responses["pgrep"] = (1, "")
    transport.responses["CDT_status_brief"] = "idle since boot"
    status = service.get_status("default", "mgmt-01")
    assert status == {"available": True, "running": False, "brief": "idle since boot"}


# -- jobs --------------------------------------------------------------------------


def test_stage_job_uploads_package_and_config(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["stat -c %s"] = (1, "")  # not staged yet
    job = service.submit_stage("default", "mgmt-01", PKG)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    # Package upload, then the rendered XML config.
    assert transport.puts[0][1] == f"/var/log/upload/{PKG}"
    assert transport.puts[1][1] == "/opt/CPcdt/CentralDeploymentTool.xml"


def test_stage_job_skips_upload_when_size_matches(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["stat -c %s"] = (0, str(len(PKG_CONTENT)))
    job = service.submit_stage("default", "mgmt-01", PKG)
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    # Only the config XML was pushed; the package upload was skipped.
    assert [p[1] for p in transport.puts] == ["/opt/CPcdt/CentralDeploymentTool.xml"]
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "skip upload" in messages


def test_generate_job_reports_row_count(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_generate("default", "mgmt-01")
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    assert any("-generate" in c for c in transport.commands)
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "generated 2 candidate(s)" in messages


def test_prepare_job_extended_flag(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_prepare("default", "mgmt-01", extended=True)
    _run(service)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    assert any("-extended_preparations" in c for c in transport.commands)


def test_execute_requires_confirmation(service: CDTService) -> None:
    with pytest.raises(JobError, match="explicit confirmation"):
        service.submit_execute("default", "mgmt-01", confirmed=False)


def test_execute_job_polls_until_done(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    # pgrep: not running (pre-launch check) → running (one poll) → gone.
    transport.responses["pgrep"] = [(1, ""), (0, ""), (1, "")]
    transport.responses["nohup"] = "started"
    transport.responses["CDT_status_brief"] = "2 of 2 succeeded"

    job = service.submit_execute("default", "mgmt-01", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    messages = " | ".join(e.message for e in store.events(job.id))
    assert "launching CDT execute for 2 candidate(s)" in messages
    assert "CDT execute finished" in messages


def test_execute_job_fails_when_status_reports_failures(
    service: CDTService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["pgrep"] = [(1, ""), (1, "")]  # finishes immediately
    transport.responses["nohup"] = "started"
    transport.responses["CDT_status_brief"] = "1 succeeded, 1 Failed"

    job = service.submit_execute("default", "mgmt-01", confirmed=True)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert finished.error is not None and "reported failures" in finished.error
