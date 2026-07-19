from __future__ import annotations

import pytest

from chkp_cpuse_orch.cdt import CDT, CandidatesFile, CDTStatus, build_config_xml
from chkp_cpuse_orch.errors import CDTError

from .fakes import FakeTransport

CANDIDATES_CSV = """\
Object Name,Cluster Name,IP Address,Version,State,Upgrade Order
fw-a1,cluster-a,192.0.2.31,R81.10,standby,1
fw-a2,cluster-a,192.0.2.32,R81.10,active,2
fw-01,,192.0.2.20,R81.10,,3
"""


# -- CandidatesFile ----------------------------------------------------------------


def test_candidates_roundtrip_preserves_order() -> None:
    cands = CandidatesFile.from_csv(CANDIDATES_CSV)
    assert cands.header[0] == "Object Name"
    assert [r[0] for r in cands.rows] == ["fw-a1", "fw-a2", "fw-01"]
    assert cands.to_csv() == CANDIDATES_CSV


def test_candidates_empty_and_blank_lines() -> None:
    assert CandidatesFile.from_csv("").rows == []
    cands = CandidatesFile.from_csv("a,b\n\n1,2\n\n")
    assert cands.rows == [["1", "2"]]


def test_candidates_cells_with_commas_survive() -> None:
    cands = CandidatesFile(header=["name", "note"], rows=[["fw-01", "a, quoted note"]])
    assert CandidatesFile.from_csv(cands.to_csv()).rows == [["fw-01", "a, quoted note"]]


# -- config XML --------------------------------------------------------------------


def test_build_config_xml_contains_package() -> None:
    xml = build_config_xml("/var/log/upload/jhf.tgz")
    assert "<PackageToInstall>/var/log/upload/jhf.tgz</PackageToInstall>" in xml
    assert "<CPUSE>" not in xml


def test_build_config_xml_optional_elements() -> None:
    xml = build_config_xml(
        "/var/log/upload/jhf.tgz",
        cpuse_rpm_path="/var/log/upload/da.rpm",
        pre_script="/opt/scripts/pre.sh",
        post_script="/opt/scripts/post.sh",
    )
    assert "<CPUSE>/var/log/upload/da.rpm</CPUSE>" in xml
    assert "<PreInstallationScript>/opt/scripts/pre.sh</PreInstallationScript>" in xml
    assert "<PostInstallationScript>/opt/scripts/post.sh</PostInstallationScript>" in xml


def test_build_config_xml_rejects_suspicious_paths() -> None:
    for bad in ("relative/path.tgz", "/tmp/x; rm -rf /", "/tmp/$(reboot)", "/tmp/a b.tgz"):
        with pytest.raises(CDTError, match="suspicious"):
            build_config_xml(bad)


# -- CDT wrapper -------------------------------------------------------------------


def test_read_candidates_parses_remote_file() -> None:
    runner = FakeTransport({"cat /opt/CPcdt/orch_candidates.csv": CANDIDATES_CSV})
    cands = CDT(runner).read_candidates()
    assert len(cands.rows) == 3


def test_read_candidates_missing_file_raises() -> None:
    runner = FakeTransport({"cat /opt/CPcdt/orch_candidates.csv": (1, "")})
    with pytest.raises(CDTError, match="run generate first"):
        CDT(runner).read_candidates()


def test_status_running_and_brief() -> None:
    runner = FakeTransport({"pgrep": (0, ""), "CDT_status_brief": "3 of 5 done"})
    status = CDT(runner).status()
    assert status.running is True
    assert status.brief == "3 of 5 done"
    assert status.looks_failed is False


def test_status_failure_detection() -> None:
    assert CDTStatus(running=False, brief="2 succeeded, 1 Failed").looks_failed
    assert CDTStatus(running=False, brief="Failure on fw-01").looks_failed
    assert not CDTStatus(running=False, brief="all 5 succeeded").looks_failed


def test_generate_invokes_binary_with_candidates_path() -> None:
    runner = FakeTransport()
    CDT(runner).generate()
    assert runner.commands == [
        "/opt/CPcdt/CentralDeploymentTool -generate /opt/CPcdt/orch_candidates.csv"
    ]


def test_preparations_variants() -> None:
    runner = FakeTransport()
    cdt = CDT(runner)
    cdt.preparations()
    cdt.preparations(extended=True)
    assert "-preparations" in runner.commands[0]
    assert "-extended_preparations" in runner.commands[1]


def test_start_execute_uses_nohup_and_refuses_when_running() -> None:
    runner = FakeTransport({"pgrep": (1, ""), "nohup": "started"})
    CDT(runner).start_execute()
    launch = next(c for c in runner.commands if "nohup" in c)
    assert "-execute /opt/CPcdt/orch_candidates.csv" in launch
    assert "&" in launch  # backgrounded: survives SSH drop

    busy = FakeTransport({"pgrep": (0, "")})
    with pytest.raises(CDTError, match="already running"):
        CDT(busy).start_execute()


def test_failed_invoke_raises_with_detail() -> None:
    runner = FakeTransport({"-generate": (1, "no package configured")})
    with pytest.raises(CDTError, match="no package configured"):
        CDT(runner).generate()
