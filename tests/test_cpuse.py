from __future__ import annotations

import pytest

from chkp_cpuse_orch.cpuse import (
    CPUSE,
    GaiaShell,
    PackageScope,
    PackageState,
    parse_packages,
)
from chkp_cpuse_orch.errors import CPUSEError
from chkp_cpuse_orch.transport.ssh import CommandResult


class FakeRunner:
    """Records commands; replies with a scripted result."""

    def __init__(self, stdout: str = "", exit_status: int = 0, stderr: str = "") -> None:
        self.commands: list[str] = []
        self._stdout = stdout
        self._exit_status = exit_status
        self._stderr = stderr

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        return CommandResult(
            command=command,
            exit_status=self._exit_status,
            stdout=self._stdout,
            stderr=self._stderr,
        )


# -- command construction ---------------------------------------------------------


def test_expert_shell_wraps_with_clish() -> None:
    runner = FakeRunner()
    CPUSE(runner, shell=GaiaShell.EXPERT).import_local("/var/log/upload/jhf.tgz")
    assert runner.commands == [
        "clish -c 'installer import local /var/log/upload/jhf.tgz not-interactive'"
    ]


def test_clish_shell_sends_bare_command() -> None:
    runner = FakeRunner()
    CPUSE(runner, shell=GaiaShell.CLISH).verify("Check_Point_R81.20_JHF_T99")
    assert runner.commands == ["installer verify Check_Point_R81.20_JHF_T99 not-interactive"]


def test_install_and_uninstall_are_not_interactive() -> None:
    runner = FakeRunner()
    cpuse = CPUSE(runner, shell=GaiaShell.CLISH)
    cpuse.install("Pkg-1.0")
    cpuse.uninstall("Pkg-1.0")
    assert runner.commands == [
        "installer install Pkg-1.0 not-interactive",
        "installer uninstall Pkg-1.0 not-interactive",
    ]


def test_list_packages_uses_scope() -> None:
    runner = FakeRunner(stdout="There are no imported packages")
    CPUSE(runner, shell=GaiaShell.CLISH).list_packages(PackageScope.IMPORTED)
    assert runner.commands == ["show installer packages imported"]


def test_failure_raises_cpuse_error_with_detail() -> None:
    runner = FakeRunner(exit_status=1, stderr="CPUSE is busy")
    with pytest.raises(CPUSEError, match="CPUSE is busy"):
        CPUSE(runner, shell=GaiaShell.CLISH).install("Pkg")


def test_import_local_requires_full_safe_path() -> None:
    cpuse = CPUSE(FakeRunner())
    with pytest.raises(CPUSEError, match="FULL remote path"):
        cpuse.import_local("jhf.tgz")
    with pytest.raises(CPUSEError, match="suspicious remote path"):
        cpuse.import_local("/var/log/../../etc/passwd; rm -rf /")


def test_shell_suspicious_package_id_rejected() -> None:
    cpuse = CPUSE(FakeRunner())
    with pytest.raises(CPUSEError, match="suspicious package identifier"):
        cpuse.install("pkg; reboot")


# -- parsing ------------------------------------------------------------------------

TABULAR = """\
Result of the command "show installer packages all"

Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz      Available for Install
Check_Point_R81.20_JHF_T99.tgz                            Imported
Check_Point_R81_10_JHF_T45.tgz                            Installed
"""

BLOCK = """\
Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz
    Info: Jumbo Hotfix Accumulator for R81.20 (Take 89)
    Status: Imported

Check_Point_R81_10_JHF_T45.tgz
    Info: Jumbo Hotfix Accumulator for R81.10 (Take 45)
    Status: Installed
"""


def test_parse_tabular_output() -> None:
    pkgs = parse_packages(TABULAR)
    assert [p.identifier for p in pkgs] == [
        "Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz",
        "Check_Point_R81.20_JHF_T99.tgz",
        "Check_Point_R81_10_JHF_T45.tgz",
    ]
    assert pkgs[0].status == "Available for Install"
    assert pkgs[0].is_imported and not pkgs[0].is_installed
    assert pkgs[2].is_installed


def test_parse_block_output_with_descriptions() -> None:
    pkgs = parse_packages(BLOCK)
    assert len(pkgs) == 2
    assert pkgs[0].status == "Imported"
    assert pkgs[0].description == "Jumbo Hotfix Accumulator for R81.20 (Take 89)"
    assert pkgs[1].is_installed


def test_parse_no_packages_message() -> None:
    assert parse_packages("There are no imported packages\n") == []


def test_parse_garbage_is_skipped_not_fatal() -> None:
    assert parse_packages("some banner\nnoise without status\n\n") == []


def test_package_state_status_helpers() -> None:
    assert PackageState("x", "Installed").is_installed
    assert PackageState("x", "installed (reboot pending)").is_installed
    assert PackageState("x", "Available for Install").is_imported
    assert not PackageState("x", "Available for Download").is_imported
