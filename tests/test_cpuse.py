from __future__ import annotations

import pytest

from chkp_cpuse_orch.cpuse import (
    CPUSE,
    GaiaShell,
    PackageScope,
    PackageState,
    extract_take,
    parse_package_detail,
    parse_packages,
    summarize_jumbo,
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
        "clish -c 'lock database override'",
        "clish -c 'installer import local /var/log/upload/jhf.tgz not-interactive'",
    ]


def test_clish_shell_sends_bare_command() -> None:
    runner = FakeRunner()
    CPUSE(runner, shell=GaiaShell.CLISH).verify("Check_Point_R81.20_JHF_T99")
    assert runner.commands == [
        "lock database override",
        "installer verify Check_Point_R81.20_JHF_T99 not-interactive",
    ]


def test_install_and_uninstall_are_not_interactive() -> None:
    runner = FakeRunner()
    cpuse = CPUSE(runner, shell=GaiaShell.CLISH)
    cpuse.install("Pkg-1.0")
    cpuse.uninstall("Pkg-1.0")
    assert runner.commands == [
        "lock database override",
        "installer install Pkg-1.0 not-interactive",
        "lock database override",
        "installer uninstall Pkg-1.0 not-interactive",
    ]


def test_import_cloud_uses_bare_id_not_local() -> None:
    runner = FakeRunner()
    CPUSE(runner, shell=GaiaShell.CLISH).import_cloud("Check_Point_R81.20_JHF_T99")
    assert runner.commands == [
        "lock database override",
        "installer import Check_Point_R81.20_JHF_T99 not-interactive",
    ]


def test_import_cloud_rejects_suspicious_id() -> None:
    with pytest.raises(CPUSEError, match="suspicious package identifier"):
        CPUSE(FakeRunner(), shell=GaiaShell.CLISH).import_cloud("id; rm -rf /")


def test_cluster_state_parses_local_role() -> None:
    stdout = (
        "ID         Unique Address  Assigned Load   State          Name\n"
        "1 (local)  11.22.33.245    100%            ACTIVE(!)      Member1\n"
        "2          11.22.33.246    0%              DOWN           Member2\n"
    )
    runner = FakeRunner(stdout=stdout)
    state = CPUSE(runner, shell=GaiaShell.CLISH).cluster_state()
    assert runner.commands == ["lock database override", "show cluster state"]
    assert state is not None
    assert state.is_active
    assert state.cluster_name == "Member1, Member2"


def test_cluster_state_none_when_command_fails() -> None:
    runner = FakeRunner(exit_status=1, stderr="not a cluster member")
    assert CPUSE(runner, shell=GaiaShell.CLISH).cluster_state() is None


def test_list_packages_uses_scope() -> None:
    runner = FakeRunner(stdout="There are no imported packages")
    CPUSE(runner, shell=GaiaShell.CLISH).list_packages(PackageScope.IMPORTED)
    # A read-only query first overrides Gaia's config-database lock (in case
    # another admin session is holding it) so it isn't blocked behind it.
    assert runner.commands == ["lock database override", "show installer packages imported"]


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


# "Display name / Type" shape (operator-confirmed, 2026-07-22): real
# `show installer packages imported` output on some Gaia versions has no
# per-row status at all, plus a noisy banner unrelated to the actual list.
NAME_TYPE_IMPORTED = """\
**  ************************************************************************* **
**              Connection error. Packages list might be incomplete           **
**  ************************************************************************* **
**  ************************************************************************* **
**                                 Hotfixes                                   **
**  ************************************************************************* **
Display name                                                                     Type
Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz                           Hotfix
R82.10 Jumbo Hotfix Accumulator Take 19                                          Hotfix
R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 24                        Hotfix
Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz                             Hotfix
"""


def test_parse_name_type_shape_for_imported_scope() -> None:
    pkgs = parse_packages(NAME_TYPE_IMPORTED, PackageScope.IMPORTED)
    assert [p.identifier for p in pkgs] == [
        "Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz",
        "R82.10 Jumbo Hotfix Accumulator Take 19",
        "R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 24",
        "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz",
    ]
    # The scope itself implies the status — there's no per-row status text.
    assert all(p.status == "Imported" and p.is_imported for p in pkgs)


def test_parse_name_type_shape_ignored_without_a_scope() -> None:
    # Without a scope that implies a status (the default, PackageScope.ALL),
    # this shape can't be told apart from "installed" vs "imported" — left
    # alone rather than guessed at.
    assert parse_packages(NAME_TYPE_IMPORTED) == []


def test_parse_no_packages_message() -> None:
    assert parse_packages("There are no imported packages\n") == []


def test_parse_garbage_is_skipped_not_fatal() -> None:
    assert parse_packages("some banner\nnoise without status\n\n") == []


def test_package_state_status_helpers() -> None:
    assert PackageState("x", "Installed").is_installed
    assert PackageState("x", "installed (reboot pending)").is_installed
    assert PackageState("x", "Available for Install").is_imported
    assert not PackageState("x", "Available for Download").is_imported


# `show installer package <id>` — operator-confirmed real device output,
# 2026-07-22, from a case where `installer install` reported success but the
# package never actually left "Imported".
PACKAGE_DETAIL = """\
CLINFR0771  Config lock is owned by admin. Use 'lock database override' to acquire the lock.
Display name:     Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz
File name:        Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz
Description:      No Description
Size:             2.169 GB
Type:             Hotfix
Status:           Imported
Requires reboot:  true
Recommended:      false
Contains:         Check_Point_R82_10_jumbo_hf_main_Bundle_T19_FULL.tgz
                  Check_Point_R82_10_jumbo_hf_main_Bundle_T24_FULL.tgz
Contained-in:     None
Downloaded on:    N/A
Imported on:      Wed Jul 22 15:11:09 2026
Installed on:     N/A
Installation log: N/A
"""


def test_parse_package_detail_reads_status_ignoring_the_lock_banner() -> None:
    name = "Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz"
    detail = parse_package_detail(PACKAGE_DETAIL, name)
    assert detail.status == "Imported"
    assert detail.description == "No Description"
    assert detail.is_imported and not detail.is_installed


def test_parse_package_detail_recognizes_installed() -> None:
    detail = parse_package_detail("Status:           Installed\n", "x")
    assert detail.is_installed


def test_parse_package_detail_in_progress_percentage_is_not_installed() -> None:
    # Exact in-progress wording isn't confirmed, but whatever it is, it must
    # not be mistaken for "Installed" while a percentage is still climbing.
    detail = parse_package_detail("Status:           Installing 45%\n", "x")
    assert not detail.is_installed
    assert detail.status == "Installing 45%"


def test_summarize_jumbo_picks_highest_installed_take() -> None:
    # Take 19 is superseded by (installed as part of) the Take 24 bundle —
    # the highest installed Take is the one actually running.
    packages = [
        PackageState("Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz", "Imported"),
        PackageState("R82.10 Jumbo Hotfix Accumulator Take 19", "Installed as part of"),
        PackageState("R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 24", "Installed"),
        PackageState("Some Weird Package", "Not Applicable"),
    ]
    summary = summarize_jumbo(packages)
    assert summary.version == "R82.10"
    assert summary.jhf == "Take 24"


def test_extract_take_handles_underscore_terminated_filename() -> None:
    # "..._Bundle_T36_FULL.tgz" — the Take number is followed by '_', not '.'
    # or true end of string. Both digit and '_' are regex word characters, so
    # `\b` right after the digits silently never matched this real, common
    # naming convention (operator-confirmed, 2026-07-22).
    assert extract_take("Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz") == 36


# Real `show installer packages all` output (operator-confirmed, 2026-07-22)
# right after installing Take 36 over a previously-installed Take 24 — a
# Refresh kept showing "Take 24" because of the extract_take bug above: the
# newly-installed package's own filename couldn't be read for a Take number,
# so summarize_jumbo silently fell back to the OTHER installed JHF entry it
# could parse one out of — the stale, superseded Take 24.
REAL_ALL_SCOPE_AFTER_JHF_INSTALL = """\
**  ***************************************************** **
**       Connection error. Packages list might be incomplete   **
**  ***************************************************** **
**  ***************************************************** **
**                       Hotfixes                              **
**  ***************************************************** **
Display name                                                Status
Check_Point_R82_10_ga_time_fix_main_Bundle_T9_FULL.tgz      Installed
R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 24   Installed as part of
Check_Point_R82_10_jumbo_hf_main_Bundle_T36_FULL.tgz        Installed
"""


def test_summarize_jumbo_reads_new_take_from_real_all_scope_output() -> None:
    packages = parse_packages(REAL_ALL_SCOPE_AFTER_JHF_INSTALL, PackageScope.ALL)
    summary = summarize_jumbo(packages)
    assert summary.version == "R82.10"
    assert summary.jhf == "Take 36"


def test_summarize_jumbo_handles_tarball_filename_convention() -> None:
    packages = [
        PackageState(
            "Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz",
            "Available for Install",
            "Jumbo Hotfix Accumulator for R81.20 (Take 89)",
        ),
        PackageState("Check_Point_R81.20_JHF_T99.tgz", "Imported"),
        PackageState("Check_Point_R81_10_JHF_T45.tgz", "Installed"),
    ]
    summary = summarize_jumbo(packages)
    assert summary.version == "R81.10"
    assert summary.jhf == "Take 45"


def test_summarize_jumbo_falls_back_to_any_installed_version_without_a_jhf() -> None:
    summary = summarize_jumbo([PackageState("Check_Point_R82_10_ga_main.tgz", "Installed")])
    assert summary.version == "R82.10"
    assert summary.jhf is None


def test_summarize_jumbo_empty_without_packages() -> None:
    assert summarize_jumbo([]) == summarize_jumbo([PackageState("x", "Not Applicable")])
