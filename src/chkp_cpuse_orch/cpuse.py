"""CPUSE wrapper — drives the Deployment Agent on a *single* Gaia host.

Thin by design: it builds clish ``installer`` commands, runs them over a
``CommandRunner``, and parses results. It makes NO sequencing or safety decisions —
those belong to the orchestrator. See .claude/memory/cdt-cpuse-domain.md.

Used primarily to patch **management servers** locally (management servers are not
targeted by CDT). Per the official docs there is no expert-mode ``da_cli``
equivalent — clish ``installer`` with ``not-interactive`` IS the automation
surface. Flow per host: upload package (transport) → ``installer import local
<full path>`` → ``installer verify <ID>`` → ``installer install <ID>``.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import StrEnum

from .errors import CPUSEError
from .transport.ssh import CommandResult, CommandRunner

# Conventional staging directory for uploaded packages (any dir works; the docs
# use /var/log/upload in their examples).
DEFAULT_STAGING_DIR = "/var/log/upload"


class GaiaShell(StrEnum):
    """What the SSH login shell is, which decides how clish commands are sent."""

    EXPERT = "expert"  # login shell is bash → wrap as: clish -c "<cmd>"
    CLISH = "clish"  # login shell is clish → send the command bare


class PackageScope(StrEnum):
    """Scopes accepted by `show installer packages <scope>`."""

    ALL = "all"
    IMPORTED = "imported"
    INSTALLED = "installed"


@dataclass(frozen=True)
class PackageState:
    """Parsed state of one CPUSE package on the host."""

    identifier: str
    status: str  # raw status text, e.g. "Installed", "Imported", "Available for Install"
    description: str = ""

    @property
    def is_installed(self) -> bool:
        return self.status.strip().lower().startswith("installed")

    @property
    def is_imported(self) -> bool:
        s = self.status.strip().lower()
        return s.startswith("imported") or s.startswith("available for install")


@dataclass(frozen=True)
class JumboSummary:
    """Best-effort major version + currently-installed Jumbo Hotfix Accumulator,
    derived from detected package state for the UI's compact summary line."""

    version: str | None
    jhf: str | None  # e.g. "Take 24"


# Identifiers/descriptions come in at least two conventions (see the fixtures in
# tests/test_cpuse.py): human-readable ("Jumbo Hotfix Accumulator for R81.20
# (Take 89)") and tarball-filename ("Check_Point_R81_20_JHF_T99" /
# "..._JUMBO_HF_MAIN_Bundle_T89_FULL"). Both are handled here.
_JUMBO_RE = re.compile(r"jumbo|jhf", re.IGNORECASE)
_TAKE_RE = re.compile(r"take\s*(\d+)", re.IGNORECASE)
_TAKE_FILENAME_RE = re.compile(r"_t(\d+)\b", re.IGNORECASE)
_VERSION_RE = re.compile(r"R(\d{2})[._](\d{2})", re.IGNORECASE)


def _pkg_text(pkg: PackageState) -> str:
    return f"{pkg.identifier} {pkg.description}"


def _extract_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return f"R{m.group(1)}.{m.group(2)}" if m else None


def _extract_take(text: str) -> int | None:
    m = _TAKE_RE.search(text) or _TAKE_FILENAME_RE.search(text)
    return int(m.group(1)) if m else None


def summarize_jumbo(packages: list[PackageState]) -> JumboSummary:
    """Among *installed* jumbo/JHF packages, the highest Take number wins — a
    JHF lists earlier Takes it superseded as "installed as part of", so the
    highest Take is the one actually running."""
    best_take = -1
    version: str | None = None
    for pkg in packages:
        if not pkg.is_installed:
            continue
        text = _pkg_text(pkg)
        if not _JUMBO_RE.search(text):
            continue
        take = _extract_take(text)
        if take is not None and take > best_take:
            best_take = take
            version = _extract_version(text) or version
    if version is None:
        # No installed JHF found — fall back to any installed package's version token.
        for pkg in packages:
            if pkg.is_installed:
                version = _extract_version(_pkg_text(pkg))
                if version:
                    break
    return JumboSummary(version=version, jhf=f"Take {best_take}" if best_take >= 0 else None)


class CPUSE:
    """CPUSE / Deployment Agent operations for one Gaia host."""

    def __init__(
        self,
        runner: CommandRunner,
        *,
        shell: GaiaShell = GaiaShell.EXPERT,
        timeout: float | None = 3600.0,  # installs legitimately take a long time
    ) -> None:
        self._runner = runner
        self._shell = shell
        self._timeout = timeout

    # -- read-only -------------------------------------------------------------

    def list_packages(self, scope: PackageScope = PackageScope.ALL) -> list[PackageState]:
        """`show installer packages <scope>` → parsed package states.

        This is the source of truth the UI reflects — always *detected* state,
        never our last action's assumed outcome.
        """
        result = self._clish(f"show installer packages {scope.value}")
        if not result.ok:
            raise CPUSEError(f"failed to list packages: {_failure_detail(result)}")
        return parse_packages(result.stdout)

    def agent_build(self) -> str:
        """`show installer status build` → Deployment Agent build string."""
        result = self._clish("show installer status build")
        if not result.ok:
            raise CPUSEError(f"failed to read DA build: {_failure_detail(result)}")
        return result.stdout.strip()

    # -- lifecycle (mutating; caller must gate on safety checks) ---------------

    def import_local(self, remote_path: str) -> None:
        """Import a package file already uploaded to the host (full path)."""
        if not remote_path.startswith("/"):
            raise CPUSEError(f"import local needs a FULL remote path, got {remote_path!r}")
        if not re.fullmatch(r"/[A-Za-z0-9/._-]+", remote_path) or "/../" in remote_path:
            raise CPUSEError(f"suspicious remote path: {remote_path!r}")
        self._run_installer(f"import local {remote_path}", "import")

    def verify(self, package_id: str) -> None:
        self._run_installer(f"verify {_check_id(package_id)}", "verify")

    def install(self, package_id: str) -> None:
        """Install an imported package. May reboot the host — the caller must have
        gated this on HA-peer health first. See safety-constraints."""
        self._run_installer(f"install {_check_id(package_id)}", "install")

    def uninstall(self, package_id: str) -> None:
        self._run_installer(f"uninstall {_check_id(package_id)}", "uninstall")

    def _run_installer(self, verb: str, action: str) -> None:
        # not-interactive suppresses prompts — required for automation.
        result = self._clish(f"installer {verb} not-interactive")
        if not result.ok:
            raise CPUSEError(f"CPUSE {action} failed: {_failure_detail(result)}")

    # -- command plumbing --------------------------------------------------------

    def _clish(self, command: str) -> CommandResult:
        wire = f"clish -c {shlex.quote(command)}" if self._shell is GaiaShell.EXPERT else command
        return self._runner.run(wire, timeout=self._timeout)


# -- parsing --------------------------------------------------------------------

# Status phrases CPUSE uses; matched case-insensitively at end of a line.
_STATUS_PHRASES = (
    "available for install",
    "available for download",
    "installed",
    "imported",
    "downloading",
    "importing",
    "verifying",
    "installing",
    "failed",
)
_STATUS_LINE_RE = re.compile(
    rf"^(?P<name>\S.*?)\s{{2,}}(?P<status>(?:{'|'.join(_STATUS_PHRASES)})\b.*)$",
    re.IGNORECASE,
)
_NO_PACKAGES_RE = re.compile(r"there are no .* packages", re.IGNORECASE)


def parse_packages(stdout: str) -> list[PackageState]:
    """Parse `show installer packages` output.

    Output formats drift across Gaia versions, so this is deliberately tolerant
    and handles the two shapes seen in the field (fixtures in tests/):

    1. Tabular: ``<package-name>   <status text>`` (two+ spaces as separator)
    2. Block:   package-name line followed by indented ``Info:``/``Status:`` lines

    Unrecognized lines are skipped, never fatal — the UI shows raw statuses and
    the orchestrator matches them case-insensitively.
    """
    packages: list[PackageState] = []
    current_name: str | None = None
    current_info = ""

    def flush(status: str) -> None:
        nonlocal current_name, current_info
        if current_name is not None:
            packages.append(
                PackageState(identifier=current_name, status=status, description=current_info)
            )
        current_name, current_info = None, ""

    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line.strip() or _NO_PACKAGES_RE.search(line):
            continue

        if line[0].isspace():  # indented → block-form detail line
            detail = line.strip()
            lowered = detail.lower()
            if lowered.startswith("status:"):
                flush(detail.split(":", 1)[1].strip())
            elif lowered.startswith("info:"):
                current_info = detail.split(":", 1)[1].strip()
            continue

        # Non-indented: either a one-line tabular entry or a block-form name line.
        m = _STATUS_LINE_RE.match(line)
        if m:
            flush("")  # a dangling block name without Status: is dropped
            packages.append(
                PackageState(identifier=m.group("name").strip(), status=m.group("status").strip())
            )
        elif _looks_like_package_name(line):
            flush("")
            current_name = line.strip()

    flush("")
    return packages


def _looks_like_package_name(line: str) -> bool:
    token = line.strip()
    return " " not in token and (token.endswith(".tgz") or token.startswith("Check_Point"))


def _check_id(package_id: str) -> str:
    """Package IDs feed a clish command line — reject anything shell-suspicious."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", package_id):
        raise CPUSEError(f"suspicious package identifier: {package_id!r}")
    return package_id


def _failure_detail(result: CommandResult) -> str:
    detail = result.stderr.strip() or result.stdout.strip()
    return f"rc={result.exit_status}: {detail}"
