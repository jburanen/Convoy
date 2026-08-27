"""Pre/post health checks that gate every deployment step.

The orchestrator calls these to decide whether a step may proceed (pre) and whether
a batch succeeded (post). Checks **fail closed**: an inconclusive result is a failure.
See .claude/memory/safety-constraints.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .transport.ssh import CommandRunner


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is CheckStatus.PASS


class HealthChecks:
    """Health probes for a single Gaia host, run over a ``CommandRunner``."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def cluster_state(self) -> CheckResult:
        """Confirm ClusterXL/HA state (`cphaprob state`) before/after patching a member."""
        # TODO: parse `cphaprob state`; require a healthy, expected role.
        raise NotImplementedError("cluster_state check not yet implemented")

    def free_disk(self, min_gb: int = 5) -> CheckResult:
        # TODO: parse `df -h` for the relevant partitions.
        raise NotImplementedError("free_disk check not yet implemented")

    def version(self) -> CheckResult:
        # TODO: capture current version/take for pre/post comparison.
        raise NotImplementedError("version check not yet implemented")

    def run_all(self) -> list[CheckResult]:
        """Run the standard pre-check battery. Order chosen cheapest-first."""
        # Wired once the individual checks are implemented.
        raise NotImplementedError("run_all not yet implemented")
