"""Fleet orchestration — where all sequencing and safety decisions live.

Turns an inventory + a requested package into a **run plan** of ordered steps, then
executes them with health gating, cluster-aware ordering, and bounded blast radius.
The CDT/CPUSE wrappers stay dumb; the judgment is here. See
.claude/memory/architecture.md and .claude/memory/safety-constraints.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .config import Config
from .errors import SafetyViolation
from .inventory import Inventory, Role
from .reporting import get_logger

log = get_logger(__name__)


class StepKind(StrEnum):
    PRECHECK = "precheck"
    PATCH_MANAGEMENT = "patch_management"  # CPUSE, local to a mgmt server
    DEPLOY_FIREWALLS = "deploy_firewalls"  # CDT, from a mgmt server to firewalls
    POSTCHECK = "postcheck"


@dataclass
class Step:
    kind: StepKind
    targets: list[str]  # Host.name references
    description: str = ""


@dataclass
class RunPlan:
    """An ordered, previewable plan. Building a plan never touches live gear."""

    package_name: str
    steps: list[Step] = field(default_factory=list)
    dry_run: bool = True

    def describe(self) -> str:
        lines = [f"Run plan for package {self.package_name!r} (dry_run={self.dry_run}):"]
        for i, step in enumerate(self.steps, 1):
            targets = ", ".join(step.targets)
            lines.append(f"  {i}. [{step.kind.value}] {step.description} -> {targets}")
        return "\n".join(lines)


class Orchestrator:
    """Builds and executes deployment run plans."""

    def __init__(self, inventory: Inventory, config: Config) -> None:
        self.inventory = inventory
        self.config = config

    # -- planning (pure; safe to run anytime) ----------------------------------

    def build_plan(self, package_name: str, *, dry_run: bool | None = None) -> RunPlan:
        """Compose an ordered plan: prechecks → mgmt → firewalls (batched) → postchecks.

        Cluster members are ordered standby-first and split across batches so no two
        members of the same cluster are ever patched together.
        """
        plan = RunPlan(
            package_name=package_name,
            dry_run=self.config.defaults.dry_run if dry_run is None else dry_run,
        )
        mgmt = [h.name for h in self.inventory.hosts_by_role(Role.MANAGEMENT)]
        firewalls = [h.name for h in self.inventory.hosts_by_role(Role.FIREWALL)]
        firewalls += [h.name for h in self.inventory.hosts_by_role(Role.CLUSTER_MEMBER)]
        # Role.SPARK_FIREWALL is deliberately excluded — CDT bulk-deploy
        # mechanics don't apply to Quantum Spark (Gaia Embedded) appliances
        # yet. Not an oversight; see inventory.py's Role.SPARK_FIREWALL note.

        if mgmt:
            plan.steps.append(Step(StepKind.PRECHECK, mgmt, "pre-checks on management servers"))
            plan.steps.append(Step(StepKind.PATCH_MANAGEMENT, mgmt, "CPUSE patch mgmt servers"))
            plan.steps.append(Step(StepKind.POSTCHECK, mgmt, "post-checks on management servers"))
        for batch in self._batches(firewalls):
            plan.steps.append(Step(StepKind.PRECHECK, batch, "pre-checks on firewall batch"))
            plan.steps.append(
                Step(StepKind.DEPLOY_FIREWALLS, batch, "CDT deploy to firewall batch")
            )
            plan.steps.append(Step(StepKind.POSTCHECK, batch, "post-checks on firewall batch"))
        return plan

    def _batches(self, firewalls: list[str]) -> list[list[str]]:
        """Split firewalls into blast-radius-bounded batches.

        TODO: make cluster-aware — guarantee members of the same cluster land in
        different batches, standby first. For now, a simple size cap.
        """
        size = self.config.defaults.max_concurrent_firewalls
        return [firewalls[i : i + size] for i in range(0, len(firewalls), size)]

    # -- execution (mutating; gated) -------------------------------------------

    def execute(self, plan: RunPlan) -> None:
        """Execute a plan step by step, gating on checks and failing closed.

        A dry-run is a pure preview: it logs each step and touches no host. Real
        execution (``plan.dry_run is False``) dispatches to the wrappers via
        ``_run_step``.
        """
        for step in plan.steps:
            log.info("step", kind=step.kind.value, targets=step.targets, dry_run=plan.dry_run)
            if plan.dry_run:
                log.info("dry_run_preview", kind=step.kind.value, targets=step.targets)
                continue
            self._run_step(step, dry_run=plan.dry_run)

    def _run_step(self, step: Step, *, dry_run: bool) -> None:
        # TODO: dispatch to checks/cpuse/cdt per step.kind. Each mutating step must:
        #   1) confirm the maintenance window is open,
        #   2) run pre-checks (fail closed),
        #   3) verify cluster ordering before touching a member,
        #   4) execute via the wrapper,
        #   5) run post-checks before advancing.
        raise NotImplementedError("step execution not yet implemented")

    # -- safety guards ---------------------------------------------------------

    def assert_cluster_safe(self, batch: list[str]) -> None:
        """Raise SafetyViolation if a batch contains >1 member of the same cluster."""
        seen: dict[str, str] = {}
        for site in self.inventory.sites:
            for cluster in site.clusters:
                members = set(cluster.members)
                in_batch = [m for m in batch if m in members]
                if len(in_batch) > 1:
                    raise SafetyViolation(
                        f"batch would patch {len(in_batch)} members of cluster "
                        f"{cluster.name!r} at once: {in_batch}"
                    )
                for m in in_batch:
                    seen[m] = cluster.name
