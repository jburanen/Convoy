from __future__ import annotations

import pytest

from convoy.config import Config
from convoy.errors import SafetyViolation
from convoy.inventory import Inventory
from convoy.orchestrator import Orchestrator, StepKind


def test_plan_starts_with_management_and_is_dry_by_default(
    inventory: Inventory, config: Config
) -> None:
    orch = Orchestrator(inventory, config)
    plan = orch.build_plan("Check_Point_R81.20_JHF_T99.tgz")
    assert plan.dry_run is True
    # Management is patched (and post-checked) before any gateway deploy.
    kinds = [s.kind for s in plan.steps]
    assert kinds[0] is StepKind.PRECHECK
    assert StepKind.PATCH_MANAGEMENT in kinds
    first_mgmt = kinds.index(StepKind.PATCH_MANAGEMENT)
    first_deploy = kinds.index(StepKind.DEPLOY_GATEWAYS)
    assert first_mgmt < first_deploy


def test_gateway_batches_respect_blast_radius(inventory: Inventory) -> None:
    cfg = Config()
    cfg.defaults.max_concurrent_gateways = 1
    orch = Orchestrator(inventory, cfg)
    plan = orch.build_plan("pkg")
    deploy_steps = [s for s in plan.steps if s.kind is StepKind.DEPLOY_GATEWAYS]
    assert all(len(s.targets) <= 1 for s in deploy_steps)


def test_cluster_safety_guard_blocks_two_members_together(
    inventory: Inventory, config: Config
) -> None:
    orch = Orchestrator(inventory, config)
    # Both members of cluster-a in one batch must be rejected.
    with pytest.raises(SafetyViolation):
        orch.assert_cluster_safe(["fw-a1", "fw-a2"])
    # A single member is fine.
    orch.assert_cluster_safe(["fw-a1"])


def test_execute_dry_run_skips_mutations(inventory: Inventory, config: Config) -> None:
    orch = Orchestrator(inventory, config)
    plan = orch.build_plan("pkg")  # dry_run=True
    # Should not raise NotImplementedError: mutating steps are skipped, and the
    # check steps are not executed in dry-run either.
    orch.execute(plan)
