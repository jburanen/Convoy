---
name: safety-constraints
description: Operational safety rules for deploying to live firewalls — non-negotiable
metadata:
  type: project
---

This tool changes **production firewalls**. A bad rollout can drop traffic for an
entire site. These constraints are requirements, not suggestions.

**Why:** Check Point firewalls often sit inline on critical paths; clusters fail over
but only if members are patched in the right order and health is confirmed between
steps. Management servers gate policy for the whole estate.

**How to apply:**
- **Dry-run first.** Every mutating verb defaults to a plan/preview; real execution
  requires an explicit `--execute` (or equivalent) flag.
- **Cluster-aware ordering.** Never patch all members of a ClusterXL/HA pair at once.
  Patch standby → confirm healthy failover → patch former active. Confirm cluster
  state before and after each member. (see [[cdt-cpuse-domain]])
- **Health gating.** A step only proceeds if `checks.py` pre-checks pass; a batch
  only advances if post-checks pass. Fail closed — stop the run, don't continue.
- **Maintenance windows.** Deploys are gated to an approved window; abort cleanly if
  the window closes mid-run.
- **Batching / blast radius.** Firewalls roll out in bounded batches, never the whole
  fleet in one shot. Configurable concurrency with a conservative default.
- **Rollback path.** Prefer snapshots / known-good restore points; record enough to
  roll back. Management servers: snapshot before CPUSE install.
- **Auditability.** Every action, target, and outcome is logged (structlog) to a run
  report. Deployments must be reconstructable after the fact.
- **Least privilege & authorization.** Assume the operator is running authorized
  maintenance on their own estate. Do not add capabilities for scanning or acting on
  infrastructure the operator doesn't own.
