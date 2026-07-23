"""chkp-cpuse-orch — orchestration layer for Check Point CDT / CPUSE deployments.

See .claude/memory/ for project context. Public surface is intentionally small;
most work goes through the CLI (`chkp_cpuse_orch.cli`) or the orchestrator.
"""

# Single source of truth for the version (pyproject reads it dynamically).
# Bump with every user-visible change: minor for features, patch for fixes.
__version__ = "0.27.2"
