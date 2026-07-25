---
name: project-rename-convoy
description: Project will be renamed from chkp-cpuse-orch to Convoy before GA release
metadata:
  type: project
---

The project name is changing from `chkp-cpuse-orch` to **Convoy** ahead of the
first GA release. Decided 2026-07-25.

**Why:** `chkp-cpuse-orch` is a generic internal-tool slug. Convoy evokes a
fleet moving together in staged, health-gated order — a direct fit for how
this tool sequences patches/upgrades across management servers and gateways
(see [safety-constraints.md](safety-constraints.md)).

**How to apply:**
- The user will rename the GitHub repo manually, sometime before GA — not
  something to do proactively or without being asked.
- The PyPI name `convoy` is already taken (unrelated, apparently abandoned
  JS/CSS combo-loader package) — if/when this ships to PyPI, the distribution
  name will need a variant, e.g. `convoy-cdt` or similar.
- Don't start renaming the package (`src/chkp_cpuse_orch/`), pyproject
  `name`, CLI entrypoint, or README title until the user asks — this is a
  planned future change, not yet in effect.
