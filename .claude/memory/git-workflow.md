---
name: git-workflow
description: Operator's git workflow preference — commit directly to main, no feature branches
metadata:
  type: feedback
---

Work directly on **`main`** in this repo. The operator does not want per-feature
branches — commit and push to `main`.

**Why:** solo/small-team internal tool; the operator deploys from `main` (the dev
host checkout tracks `main`, see [[test-host-deploy]]) and prefers a single line of
history over branch/PR overhead. Stated 2026-07-20 after merging `feat/ldap-auth`
(the first and last feature branch) back to `main`.

**How to apply:**
- Default to committing on `main`; do **not** auto-create a branch first (this
  overrides the usual "branch before committing on the default branch" habit).
- Still only commit/push when the operator asks.
- Deploying still means merging/pushing to `main` then running the deploy over SSH
  ([[test-host-deploy]]) — the host pulls `main`.

## Explicit-ask means THIS batch, not "earlier in the session"
Stated 2026-07-23 after committing+pushing a UI-only batch (firewalls-table column
changes) without a fresh ask — the operator had said "commit push deploy" for the
*previous* batch that same session, and I carried that as standing permission into
the next one. Wrong: each batch needs its own explicit go-ahead. Doing finished work
and then asking "commit push deploy?" is correct; inferring it from a prior request
in the same conversation is not — even a few turns later, even in the same session.
**How to apply:** finish the requested change, verify it, then stop and report —
don't run `git commit`/`git push` until the operator's *current* message actually
asks for it. Deploys are already separately gated as "only when asked"
([[test-host-deploy]]); this tightens the commit/push half to match — one
explicit ask, one batch, no carry-over.

## Bump the version every batch
Keep `__version__` in `src/chkp_cpuse_orch/__init__.py` (the single source of truth —
`pyproject` reads it dynamically) moving forward as we go. **Include the bump in the
same commit as the changes it ships** — do not leave it as a follow-up commit. The
version is user-visible (login + main footer, `/health`, `/api/status`). Patch bump
for fixes/UI tweaks, minor for feature batches; the commit subject convention is
`vX.Y.Z: <summary>`. Stated 2026-07-21 after a batch shipped without a bump.
**Why:** the running/deployed version must identify exactly what's live.
