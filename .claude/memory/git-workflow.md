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
