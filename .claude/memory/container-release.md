---
name: container-release
description: Releases are GHCR images published by a vX.Y.Z tag; docker-compose.yml pulls, docker-compose.dev.yml builds; deploy.sh re-execs itself after git pull
metadata:
  type: project
---

From v1.0.0-rc.1 a release is a **container image**, not a checkout.

**Two compose files, deliberately.**

* `docker-compose.yml` — what end users run. Pulls
  `ghcr.io/jburanen/convoy:${CONVOY_TAG:-latest}` into the **named volume**
  `convoy-data`. Named, not a bind mount, because `/data` in the image is owned
  by uid 1001 and Docker initializes a fresh named volume with the image's
  ownership — a bind-mounted host directory arrives owned by whoever ran
  compose and the container gets `Permission denied`. That is the whole reason
  the dev host needs `DEPLOY_UID`/`DEPLOY_GID`.
* `docker-compose.dev.yml` — build from source, bind-mount `./data`. What
  `scripts/deploy.sh` drives, passing `-f` on **every** compose call.

**Publishing.** `.github/workflows/release.yml` fires on any `v*` tag: pytest +
ruff + mypy, then build and push `:<version>` and `:latest` to GHCR. The GitHub
Release is created by hand *after* the published image is confirmed to deploy —
operator's rule, and a good one.

**Config seeding lives in the image** (`docker-entrypoint.sh`), not in
`deploy.sh` any more: a published-image deployment has no checkout to copy
`examples/config.example.yaml` from. `Config.load()` still treats a missing
config as fatal. Supersedes the seeding step described in [[deploy-reset-flag]].

**`scripts/deploy.sh` re-execs itself when `git pull` changes it.** bash reads a
script incrementally, so a pull rewrites the file mid-execution and the shell
carries on at a byte offset into the *new* text — running a splice of both
versions. Hit for real on the v1.0.0-rc.1 deploy: the still-running old copy
called plain `docker compose`, which resolved the *new* image-based
`docker-compose.yml` and tried to pull a tag that did not exist yet. Nothing
was harmed (the pull failed before anything was recreated) and a second run
took, but the deploy was a silent no-op. The guard re-execs **without** the
original arguments — any `--reset` already ran before the pull, and repeating
it would prompt again or wipe twice.

Any change to `deploy.sh` therefore lands one deploy later than the rest of the
commit, on hosts that already have the old copy running.
