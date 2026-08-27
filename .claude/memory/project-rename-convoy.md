---
name: project-rename-convoy
description: Rename to Convoy is complete — repo, folder, package, CLI, image and env prefix; two literals deliberately keep the old spelling
metadata:
  type: project
---

The project was renamed from `chkp-cpuse-orch` to **Convoy**. Decided 2026-07-25,
completed 2026-08-26.

**Why:** `chkp-cpuse-orch` was a generic internal-tool slug. Convoy evokes a fleet
moving together in staged, health-gated order — a direct fit for how this tool
sequences patches/upgrades across management servers and gateways (see
[safety-constraints.md](safety-constraints.md)).

## What changed
- **GitHub repo** → `jburanen/Convoy`. GitHub serves permanent redirects from the
  old path, so a clone still pointing at the old URL keeps fetching — including the
  dev host's checkout at `/home/jason/docker-cpuse` ([[test-host-deploy]]).
- **Local clone** → `C:\Users\jburanen\Github\Convoy`. The `.venv` needed rebuilding
  (the editable-install `.pth` and every `Scripts\*.exe` shim bake in the absolute
  path), and Claude Code's per-project history had to be copied to the new
  path-derived key under `~/.claude/projects/`.
- **Python package** `src/chkp_cpuse_orch/` → `src/convoy/`; pyproject `name` and the
  CLI entrypoint are both `convoy`.
- **Docker** image `convoy:dev`, container `convoy`. The container name and
  `scripts/deploy.sh`'s health-check `docker inspect` target must always move
  together — they are matched by string, and a mismatch makes a deploy hang waiting
  on a container that never reports healthy.
- **Env prefix** `CHKP_CPUSE_*` → `CONVOY_*`, via `src/convoy/envcompat.py`.

## Two things that deliberately keep the old spelling
Both are **persisted or operator-owned values, not labels** — renaming them breaks
running installs, which is why they are called out here rather than left to be
"cleaned up" later:

1. `_CANARY_PLAINTEXT` in `credentials.py` is still
   `b"chkp-cpuse-orch credential canary v1"`. Its ciphertext sits in the DB's
   `credential_canary` meta row and is compared on every open. Renaming it makes an
   existing install fail `_check_canary` and report the operator's master key as
   wrong — i.e. it presents as credential loss.
2. The `CHKP_CPUSE_*` env names still resolve. A deployment's `.env` is
   operator-managed and outside this repo, so a hard cutover would break it on the
   next `git pull` — and `CHKP_CPUSE_MASTER_KEY` is what derives the credential-store
   key. `compat_env()` maps old → new, warns once per variable, and lets an explicit
   `CONVOY_*` win. Covered by `tests/test_envcompat.py`.

`SESSION_COOKIE_NAME` also changed, which invalidates existing browser sessions —
harmless (one re-login), but it is why everyone gets logged out on the upgrade.

The README changelog keeps the historical `CHKP_CPUSE_SHOW_TAB_HINTS` spelling in
the v0.65.0 entry on purpose: release notes record what shipped at the time.

**PyPI note:** `convoy` is already taken there (unrelated, apparently abandoned
JS/CSS combo-loader). If this ever ships to PyPI the *distribution* name needs a
variant such as `convoy-cdt`; the import package can stay `convoy`.
