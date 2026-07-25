---
name: deploy-reset-flag
description: scripts/deploy.sh --reset does a full dev-only wipe (./data + .env) before redeploying
metadata:
  type: project
---

`scripts/deploy.sh --reset` (added 2026-07-25), dev use only. Deletes `./data`
(git-ignored — `config.yaml`, and the whole DB: environments, servers, firewalls,
credential sets, sessions, job history; plus uploaded package files) and `.env`
(git-ignored — master key, LDAP config, any `BASIC_AUTH_*` override, everything),
then restores `examples/config.example.yaml` to `data/config.yaml` before
continuing the normal pull/build/up/health-check flow. `docker compose down` runs
first so nothing has the SQLite file open mid-wipe.

**Why both `./data` and `.env`:** the DB alone doesn't reset a changed basic-auth
password ([[web-auth]] persists that override in the `meta` table, which lives in
`./data`) or the master key/LDAP settings (those are `.env`, not DB) — a "full
reset" needs both to actually land back on built-in defaults (basic auth
admin/admin, no LDAP, credential store unconfigured).

**Safety:** irreversible, so it prompts (type `RESET`) unless `-y`/`--yes` is also
passed — same pattern as this assistant's own confirm-before-destroying-work
default, just baked into the script instead of asked interactively each time.

Config.load() requires `/data/config.yaml` to exist when `CHKP_CPUSE_CONFIG` is
set (which docker-compose.yml always does) — `--reset` must recreate it
(copied from the example), never just delete-and-leave-gone, or the container
won't boot.
