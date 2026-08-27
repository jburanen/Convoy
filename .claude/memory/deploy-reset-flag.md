---
name: deploy-reset-flag
description: scripts/deploy.sh --reset wipes app state but keeps .env + data/certs; --reset-all wipes those too
metadata:
  type: project
---

`scripts/deploy.sh` has two dev-only wipe flags. Both are irreversible and
prompt (type `RESET`) unless `-y`/`--yes` is also passed. `docker compose down`
runs first so nothing has the SQLite file open mid-wipe.

## `--reset` — application state only (the common one)
Deletes the *contents* of `./data` **except `data/certs`**: `config.yaml`, the
whole DB (environments, servers, firewalls, credential sets, sessions, job
history) and uploaded package files. Then restores
`examples/config.example.yaml` to `data/config.yaml` and continues the normal
pull/build/up/health-check flow.

**`.env` and `data/certs` are deliberately KEPT** — so the master key, LDAP
config, any `BASIC_AUTH_*` override and the TLS certificate/private key all
survive a reset. Rewritten to this shape 2026-08-27 (operator-directed); it
previously deleted both.

**Why:** on the dev host the wildcard TLS cert and its private key live in
`data/certs`, and `.env` points `CONVOY_SSL_CERTFILE`/`KEYFILE` at them. Those
are host infrastructure, not application data. Wiping them dropped the app back
to plain HTTP with no way for the deploying account to put the cert back — see
the ownership note below.

## `--reset-all` — genuine back-to-defaults
`--reset` plus `rm -rf ./data` (certs included) and `rm -f .env`, landing on
built-in defaults: basic auth admin/admin, no LDAP, no TLS, credential store
unconfigured. Added 2026-08-27 alongside the `--reset` change.

## Gotcha: certs are usually owned by someone else
On inbev01, `data/certs` is `jason:deploy drwxr-sr-x` while the deploy runs as
`devuser` — group has r-x, **not** w, so devuser cannot delete anything inside
it. A blind `rm -rf ./data` therefore fails, and under `set -e` it aborted the
wipe *after* `docker compose down`: stack down, data half-gone, nothing
redeployed. `--reset-all` now pre-flights with `find ./data -type d ! -writable`
and exits **before** stopping the stack, naming the offending directories.
`--reset` sidesteps it entirely by deleting `./data`'s entries with
`find -maxdepth 1 ! -name certs` instead of the directory itself.

Config.load() requires `/data/config.yaml` to exist when `CONVOY_CONFIG` is
set (which docker-compose.yml always does) — both flags must recreate it
(copied from the example), never just delete-and-leave-gone, or the container
won't boot.
