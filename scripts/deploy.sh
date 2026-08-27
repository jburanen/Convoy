#!/usr/bin/env bash
# Deploy on the test host: pull latest, rebuild, restart, and health-check.
# Run this ON the host from inside the checkout:  ./scripts/deploy.sh
# (Claude invokes it over SSH so no manual git pull is needed.)
#
# --reset (dev only): wipe the app's own state before deploying — ./data's
# config.yaml, the DB (environments, servers, firewalls, credentials,
# sessions, jobs/job history) and uploaded packages. ./data/certs and .env are
# deliberately KEPT: a TLS private key and the master key/LDAP settings are
# host infrastructure rather than application data, and a redeploy that
# silently destroyed them would leave the app reachable only over plain HTTP
# with no way for the deploying account to put the certificate back.
# --reset-all (dev only): the above PLUS ./data/certs and .env — a genuine
# back-to-built-in-defaults wipe (no TLS, no LDAP, basic auth admin/admin).
# Both are irreversible and prompt for confirmation unless -y/--yes is given.
set -euo pipefail

# Refuse to run as root. DEPLOY_UID below is taken from `id -u` and becomes the
# container's `user:` in docker-compose.yml, so `sudo ./scripts/deploy.sh` would
# silently run the whole service as uid 0 — overriding the Dockerfile's
# `USER 1001:1001` and handing any future RCE in the app a root container
# instead of an unprivileged one. Nothing here needs root: the deploying account
# only needs to be in the `docker` group and able to write the checkout.
if [ "$(id -u)" -eq 0 ]; then
  echo "refusing to deploy as root: the container would inherit uid 0." >&2
  echo "Re-run as an unprivileged user that is in the 'docker' group." >&2
  exit 1
fi

cd "$(dirname "$0")/.."

RESET=0
RESET_ALL=0
CONFIRMED=0
for arg in "$@"; do
  case "$arg" in
    --reset|-reset) RESET=1 ;;
    --reset-all|-reset-all) RESET=1; RESET_ALL=1 ;;
    -y|--yes) CONFIRMED=1 ;;
    *)
      echo "usage: $0 [--reset | --reset-all] [-y|--yes]" >&2
      exit 1
      ;;
  esac
done

if [ "$RESET" = "1" ]; then
  if [ "$RESET_ALL" = "1" ]; then
    echo "!! --reset-all: this PERMANENTLY deletes ./data IN FULL (config, database"
    echo "!! — every environment/server/firewall/credential/job/session — uploaded"
    echo "!! packages, AND ./data/certs, i.e. any TLS certificate and private key"
    echo "!! kept there) plus .env (master key, LDAP, TLS paths — every runtime"
    echo "!! setting, back to built-in defaults). Dev use only."
  else
    echo "!! --reset: this PERMANENTLY deletes the application's state in ./data —"
    echo "!! config.yaml, the database (every environment/server/firewall/credential/"
    echo "!! job/session) and uploaded packages. ./data/certs and .env are KEPT, so"
    echo "!! TLS, the master key and LDAP settings survive — use --reset-all to wipe"
    echo "!! those too. Dev use only."
  fi
  if [ "$CONFIRMED" != "1" ]; then
    read -r -p "Type RESET to confirm: " reply
    if [ "$reply" != "RESET" ]; then
      echo "Aborted — nothing was deleted." >&2
      exit 1
    fi
  fi

  # Pre-flight, BEFORE the stack is stopped. A directory under ./data this
  # account cannot write is one whose contents it cannot delete, and under
  # `set -e` that aborts the wipe half-done: stack down, data partly gone,
  # nothing redeployed. Only --reset-all can hit this, since --reset never
  # descends into the one directory (certs) that is typically owned by
  # someone else.
  if [ "$RESET_ALL" = "1" ] && [ -d ./data ]; then
    blocked="$(find ./data -mindepth 1 -type d ! -writable -print 2>/dev/null || true)"
    if [ -n "$blocked" ]; then
      echo "!! cannot delete these directories as $(id -un):" >&2
      echo "$blocked" >&2
      echo "!! re-run as their owner, or use --reset (which keeps ./data/certs)." >&2
      exit 1
    fi
  fi

  echo ">> stopping the stack (so nothing has ./data open while it's wiped)"
  docker compose down || true

  if [ "$RESET_ALL" = "1" ]; then
    echo ">> wiping ./data in full (certs included) and .env"
    rm -rf ./data
    rm -f ./.env
  else
    echo ">> wiping ./data except certs (.env kept)"
    # Delete ./data's CONTENTS rather than ./data itself, so `certs` survives
    # untouched — including when this account cannot write inside it.
    if [ -d ./data ]; then
      find ./data -mindepth 1 -maxdepth 1 ! -name certs -exec rm -rf {} +
    fi
  fi

  echo ">> restoring default config.yaml"
  mkdir -p data
  cp examples/config.example.yaml data/config.yaml
fi

echo ">> git pull"
git pull --ff-only

echo ">> ensure data dir"
mkdir -p data

# The container runs as this uid:gid (docker-compose.yml's `user:`) so the
# bind-mounted ./data above — just created owned by whoever is running this
# script — is always writable by the container too, on any host, without a
# manual chown.
export DEPLOY_UID DEPLOY_GID
DEPLOY_UID="$(id -u)"
DEPLOY_GID="$(id -g)"

echo ">> build + (re)start"
docker compose up -d --build

echo ">> wait for health"
for i in $(seq 1 30); do
  status="$(docker inspect --format '{{ .State.Health.Status }}' convoy 2>/dev/null || echo starting)"
  if [ "$status" = "healthy" ]; then
    echo ">> healthy"
    # Native TLS (CONVOY_SSL_CERTFILE/KEYFILE, see .env) makes the app
    # https-only — try plain http first, fall back to an unverified https
    # probe (loopback, not a trust decision) so this doesn't print a spurious
    # failure on a TLS-enabled host.
    if curl -fsS http://localhost:8080/health 2>/dev/null; then
      echo
    else
      curl -fsSk https://localhost:8080/health && echo
    fi
    exit 0
  fi
  sleep 2
done

echo "!! container did not become healthy in time" >&2
docker compose logs --tail=50 web >&2 || true
exit 1
