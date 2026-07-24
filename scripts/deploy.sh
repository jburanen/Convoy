#!/usr/bin/env bash
# Deploy on the test host: pull latest, rebuild, restart, and health-check.
# Run this ON the host from inside the checkout:  ./scripts/deploy.sh
# (Claude invokes it over SSH so no manual git pull is needed.)
set -euo pipefail

cd "$(dirname "$0")/.."

echo ">> git pull"
git pull --ff-only

echo ">> ensure data dir"
mkdir -p data

echo ">> build + (re)start"
docker compose up -d --build

echo ">> wait for health"
for i in $(seq 1 30); do
  status="$(docker inspect --format '{{ .State.Health.Status }}' chkp-cpuse-orch 2>/dev/null || echo starting)"
  if [ "$status" = "healthy" ]; then
    echo ">> healthy"
    # Native TLS (CHKP_CPUSE_SSL_CERTFILE/KEYFILE, see .env) makes the app
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
