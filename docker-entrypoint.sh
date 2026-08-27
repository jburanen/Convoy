#!/bin/sh
# Container entrypoint: make the data volume usable, then hand off to the app.
#
# Config.load() treats a missing config file as fatal, and a published image is
# started by people who have no checkout to copy an example from — so the image
# carries its own and seeds the volume on first run. This used to live in
# scripts/deploy.sh, which only ever helped a deployment made from a git clone.
#
# Only ever creates what is absent: an existing config.yaml is operator-edited
# state and is never touched, which is what makes this safe on every start.
set -e

CONFIG="${CONVOY_CONFIG:-/data/config.yaml}"

if [ ! -f "$CONFIG" ]; then
  # A volume the container cannot write is the other first-run failure, and
  # left alone it surfaces as an unexplained health-check timeout rather than
  # as its actual cause. Say it plainly instead.
  if ! mkdir -p "$(dirname "$CONFIG")" 2>/dev/null ||
     ! cp /app/examples/config.example.yaml "$CONFIG" 2>/dev/null; then
    echo "convoy: cannot write $CONFIG (running as uid $(id -u))." >&2
    echo "convoy: the data volume must be writable by this user — with a bind" >&2
    echo "convoy: mount, set DEPLOY_UID/DEPLOY_GID to your own account first." >&2
    exit 1
  fi
  echo "convoy: seeded $CONFIG from the packaged example (first run)"
fi

exec "$@"
