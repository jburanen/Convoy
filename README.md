# chkp-cpuse-orch

Orchestration layer for Check Point's **Central Deployment Tool (CDT)** and **CPUSE**.
It coordinates deployment of patches and upgrades — hotfixes,
Jumbo Hotfix Accumulators, and major-version upgrades — across fleets of Security
Management Servers and Security Gateways, through a web interface.

> This is an internal operations tool for authorized maintenance on
> infrastructure you own. It *drives* Check Point's own CDT/CPUSE agents; it does not
> replace them.

## Why

CDT and CPUSE are powerful but operate one plan / one host at a time and lack
fleet-level orchestration. Staged rollouts, per-site batching,
cluster-aware deployment, health checks, maintenance-window gating, and an auditable
record are part of a responsible patching regime. This tool strives to be that orchestration layer, with a web UI for day-to-day work.

## What it does

Two patching subsystems over one shared core (see
[.claude/memory/patching-web-design.md](.claude/memory/patching-web-design.md)):

- **Direct Individual Patching — CPUSE.** CDT does *not* patch management servers (beginning in R82.10 this gap begins to close), so
  the tool does it directly: upload a package, `installer import local`, then
  `installer verify` / `installer install`. Live `show installer packages` state is
  shown per server; install is confirmed after reboot.
- **Bulk Patching — CDT.** Runs CDT *on* a management server: stage the package,
  generate the candidates list, reorder/trim it (row order = deployment order = blast
  radius), optional preparations, then execute under `nohup` with live status
  polled into the job log.

Supporting features, all in the UI:

- **Bootstrapping.** Generates the clish commands to create the tool's service account on a primary management server, then discovery the remaining management servers and firewalls.
- **Independent environments.** Separate management estates, each with its own
  inventory and its own credential namespace; package repo is shared.
- **Encrypted credential store.** SSH/API/Expert credential store,
  encrypted at rest with argon2id; the master key is supplied at startup and never persisted.
- **Package store.** Upload CPUSE packages for temporary or permanent storage; upload once, distribute to many.
- **Background jobs.** Every import/install/CDT action runs as a persisted job with a
  live progress log, cancellation, and restart recovery.

## Status

**Working, pre-production.** The web UI, service core, SSH transport, CPUSE and CDT
wrappers, credential/package stores, environments, and the background job runner are
implemented and unit-tested. Caveats:

- CPUSE/CDT output parsers are built tolerant but **not yet validated against live
  Gaia hardware** — expect to tune them on first real connection.
- The web app has **no authentication yet** — run it only on a trusted network
  (basic-auth + LDAP are planned).
- The secondary **CLI** does inventory validation and dry-run planning; its
  fleet-`--execute` path and the health-check gating (`checks.py`) are still typed
  stubs.

## Run it (Docker)

The intended deployment. `docker compose` builds the image and serves the UI on
`:8080`, with state on a bind-mounted `./data` volume.

```bash
# On the host, in the deploy directory:
mkdir -p data
cp examples/config.example.yaml data/config.yaml   # adjust /data paths inside

# Master key for the credential store — supply via env or a git-ignored .env.
# Held in memory only; the app boots "locked" (credentials disabled) without it.
export CHKP_CPUSE_MASTER_KEY='choose-a-strong-passphrase'

docker compose up -d --build
# → http://<host>:8080  (GET /health for a probe)
```

First run seeds environments from `config.yaml` (+ any inventory files) into the
database; after that the database is authoritative and environments are managed in
the UI. On an empty inventory the UI opens on the **Provisioning** tab.

## Develop / run locally

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows; use bin/activate on *nix
pip install -e ".[dev,web]"

# Web UI (reload for development):
export CHKP_CPUSE_MASTER_KEY='dev-passphrase'
uvicorn chkp_cpuse_orch.web.app:app --reload --port 8080

# Secondary CLI (validation + dry-run planning):
chkp-cpuse-orch validate -i inventory.yaml -c config.yaml
chkp-cpuse-orch plan "Check_Point_R81.20_JHF_T99.tgz" -i inventory.yaml

pytest
ruff check . && ruff format .
mypy src
```

## Safety model

This tool has the capability to alter or negatively impact management servers and firewalls, therefore:

- **Confirmation-gated mutations** — installs (which can reboot) and CDT fleet
  execute require an explicit operator confirmation.
- **Cluster-aware ordering** — the CDT candidates order *is* the rollout order;
  standby-first sequencing and blast-radius control live there.
- **Detected state, not assumed** — the UI reflects live `show installer packages`,
  and uploads are checksum/size-verified before import.
- **Auditable** — admin actions and job results are tracked on the Jobs tab.
- **No deletes** - the tool deliberately does not offer the ability to remove packages 
  from the CPUSE repository or the SmartConsole central repository and cannot delete credentials from firewalls or management servers. This stance may be revisited in future versions.

Cluster/health pre-gating (`checks.py`) is the next safety layer to wire in. See
[.claude/memory/safety-constraints.md](.claude/memory/safety-constraints.md).

## Security & public-repo hygiene

This repo is **public**. Only `*.example.*` templates with placeholder values are
tracked. Real inventories, CDT plans, keys, `.env`, the `data/` volume, logs, and run
reports are git-ignored (and `.claudeignore`d). Credentials are encrypted at rest and
never echoed by the API. See
[.claude/memory/security-hygiene.md](.claude/memory/security-hygiene.md). **Never
commit real infrastructure detail or secrets.**

## Layout

```
src/chkp_cpuse_orch/
  web/            FastAPI app + static, hand-editable UI (web/static/)
  services/       service core: patching (CPUSE), cdt_ops (CDT), environments,
                  provisioning, common (host connector + environment registry)
  transport/      SSH (Paramiko) + Gaia/Management API clients
  cpuse.py cdt.py thin wrappers over the installer / CentralDeploymentTool
  store.py        SQLite: jobs, credential ciphertext, packages, environments
  credentials.py packages.py jobs.py  encrypted store / package store / job runner
  orchestrator.py checks.py  fleet planning + health gating (CLI path; partial)
  cli.py config.py inventory.py reporting.py errors.py
examples/         *.example.yaml templates (tracked)
tests/            pytest suite (service logic via fakes; no live gear)
Dockerfile docker-compose.yml scripts/deploy.sh
.claude/memory/   project memory for Claude Code (start at MEMORY.md)
CLAUDE.md         project instructions
```

## To-do List

- CPUSE: should multiple CPUSE jobs (with different tarets) be permitted to run concurrently?
- CPUSE: Add concept of direct patching for gateways as well with a separate panel from mgmt servers
- CPUSE: Gateways to direct patch should be added by admin on the CPUSE tab with a similar UI to adding mgmt servers on the provisioning tab. Management servers should be inherited from Prov tab
- CPUSE: Add ability to edit existing direct patching targets
- CPUSE: Add deployment agent upgrade option
- CPUSE: check available disk space before copying file
- CPUSE: indicate on each server if a job is currently running by replacing the check box with an icon, block new jobs until complete
- CPUSE: add muted explanatory text at top of firewalls panel to talk about how direct patching is mostly for management servers and small numbers of gateways. gateways can also be patched from SmartConsole and Web SmartConsole (generate a link). Large numbers of gateways can be patched with the CDT tab (future).
- Packages: can I extract and display meta data like compatible major version from the package file?
- Packages: treat uploads/deletions as a job and log them on the jobs tab with pkgs prefix
- Packages: if I uncheck the keep box, reset the retention timer to the configured duration beginning when I uncheck the box
- Provisioning: treat credential management actions as jobs and track with prov prefix
- Provisioning: treat server discovery and connection actions as jobs and track with prov prefix
- Jobs: fix column width resizing
- Jobs: add syslog output
- Packages: only display SHA1 hash, sha256 is not needed
- Packages: add ability to upload a stored package to the smartconsole packages repo using mgmt api

## Disclaimer

Not affiliated with or endorsed by Check Point Software Technologies. "Check Point",
"CDT", and "CPUSE" refer to their products. Use only on infrastructure you are
authorized to maintain. 

Written by Claude under the direction of humans. Deploy, **test**, and use this tool with appropriate caution. No guarantees or assurance of safety is made by the developers.
