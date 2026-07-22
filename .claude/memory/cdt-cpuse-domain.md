---
name: cdt-cpuse-domain
description: How Check Point CDT and CPUSE work — the tools this project orchestrates
metadata:
  type: reference
---

The two Check Point mechanisms this tool drives. (SK numbers below are the known
reference articles; verify against the customer's version before relying on exact
CLI syntax — Check Point changes these across releases.)

**CPUSE — Check Point Upgrade Service Engine** (aka the Deployment Agent / DA)
- Runs on a *single* Gaia machine (mgmt server or gateway). Source of truth for
  local install state.
- Lifecycle per package: `import` → `verify` → `install` → (optional reboot) →
  `uninstall`. Packages: hotfixes, Jumbo Hotfix Accumulators (JHF/HFA), and major
  version upgrades.
- CLI via Gaia clish `installer` verbs (confirmed via docs MCP; there is **no
  documented `da_cli`/expert-mode equivalent** — clish `installer` IS the
  automation surface). Also a Gaia Portal web UI. Reference: sk92449.
  - `installer import local <FULL PATH> not-interactive` — package may sit in any
    dir (`/var/log/upload/` is conventional); full path required.
  - `installer verify <ID> not-interactive` / `installer install <ID> not-interactive`
  - `show installer packages all|imported|installed`; `show installer status build`
  - `not-interactive` suppresses prompts — essential for automation.
  - On MDPS-enabled boxes, `set mdps environment mplane` first.
  - **`lock database override` before the two read/refresh commands above**
    (operator-confirmed, 2026-07-22) — Gaia's config-database lock (e.g. held by
    another admin session) can otherwise block them from running correctly.
    `CPUSE._override_lock()` sends it before every `list_packages()`/
    `agent_build()` call; best-effort (a failure here doesn't abort the refresh —
    the read command itself surfaces a clear error if genuinely still blocked).
  - **A package's identifier in `show installer packages imported` is NOT
    reliably its uploaded filename** (operator-confirmed, 2026-07-22). Some
    package types (JHFs) are rendered as a human-readable string instead, e.g.
    "R82.10 Jumbo Hotfix Accumulator Take 24" or "...Take 19" — no relation to
    the uploaded "Check_Point_R82_10_..._Bundle_T24_FULL.tgz". The reliable
    cross-reference is `hf.config`, a small file buried a few tar/tgz layers
    inside the package archive (`PATCH_NAME`, `TAKE_NUMBER`, `BRANCH_NAME`,
    `PACKAGE_TYPE`, `CATEGORY`, `DIRECT_BASE_VERSION` — see `hfconfig.py`).
    `PatchingService._wait_until_imported` matches a candidate by *either* its
    filename/stem *or* its own version+Take (via `cpuse.extract_version`/
    `extract_take`, same regexes the UI summary line uses) equaling hf.config's
    `DIRECT_BASE_VERSION`/`TAKE_NUMBER` — either is sufficient, since which
    naming convention CPUSE picks isn't reliably predictable from hf.config
    alone.
- **Management servers are patched with CPUSE locally**, not via CDT.

**CDT — Central Deployment Tool** (reference: sk111158; confirmed via docs MCP)
- Runs *on a Security Management Server or Multi-Domain Server (MDS)*. Pushes packages
  and scripts to *many* managed Security Gateways / cluster members at once, using
  CPUSE on each target under the hood. NOT used to upgrade the management server itself.
- Beyond install/uninstall it can: take snapshots, run shell scripts, push/pull files,
  automate RMA backup/restore, and handle **cluster upgrades automatically** (standby
  members first, then automatic failover; incl. Connectivity Upgrades).
- Requires **Expert mode, admin / uid 0**. Run long jobs under **`nohup`** so an SSH
  drop doesn't kill the deployment.
- The binary is **`$CDTDIR/CentralDeploymentTool`** (not a bare `cdt`). Config is XML;
  the target list is a **CSV of candidates**.

**CDT command workflow** (Security Mgmt Server; for MDS prefix with `mdsenv <DMS>` and
pass `<DMS>` as a trailing arg):
1. **Configure** `$CDTDIR/CentralDeploymentTool.xml`:
   - `<PackageToInstall>` → absolute path to the CPUSE **offline** package
   - `<CPUSE>` → path to the CPUSE RPM (upgrades the agent on targets)
   - optional `<PreInstallationScript>` / `<PostInstallationScript>`
2. **Generate** candidates CSV: `$CDTDIR/CentralDeploymentTool -generate <cands>.csv`
3. **Edit** the CSV — this is where **upgrade ORDER** is set and unwanted targets
   removed. CSV order == cluster-aware sequencing == blast-radius control.
4. *(optional)* **Preparations** to front-load slow work before the window:
   - `-preparations <cands>.csv` (ship packages, run pre-scripts)
   - `-extended_preparations <cands>.csv` (also update CPUSE + import packages)
5. **Execute**: `$CDTDIR/CentralDeploymentTool -execute <cands>.csv`
   - Per target CDT: validates state → prepares Access Control policy (upgrades) →
     updates CPUSE → push/import/install → validates policy install → pre/post scripts
     → cluster failover.
- **Gotcha:** after upgrades you may still need to **manually install** Threat
  Prevention, QoS, and Desktop policies (depends on CDT version).

**Advanced mode — Deployment Plan file** (richer than a flat CSV; confirmed via docs MCP):
- Two complementary files:
  - **Deployment Plan (XML)** = *WHAT* to do — packages, actions, scripts. Lives in
    `/opt/CPcdt/DeploymentPlanRepository/`. (This is the structured form of what the
    simple mode put inline in `CentralDeploymentTool.xml`.)
  - **Candidates List (CSV)** = *WHERE* — target gateways/cluster members. Lives in
    `/opt/CPcdt/CandidateListsRepository/`. Columns: Object Name, Cluster Name, IP,
    Version/JHF Take, State (active/standby), **Upgrade Order**.
- Relationship: the Deployment Plan is *input* to generating the Candidates list — CDT
  filters candidates by the **first package** in the plan; you then edit the CSV to pick
  targets/order. Both files are passed together to execute.
- Advanced commands use **named flags** (vs. the positional simple mode):
  ```bash
  $CDTDIR/CentralDeploymentTool -generate  -candidates=<c>.csv -deploymentplan=<p>.xml [-server=<DMS IP>] [-session=<name>]
  $CDTDIR/CentralDeploymentTool -execute   -candidates=<c>.csv -deploymentplan=<p>.xml [-server=<DMS IP>] [-session=<name>]
  ```
  Gaia clish equivalents: `start cdt generate-candidates deployment-plan "<p>.xml" candidates-list "<c>.csv" [server <DMS>] [session <name>]`
  and `start cdt execute deployment-plan "<p>.xml" candidates-list "<c>.csv" [server <DMS>] [session <name>]`.
- **Filter file** (optional): plain text, one gateway name per line, narrows targets:
  `-filter=<FilterFile.txt>` on generate/execute.
- **Monitoring**: `watch -d cat $CDTDIR/CDT_status.txt` (full log) and
  `$CDTDIR/CDT_status_brief.txt` (brief). These are the artifacts our reporting layer
  should tail/parse rather than reinventing.

**How our tool maps onto CDT** (keep wrappers thin — see [[architecture]]):
- our `plan` / dry-run ≈ `-generate` + inspecting/ordering the CSV (no live changes)
- our preparation phase ≈ `-preparations` / `-extended_preparations`
- our `deploy --execute` ≈ `-execute`
- cluster-aware ordering + health gating live in `orchestrator.py`/`checks.py`, realized
  as the **CSV order** we hand CDT. (see [[safety-constraints]])

**Typical end-to-end upgrade this tool orchestrates**
1. Pre-checks: HA state, cluster member roles, connectivity, free disk, current
   versions. (see [[safety-constraints]])
2. Patch the **management server** via CPUSE (local, one host, often HA pair).
3. Stage package + configure CDT XML on the management server.
4. Generate + order the candidates CSV; optionally run preparations.
5. Deploy to **gateways** in batches via CDT `-execute`, respecting cluster failover order.
6. Post-checks: version confirmed, policy installed (incl. manual TP/QoS/Desktop if
   needed), cluster healthy, logs clean.

**How we reach the boxes:** SSH to Gaia (clish/expert) is the baseline transport;
Gaia REST API and the Check Point Management API (`mgmt_cli`) are used where
available. See [[tech-stack]] and [[architecture]].
