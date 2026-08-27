Convoy is an orchestration layer for Check Point's **Central Deployment Tool (CDT)** and **CPUSE**. It coordinates deployment of patches and upgrades — hotfixes, Jumbo Hotfix Accumulators, and major-version upgrades — across fleets of Security Management Servers and Security Gateways, through a web interface.  

> This is an internal operations tool for authorized maintenance on infrastructure you own. It *drives* Check Point's own CDT/CPUSE agents; it does not replace them.

## Scope

CPUSE operates one host at a time and lacks fleet-level orchestration. CDT is integrated into SmartConsole for limited use cases including single gateways and ClusterXL, but the more sophisticated operations lack a UI. This tool provides a UI for patching on-premise Smart-1 servers and their managed firewalls.

### Supported
Patching is supported for:  
✅ On-Premise Smart Center (SMS) servers  
✅ On-Premise Multi-Domain Management (MDM/MDSM) servers  
✅ Quantum Force and Spark firewalls managed by on-prem environments  
✅ Quantum Force and Spark firewalls managed by Smart-1 Cloud  
>tested Mgmt versions: R82.10  
>tested Force versions: R82.10  
>tested Spark versions: R81.10.XX, R82.00.XX  

### NOT Supported
By design, this tool does NOT support patching:  
❌ Smart-1 Cloud Management *(patched by Check Point)*  
❌ Spark Management Portal *(patched by Check Point)*  
❌ Gaia Standalone (self-managed) deployments  *(uncommon)*  
❌ Firewalls defined as dynamic IP (DAIP)  *(code limitations)*  

This tool does not CURRENTLY support but may one day support:  
⏳ Maestro  
⏳ ElasticXL  

### Tested Versions

## What it does

Two patching subsystems over one shared core (see
[.claude/memory/patching-web-design.md](.claude/memory/patching-web-design.md)):

- **Direct Individual Patching — CPUSE.** CDT does *not* patch management servers (beginning in R82.10 this gap begins to close), so the tool does it directly: upload a package, `installer import local`, then `installer verify` / `installer install`. Live `show installer package` live status is shown in the job log; install is verified after reboot.  

> **FUTURE**  
> **Bulk Patching — CDT.** Runs CDT *on* a management server: stage the package,
  generate the candidates list, reorder/trim it, add optional pre-flight and post-flight scripts, then execute with live status in the job log.

Supporting features, all in the UI:

- **Bootstrapping.** Generates the clish commands to create the tool's service account on a primary management server, then discovery the remaining management servers and firewalls.
- **Independent environments.** Separate management estates, each with its own inventory and its own credential namespace; package repo is shared.
- **Web UI authentication.** On by default: a local admin/admin login (change the password from the User Settings modal, or disable it with `BASIC_AUTH_DISABLE`), or LDAP/Active Directory when configured (LDAP always takes priority). See `.env.example`.
- **Encrypted credential store.** SSH/API/Expert credential store, encrypted at rest with argon2id; the master key is supplied at startup and never persisted. Storing credentials for *any* environment additionally requires authentication to be configured (basic auth or LDAP) — without it, every environment behaves as storage-disabled, regardless of its own setting.
- **Package store.** Upload CPUSE packages for temporary or permanent storage; upload once, distribute to many.
- **Background jobs.** Every import/install/CDT action runs as a persisted job with a live progress log, cancellation, and restart recovery.

## 🚀 Run it (Docker Compose)

GA releases (beginning v1.0.0) will be a simple docker-compose.yml deployment model plus some environment variables. This project is currently under active early development and for now all deployments need to start with a git clone and the development deployment instructions:  

> ** FOR DEVELOPMENT DEPLOYMENTS**  
> Run `./scripts/deploy.sh`, which sets `DEPLOY_UID`/`DEPLOY_GID` for you (and pulls, rebuilds, and health-checks). `./scripts/deploy.sh --reset` (dev only) wipes `./data` and `.env` first — every environment, server, firewall, credential, package, and job history entry, plus every runtime setting back to its built-in default — then deploys clean. Prompts for confirmation unless you also pass `-y`/`--yes`.

First run seeds environments from `config.yaml` (+ any inventory files) into the database; after that the database is authoritative and environments are managed in the UI. On an empty inventory the UI opens on the **Provisioning** tab.  

## 🛡️ Safety model

This tool has the capability to alter or negatively impact your management servers and firewalls, therefore there are project guidelines designed to limit your risk. These concepts are applied by both human and AI developers:  

- **Confirmation-gates** — installs (which can reboot) and CDT fleet execute require an explicit operator confirmation. Delete actions require explicit operator confirmation.
- **Cluster-aware ordering is operator-supplied, not tool-enforced** — the CDT candidates order *is* the rollout order, and standby-first sequencing is whatever you put in that list. The tool does **not** currently detect that two candidates are members of the same cluster, and does not stagger or health-gate between them. Order the list yourself.
- **Detected state, not assumed** — the UI reflects live `show installer packages`, uploads are checksum-verified, and free space is checked before import.
- **Host-key pinning** — a Gaia host's SSH key is pinned on first connect and stored on the data volume. If it later changes, jobs for that host fail closed before any credential is sent; re-accepting is an explicit operator action. Rebuild or upgrade a box and you will need to re-accept it.
- **No snapshots, no maintenance windows** — the tool does not take rollback snapshots and does not gate runs to an approved window. 
- **Auditable** — tool actions and job results are tracked on the Jobs tab.

> **Authorization model:** every authenticated user has full destructive authority over every environment — there are no roles or per-environment permissions. Under LDAP, that means **every member of `CONVOY_LDAP_REQUIRED_GROUP`** can patch, reboot, bootstrap admin accounts onto gateways, and delete environments. Scope that group accordingly. Per-environment RBAC is a v2 item.

> Prior to the v1 initial release a policy will be implemented to require code security review by an independent agentic analyst prior to release publication.

## 🎯 Status and Milestones

### Milestones to reach v1 / Initial Release
These gates define the major version releases - the milestones may change in the future but they will remain documented here. A milestone is not marked complete until it is tested and confirmed working by a human. There will not be a packaged release until v1.

✅ LDAP authentication  
✅ Basic auth  
✅ Native TLS support  
✅ Test functionality behind Nginx/NPM  
✅ Test firewall discovery in SMS/Smart Center environment  
✅ Test firewall discovery in MDS/Multi-Domain environment  
✅ Test Gaia/Force Gateway patching via CPUSE  
✅ Test Spark (Gaia Embedded) firmware patching via upgrade_revert_image.sh  
✅ Independent agentic code security review  
✅ Re-test of functionality  
◻️ Containerized deployment release that doesn't require git clone and --build  

### Milestones to reach v2

◻️ CDT deployment to Gaia/Force gateways  

### Roadmap / Punch List
🪲 Bugfix ⏫ Required for next release 🤞 Non-blocking nice-to-have ✨ Cosmetic only  

✨ Add logic to display a warning on mobile devices that the UI of this tool does not scale down well (by design) and you should use it on a larger display.   
🤞 RADIUS auth option  
🤞 Timed/scheduled install actions  

#### Packages
🤞 If disk space check fails, parse for large folders, suggest things to clean  

#### Manual Patching (CPUSE)
🤞 Add deployment agent upgrade option  
🤞 Some kind of sledgehammer to swing to release config/job lock from management server and firewalls if a job gets stranded/stuck  
✨ Separate firewalls into two panels? Spark and non-Spark  
🤞 Leverage the gateway family identifier built into Spark filenames to limit choices  

#### Jobs
🤞 Add syslog output  
🤞 Add a download or a copy button for the install log  
🤞 Allow import jobs to be cancelled during file copy stage - clean up partial file on target  
✨ Affirm in a push_to_repo job output that the temp storage was cleaned up  
✨ On jobs with error output, never let the error output spill outside the table boundary - direct the user to view details in the output box or something like that  

Shipped fixes are documented in [CHANGELOG.md](CHANGELOG.md) — an item closed here moves into that file under the version that resolves it.  

> Not affiliated with or endorsed by Check Point Software Technologies. "Check Point", "CDT", and "CPUSE" refer to their products. Use only on infrastructure you are authorized to maintain.  
>  
> Written by Claude under the direction of humans. Deploy, <u>test</u>, and use this tool with appropriate caution. No guarantees or assurance of safety is made by the developers. Even with a whole bunch of robots doing the work, we still manage to introduce human error. 🤖  
