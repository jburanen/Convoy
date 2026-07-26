# Convoy

Orchestration layer for Check Point's **Central Deployment Tool (CDT)** and **CPUSE**. It coordinates deployment of patches and upgrades — hotfixes, Jumbo Hotfix Accumulators, and major-version upgrades — across fleets of Security Management Servers and Security Gateways, through a web interface.  

> This is an internal operations tool for authorized maintenance on infrastructure you own. It *drives* Check Point's own CDT/CPUSE agents; it does not replace them.

## Scope

CPUSE operates one host at a time and lacks fleet-level orchestration. CDT is integrated into SmartConsole for limited use cases including single gateways and ClusterXL, but the more sophisticated operations lack a UI. This tool provides a UI for patching on-premise Smart-1 servers and their managed firewalls.

### Supported
Patching is supported for:  
✅ On-Premise Smart Center (SMS) servers  
✅ On-Premise Multi-Domain Management (MDM/MDSM) servers  
✅ Gaia (Force) firewalls managed by on-prem environments  

### NOT Supported
By design, this tool does NOT support patching:  
❌ Smart-1 Cloud Management *(patched by Check Point)*  
❌ Spark Management Portal *(patched by Check Point)*  
❌ Gaia Standalone (self-managed) deployments  *(uncommon)*  
❌ Firewalls defined as dynamic IP (DAIP)  *(code limitation)*  
❌ Spark firewalls managed by above on-prem environments  *(code limitation)*  

This tool does not CURRENTLY support but may one day support:  
⏳ Maestro  
⏳ ElasticXL  

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

First run seeds environments from `config.yaml` (+ any inventory files) into the
database; after that the database is authoritative and environments are managed in
the UI. On an empty inventory the UI opens on the **Provisioning** tab.

## 🛡️ Safety model

This tool has the capability to alter or negatively impact your management servers and firewalls, therefore there are project guidelines designed to limit your risk. These concepts are applied by both human and AI developers:  

- **Confirmation-gates** — installs (which can reboot) and CDT fleet execute require an explicit operator confirmation. Delete actions require explicit operator confirmation.
- **Cluster-aware ordering** — the CDT candidates order *is* the rollout order; standby-first sequencing and blast-radius control live there.
- **Detected state, not assumed** — the UI reflects live `show installer packages`, uploads are checksum-verified, and free space is checked before import.
- **Auditable** — tool actions and job results are tracked on the Jobs tab.

> Prior to the v1 initial release a policy will be implemented to require code security review by an independent agentic analyst prior to release publication.

## 🎯 Status and Milestones

**Working, pre-production.** The web UI, service core, SSH transport, CPUSE and CDT
wrappers, credential/package stores, environments, and the background job runner are
implemented and unit-tested. Caveats:

- CPUSE/CDT output parsers are built tolerant but **not yet validated against live
  Gaia hardware** — expect to tune them on first real connection.
- The secondary **CLI** does inventory validation and dry-run planning; its
  fleet-`--execute` path and the health-check gating (`checks.py`) are still typed
  stubs.

### Milestones to reach v1 / Initial Release
These gates define the major version releases - the milestones may change in the future but they will remain documented here. A milestone is not marked complete until it is tested and confirmed working by a human. There will not be a packaged release until v1.

✅ LDAP authentication  
✅ Basic auth  
✅ Native TLS support  
✅ Test functionality behind Nginx/NPM  
◻️ Test firewall discovery in SMS/Smart Center environment  
✅ Test firewall discovery in MDS/Multi-Domain environment  
◻️ Test firewall cluster name discovery in SMS  
✅ Test firewall cluster name discovery in MDS  
✅ Test Gaia/Force Gateway patching via CPUSE  
◻️ Packaged deployment release that doesn't require git clone and --build  
◻️ Independent agentic code security review  

### Milestones to reach v2

◻️ CDT deployment to Gaia/Force gateways  

### Roadmap / Punch List
🪲 Bugfix ⏫ Probably a major change 🤞 Non-blocking nice-to-have ✨ Cosmetic only

✨ Add logic to display a warning on mobile devices that the UI of this tool does not scale down well (by design) and you should use it on a larger display.   
✨ Revisit ALL descriptive text and rewrite for clarity and brevity  

#### Provisioning  
⏫ Move definition of primary SMS/MDS to the Mangement Environment modal? This would make it possible to further automate bootstrapping - test SSH access, provision API account automatically, test access  
⏫ After bootstrapping the SSH user, use that user to deploy the admin API account, check/test access settings and offer to correct if needed  
✨ Make it more clear on the provisioning tab that the SSH account from bootstrapping must be added to ALL management servers - maybe have it test access and indicate in the servers table  
✨ Sort management servers table by Role  

#### Packages
🤞 Investigate if we can extract and display meta data like compatible major version from the package file  
✨ Show package upload status  
🪲 In the event of a failed upload to repo job we're not cleaning up the temp package storage  

#### Direct Patching (CPUSE)
⏫ Add deployment agent upgrade option  
🤞 Some kind of sledgehammer to swing to release config/job lock from management server and firewalls if a job gets stranded/stuck  
✨ Improve the display of the check intervals in the job log  
⏫ Offer via text link in info line to use CPRID to provision SSH access to firewalls if status check fails - also management servers?  

#### Jobs
⏫ Add syslog output configuration  
🤞 Add a download button for the install log  
🤞 Allow import jobs to be cancelled during file copy stage - clean up partial file on target  
✨ Affirm in a push_to_repo job output that the temp storage was cleaned up  

#### Squashed Bugs, Polished Edges
v0.48.1 The Connect to Primary API-access repair used a fabricated `set-api-settings accessibility "minimize"` mgmt_cli command - corrected to the real `set api-settings accepted-api-calls-from "All IP addresses that can be used for GUI clients"`, with the `--domain "System Data"` flag it also needs on a standalone SMS  
v0.48.1 The "heads up" API-accessibility warning under Connect to Primary rendered as plain muted text instead of orange - `hint warn` had no matching CSS rule; now uses the same prov-note-warn/-err/-ok convention as the rest of that panel  
v0.48.0 No error checking for lack of API access - Connect to Primary now proactively checks the API's accessibility over SSH right after provisioning it, and offers to repair a require-local restriction; a 403 during discovery also explains the likely cause  
v0.47.3 Multi-select management servers for import - only starts first server, doesn't queue second  
v0.46.0 Provide a way to clean up the temp file storage after a timed out or failed package import job  
v0.46.0 Make timeout and check intervals longer during package import process to account for slower imports  
v0.45.3 Upload package to management repo fails with path formatting error  

> Not affiliated with or endorsed by Check Point Software Technologies. "Check Point", "CDT", and "CPUSE" refer to their products. Use only on infrastructure you are authorized to maintain.  
>  
> Written by Claude under the direction of humans. Deploy, <u>test</u>, and use this tool with appropriate caution. No guarantees or assurance of safety is made by the developers. Even with a whole bunch of robots doing the work, we still manage to introduce human error. 🤖