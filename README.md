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
✅ Quantum Spark (Gaia Embedded) firewalls managed by on-prem environments — firmware transfer + upgrade via `upgrade_revert_image.sh`, not CPUSE (Spark doesn't run it) and not CDT (Spark isn't a CDT target); Refresh reads version via `fw ver` instead of CPUSE's `show installer status`, since Spark has no CPUSE agent to query  

### NOT Supported
By design, this tool does NOT support patching:  
❌ Smart-1 Cloud Management *(patched by Check Point)*  
❌ Spark Management Portal *(patched by Check Point)*  
❌ Gaia Standalone (self-managed) deployments  *(uncommon)*  
❌ Firewalls defined as dynamic IP (DAIP)  *(code limitation)*  

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
◻️ Test Spark (Gaia Embedded) firmware patching via upgrade_revert_image.sh  
◻️ Packaged deployment release that doesn't require git clone and --build  
◻️ Independent agentic code security review  

### Milestones to reach v2

◻️ CDT deployment to Gaia/Force gateways  

### Roadmap / Punch List
🪲 Bugfix ⏫ Probably a major change 🤞 Non-blocking nice-to-have ✨ Cosmetic only

✨ Add logic to display a warning on mobile devices that the UI of this tool does not scale down well (by design) and you should use it on a larger display.   
✨ Revisit ALL descriptive text and rewrite for clarity and brevity  
🤞 Built-in help docs with ? button on each page/panel with long-form descriptive text  
🤞 RADIUS auth option

#### Provisioning  
⏫ Harden service account practices: move away from /bin/bash for Gaia

#### Packages
🤞 Add a percentage progress display for package upload  

#### Manual Patching (CPUSE)
⏫ Add deployment agent upgrade option  
🤞 Some kind of sledgehammer to swing to release config/job lock from management server and firewalls if a job gets stranded/stuck  
🤞 After removing bash shell for gaia gateway, add detection of shell upon login so you know if you need to use clish -c wrapper  

#### Jobs
⏫ Add syslog output    
🤞 Add a download or a copy button for the install log  
🤞 Allow import jobs to be cancelled during file copy stage - clean up partial file on target  
✨ Affirm in a push_to_repo job output that the temp storage was cleaned up  
✨ On jobs with error output, never let the error output spill outside the table boundary - direct the user to view details in the output box or something like that  
✨ Show current percentage when available in the output column so I don't have to expand the full job progress to see it

#### Squashed Bugs
v0.58.0 The Firewalls panel's "Upload and import to selected" button, for a Spark (Gaia Embedded) `.img` package, also ran the upgrade - a single `spark.scp` job did the whole sequence (SCP the image to `/storage`, then immediately `upgrade_revert_image.sh ... upgrade safe`, rebooting the device) with no way to just stage the file. Split into two independent jobs: `spark.scp` now only transfers and stores the image (no confirmation needed, doesn't reboot anything), and a new `spark.install` job runs the actual upgrade, wired to the same row-level Install button/picker CPUSE-patched firewalls already use (`POST .../install` now dispatches on host role). A transferred image shows up in that picker via the same `installable` cache CPUSE populates from live device state, since Spark has no equivalent query - this tool's own record of what it staged instead; fixed a latent bug found along the way where Refresh silently wiped that list on every check  
v0.57.1 Spark (Gaia Embedded) firmware transfer failed with `TransportError: SFTP upload to <host>:<path> failed: Channel closed` - the transfer reused `Transport.put()` (Paramiko's SFTP subsystem, same call used by the Gaia CPUSE import path) on the unvalidated assumption Spark's SSH server exposed it once `bashUser on` was run, but real hardware confirmed it doesn't - `bashUser on`'s own banner only ever advertised "SCP access enabled", never SFTP. The transfer now goes over a new `SSHClient.put_scp()` (classic SCP protocol, spoken directly over `exec_command("scp -t ...")`); the Gaia CPUSE path is untouched and still uses SFTP  
v0.57.0 Firewalls panel Refresh on Spark (Gaia Embedded) rows ran CPUSE's `show installer status`/packages/cluster-state against a host that has no CPUSE agent to query, and either failed outright or showed a meaningless summary line - `detect()` now branches on host role: Spark runs a plain `fw ver` and truncates the banner down to just the version/build (`This is Check Point's 1550 Appliance R81.10.17 - Build 892` -> `1550 Appliance R81.10.17 - Build 892`), everything else keeps the existing CPUSE path; also fixed the status line's orange "needs attention" highlight wrapping the agent build number along with the parenthetical update-status text it's meant for  
v0.56.2 Installing/verifying/importing/uninstalling a CPUSE package whose display name contains a space (e.g. `R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 40`, exactly what CPUSE itself reports on some Gaia versions) failed with `CPUSEError: suspicious package identifier` - the shell-safety check on package IDs before they hit a clish command line (`cpuse.py`'s `_check_id`) allowlisted only `[A-Za-z0-9._-]+`, which was never actually the safety boundary (the whole command is `shlex.quote()`-wrapped as one unit in expert mode, or sent straight to a clish-only session in clish mode - spaces reach clish safely either way) and just rejected legitimate real-world names. Now blocklists actual shell metacharacters (`;&|` backtick `$<>\"'` and newlines) instead  
v0.56.1 A firewall's or management server's SSH login could silently use the wrong username once a credential set was assigned - `SSHClient.connect()` always used the entity's own stored `ssh_user` field, never the assigned credential set's `ssh_username`, and the two only stayed in sync via one-time UI copies (Add/Edit submit, Discover import) that went stale the moment a credential set was edited, reassigned, or - the actual case that surfaced this - a Discover Firewalls import stamped every row with the primary's own username regardless of which credential set ended up assigned to it. Right password, wrong account, generic "Authentication failed". The SSH username now resolves live from the assigned credential set at connect time for every host-touching job; `ssh_user` still exists but only matters for storage-disabled environments, which have no credential set to source it from - see `.claude/memory/ssh-username-source-of-truth.md`  
v0.56.0 Added Spark (Gaia Embedded) firmware patching: a "Test Credentials" link on Spark rows proves SSH login and `expert`-mode escalation work before you rely on them, and the Firewalls panel's bulk package selector now enforces compatibility - picking a `.tgz`/`.tar` package only allows selecting Gaia firewalls and vice versa for `.img`, picking a firewall of one kind first locks the package picker and the remaining rows to match (Management Servers panel unchanged). The transfer job follows the documented sequence (SSH, expert, `bashUser on`, log out, SCP the image to `/storage`, verify, SSH back in, expert, `bashUser off`, `upgrade_revert_image.sh ... upgrade safe`) and can't confirm the upgrade actually completes since Spark has nothing like CPUSE's `show installer package` to poll - only that the command was issued, same "not yet validated against live hardware" posture as the rest of this project's CPUSE/CDT parsers, with the two riskiest guesses (whether SFTP works over Spark's SSH server, and the `expert` password-prompt's exact text) isolated behind narrow interfaces so a wrong guess is a contained fix, not a rewrite - see `.claude/memory/spark-firmware-patching.md`  
v0.55.1 Removing a firewall (or any other action that reloads the Firewalls/Management-Servers tables while a background poll lands at the same moment) could duplicate every row in the table until a manual page refresh - `loadFirewalls()`/`loadServers()` each cleared and rebuilt their table on every call with no guard against two overlapping calls racing each other; v0.35.1 fixed one specific instance of this (a redundant reload inside `pollJobs()` itself) but left every other caller vulnerable to the same race, so it kept resurfacing - both functions now bail out of a stale call instead of rendering on top of a newer one  
v0.51.0 Manual Patching (CPUSE) Firewalls panel now offers a "Bootstrap Credentials" text link next to Refresh, shown when a status check fails with an authentication error - pushes the firewall's assigned credential set onto the gateway via the Management API's `run-script` (CPRID-backed, no SSH access needed to recover), reusing the same clish commands as the Provisioning tab's bootstrap panel  
v0.49.5 Packages tab now extracts and displays compatible major version, Take number, category, arch, and a free-text compatibility/prerequisite note from the package file itself (`hf.config` + `conditions_set.json`) at upload time - also fixed a latent bug where BUNDLE-type packages' per-component `hf.config` files (missing Take/category) could be picked up instead of the authoritative bundle-level one  
v0.49.4 Package verify command was invoked with the identifier from `show installer packages all` instead of the display name from `show installer packages imported` - `installer verify`/`installer install` need the latter, and CPUSE doesn't always render the same identifier across the two scopes  
v0.49.4 Install button on the Direct Patching (CPUSE) tab failed to register the first click - a background poll could land between picking a package and clicking Install, silently resetting the row's selection and re-disabling the button (disabled buttons don't dispatch click at all)  
v0.49.3 Jobs tab Target column was blank for push_to_repo jobs (grouped with the other filename-only pkgs.* jobs) - now shows the management server being pushed to  
v0.49.2 If a package import or upload-to-repo job fails we attempt to remove the file from the temp storage and alert in the job log if this was successful  
v0.49.1 Added percentage display for package uploads  
v0.48.2 Connect to Primary now auto-selects the credential set flagged "default" (if any) in the Credential set picker, instead of leaving it on "none — assign later"  
v0.48.2 In storage-disabled environments, the SSH user field/label in Connect to Primary rendered inline (browser-default) instead of aligned with Name/Address/Role/SSH port above it - also fixes an ID-vs-class CSS specificity bug where the fix itself broke hiding that field in storage-enabled environments  
v0.48.1 The Connect to Primary API-access repair used a fabricated `set-api-settings accessibility "minimize"` mgmt_cli command - corrected to the real `set api-settings accepted-api-calls-from "All IP addresses that can be used for GUI clients"`, with the `--domain "System Data"` flag it also needs on a standalone SMS  
v0.48.1 The "heads up" API-accessibility warning under Connect to Primary rendered as plain muted text instead of orange - `hint warn` had no matching CSS rule; now uses the same prov-note-warn/-err/-ok convention as the rest of that panel  
v0.48.0 No error checking for lack of API access - Connect to Primary now proactively checks the API's accessibility over SSH right after provisioning it, and offers to repair a require-local restriction; a 403 during discovery also explains the likely cause  
v0.47.3 Multi-select management servers for import - only starts first server, doesn't queue second  
v0.46.0 Provide a way to clean up the temp file storage after a timed out or failed package import job  
v0.46.0 Make timeout and check intervals longer during package import process to account for slower imports, improve how they are displayed in job log  
v0.45.3 Upload package to management repo fails with path formatting error  

> Not affiliated with or endorsed by Check Point Software Technologies. "Check Point", "CDT", and "CPUSE" refer to their products. Use only on infrastructure you are authorized to maintain.  
>  
> Written by Claude under the direction of humans. Deploy, <u>test</u>, and use this tool with appropriate caution. No guarantees or assurance of safety is made by the developers. Even with a whole bunch of robots doing the work, we still manage to introduce human error. 🤖