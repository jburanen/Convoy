# Convoy

Orchestration layer for Check Point's **Central Deployment Tool (CDT)** and **CPUSE**. It coordinates deployment of patches and upgrades — hotfixes, Jumbo Hotfix Accumulators, and major-version upgrades — across fleets of Security Management Servers and Security Gateways, through a web interface.  

> This is an internal operations tool for authorized maintenance on infrastructure you own. It *drives* Check Point's own CDT/CPUSE agents; it does not replace them.

## Scope

CPUSE operates one host at a time and lacks fleet-level orchestration. CDT is integrated into SmartConsole for limited use cases including single gateways and ClusterXL, but the more sophisticated operations lack a UI. This tool provides a UI for patching on-premise Smart-1 servers and their managed firewalls.

### Supported
Patching is supported for:  
✅ On-Premise Smart Center (SMS) servers  
✅ On-Premise Multi-Domain Management (MDM/MDSM) servers  
✅ Quantum Force and Spark firewalls managed by on-prem environments  
✅ Quantum Force and Spark firewalls managed by Smart-1 Cloud (manual patching only, no CDT)  

### NOT Supported
By design, this tool does NOT support patching:  
❌ Smart-1 Cloud Management *(patched by Check Point)*  
❌ Spark Management Portal *(patched by Check Point)*  
❌ Gaia Standalone (self-managed) deployments  *(uncommon)*  
❌ Firewalls defined as dynamic IP (DAIP)  *(code limitations)*  

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
✅ Test firewall discovery in SMS/Smart Center environment  
✅ Test firewall discovery in MDS/Multi-Domain environment  
✅ Test Gaia/Force Gateway patching via CPUSE  
✅ Test Spark (Gaia Embedded) firmware patching via upgrade_revert_image.sh  
◻️ Test Spark major version patching - ie 80.20.X > 81.10.X  
◻️ Packaged deployment release that doesn't require git clone and --build  
◻️ Independent agentic code security review  

### Milestones to reach v2

◻️ CDT deployment to Gaia/Force gateways  

### Roadmap / Punch List
🪲 Bugfix ⏫ Required for next release 🤞 Non-blocking nice-to-have ✨ Cosmetic only

✨ Add logic to display a warning on mobile devices that the UI of this tool does not scale down well (by design) and you should use it on a larger display.   
✨ Revisit ALL descriptive text and rewrite for clarity and brevity  
🤞 RADIUS auth option  
🤞 Timed/scheduled install actions  

#### Packages
🤞 Add a percentage progress display for package upload  
🤞 If disk space check fails, parse for large folders, suggest things to clean  

#### Manual Patching (CPUSE)
🤞 Add deployment agent upgrade option  
🤞 Some kind of sledgehammer to swing to release config/job lock from management server and firewalls if a job gets stranded/stuck  
✨ Separate firewalls into two panels - Spark and non-Spark  
🤞 For Spark gateways, warn if you've chosen a firmware package from a different major version  
🤞 Leverage the gateway family identifier built into Spark filenames to limit choices  

#### Jobs
🤞 Add syslog output    
🤞 Add a download or a copy button for the install log  
🤞 Allow import jobs to be cancelled during file copy stage - clean up partial file on target  
✨ Affirm in a push_to_repo job output that the temp storage was cleaned up  
✨ On jobs with error output, never let the error output spill outside the table boundary - direct the user to view details in the output box or something like that  
✨ Show current percentage when available in the output column so I don't have to expand the full job progress to see it  

#### Squashed Bugs
v0.65.0 Closes the "built-in help docs" punch-list item, plus a few small UI cleanups bundled in the same batch. Every panel's long-form descriptive paragraph is now a one-clause summary inline, with the full explanation moved behind a new "?" button (always the right-most button in the panel's header row) opening a shared help modal - all 9 panels' brief/full text now lives in one new content file, `web/static/js/panel-help.js`, so wording changes never need to touch `index.html` or `app.js`. Also removed the sliding descriptive-text bar that used to run under the tab row (and its now-dead `CHKP_CPUSE_SHOW_TAB_HINTS` env var/setting) - it duplicated the same information the new per-panel help modals now carry, permanently, for content only useful once. On the Firewalls table, tags now render before (not after) the cluster-membership text on their shared line, and that text drops the redundant word "cluster" (`Active member in <name>` instead of `Active cluster member in <name>`). The Manage Environments modal's API-only toggle label is now `API-only (ie: Smart-1 Cloud)`, naming the motivating use case  
v0.64.0 Added a third environment access mode alongside SMS/MDS: **API-only** management, for estates (e.g. Smart-1 Cloud, or any management server the operator only has a Management API key for) reachable exclusively via the Management API - no SSH/SCP at all. New `api_only` flag on the environment (orthogonal to `is_mds`, same DB-column/`HostConnector`-attribute/manage-modal-toggle pattern already used for MDS-kind and credential storage) is enforced in one place - `HostConnector`'s two SSH chokepoints (`require_credentials`/`connect`) refuse SSH to any management-plane host in such an environment, which transparently covers CPUSE-patching the management server itself, CDT, Connect to Primary, the API-accessibility repair job, and Upload to Mgmt's SCP step - firewalls are untouched, since patching them was never dependent on how the management server itself is reached. Credential sets for such an environment need only an API key (`CredentialStore.put_set`'s new `api_only` parameter skips the SSH-secret/expert-password requirement added in v0.60.0). The UI hides Bootstrap and Connect to Primary on the Provisioning tab, the CPUSE tab's whole Management Servers panel, and the Packages tab's Upload to Mgmt button, and simplifies the Add Server / Add Credential modals down to the fields that still apply. Firewall discovery, gateway SIC-credential bootstrap, and estate discovery's SMS path already ran entirely over the Management API with no SSH involved, so they work unmodified; MDS peer discovery's SSH step already degraded to a warning rather than a hard failure on a missing SSH credential, so an MDS + API-only combination (fully orthogonal - Multi-Domain-ness and access mode are independent) just loses that one piece of best-effort enumeration instead of breaking  
v0.63.0 Spark firmware transfer (`spark.scp`) never checked whether `/storage` actually had room for the image before copying it - unlike the CPUSE-local import path, which has checked `/var/log`/`/` since v0.23-ish. Added a pre-check (fails closed with `PreCheckError`, no override) requiring the image's own size plus 10% headroom - simpler than CPUSE's per-path multiplier scheme since Spark's transfer is a plain file copy with no separate extraction/bookkeeping filesystem to size for. Runs before `bashUser` is even enabled, so a shortfall never touches device state at all. `_free_bytes`/`_fmt_bytes` (the `df -Pk` reader and byte-formatter `PatchingService` already had) moved to `services/common.py` as `remote_free_bytes`/`format_bytes` so both patching paths share one implementation  
v0.62.0 Firewalls had no way to attach operator-defined labels (e.g. "prod", "east-region") - added a `tags` property (JSON list, new `firewalls.tags` column) alongside the existing notes-style fields, edited via a chip-list widget in the Add/Edit Firewall modal (type a tag and press Enter/Add, or pick one already used elsewhere in the environment from the datalist suggestions - free text either way, nothing enforced). Unlike cluster_name/mds_domain, tags are ordinary operator data like notes - every add or edit replaces the full list, never kind-gated to creation only. Displayed on the firewalls table's detected-state row in the same spot cluster membership already occupies, as small badges, and shown even before a firewall's first Refresh (cluster membership itself still needs one, since it's genuinely live-refreshed data - tags aren't). Also wired into last version's free-text table filter, so a tag is now one more thing a typed word can match  
v0.61.0 The Firewalls panel had no way to narrow a long table down to a specific host, subnet, role, or credential set - added a single free-text filter box spanning the table width, above the header row. Space-separated words are ANDed together (each one narrows further), matched case-insensitively against name/role/credential-set as substrings; a word shaped like a full IPv4 address or a CIDR block (e.g. `192.0.2.10` or `192.0.2.0/24`) is instead matched against the address column with real IP semantics - exact equality or subnet containment - rather than as a substring, since naive substring matching on an IP (e.g. "10" hitting any address with a "10" in any octet) would be actively misleading; a partially-typed address that isn't a complete valid IPv4 just falls through to substring matching like everything else. Client-side only (no API round trip), re-applied after every table refresh/add/edit and cleared on environment switch  
v0.60.0 Every non-Spark Gaia host (management servers, CPUSE-patched firewalls, CDT-driven gateways) was provisioned with `/bin/bash` as its service account's login shell - a standing root-equivalent SSH session on every connect, with no elevation step, the opposite of the clish-login-then-`expert`-as-needed posture Spark firewalls already used. Provisioning no longer sets a shell at all (Gaia's own default is clish); a new `GaiaSession` transport detects live per connection whether an account lands in clish or (for an operator's own pre-existing bash-shell account) bash, and only escalates to `expert` the first time a job actually needs a bash-native command (CDT, disk-space checks, sha1 verification, install-log capture, `mgmt_cli`, ...) - clish-only operations like a plain Refresh never elevate at all. File transfer (SFTP/SCP) needs a genuinely bash-shell session, which a clish login can't serve, so it's handled by briefly flipping the account's own shell to `/bin/bash`, reconnecting, transferring, and flipping it back - always, even on failure, since leaving the account on a standing bash shell would defeat the whole point. Every stored credential set now requires an expert-mode password (previously optional except for Spark's own opt-in flag), and a storage-disabled environment's job-time credential prompt now asks for one too, but only for operations that actually escalate  
v0.59.0 Spark install used to guess at its own outcome from whatever its SSH session happened to observe issuing `upgrade_revert_image.sh` - real-hardware testing showed that observation is unreliable in both directions (see v0.58.2/v0.58.3), so it no longer tries. It now leaves that session alone, waits for the device's scheduled reboot to close it, pings the firewall until it responds again, reconnects over SSH, and compares `fw ver`'s reported build number against the installed package's own filename before declaring success - a confirmed mismatch fails the job, and giving up at the ping/reconnect stage without ever finding out is a distinct "timed out, go check" outcome rather than a false failure. The Jobs tab's Output column also now shows live status text ("installing", "waiting for reboot", "pinging", etc.) while an install runs, instead of staying blank until it finishes  
v0.58.2 A Spark install could report "succeeded" against a firewall that was never actually reformatted with the new firmware - real hardware confirmed `upgrade_revert_image.sh`'s own `mount_pfrm_inactive_part()` checks the exit status of the `mount` command that runs *after* `mke2fs`, not `mke2fs`'s own status, so `mke2fs` refusing to format an already-mounted inactive partition (likely a stale mount left by an earlier, incomplete attempt) doesn't necessarily abort the script - it can silently extract the new image onto unformatted, stale storage. The install job now scans for `mke2fs`'s own refusal text and fails the job instead of reporting success, telling the operator to reboot the firewall to clear the stale mount first. Also corrected a misleading log message that framed the SSH session returning control as the job "giving up" before a reboot - the script itself returns control on success too, well before the reboot it schedules for ~1 minute later; removed a redundant `bashUser off` at the start of install (that's transfer's job, at the end of `spark.scp`, not install's to repeat)  
v0.58.1 The Install confirmation dialog for a Spark firewall could say "Skipping `installer verify` — installing directly" - `installFirewallPackage`'s confirm() text was built purely from the (now-hidden, but still present and defaulted) skip-verify checkbox with no regard for host role, and `installer verify` isn't a CPUSE concept Spark has at all (Gaia Embedded has no CPUSE agent). The line is now only added for non-Spark rows  
v0.58.1 Radio buttons (e.g. the Spark firewall credential-scenario modal) rendered as huge, badly-misaligned blobs instead of a normal-sized dot next to its label - the generic `input, select, button` rule (padding/border/background meant for text fields) was being applied to `type="radio"`/`type="checkbox"` inputs too, and a `.stacked input { width: 100% }` rule (same specificity, later in the stylesheet) stretched the box to the full form width on top of that. Checkboxes/radios now get their own reset (native size, no border/background/padding) that out-ranks both  
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