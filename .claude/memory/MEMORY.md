# Project Memory — chkp-cpuse-orch

Index of persistent project facts. One line per memory; details live in the linked file.
Load this at the start of each session; read a linked file when its hook looks relevant.

- [Project Overview](project-overview.md) — what this tool orchestrates and for whom
- [CDT & CPUSE Domain](cdt-cpuse-domain.md) — how Check Point's deployment tooling actually works
- [Tech Stack](tech-stack.md) — Python + Typer + Paramiko/Gaia API; why
- [Architecture](architecture.md) — module layout and data flow
- [Patching & Web Design](patching-web-design.md) — two subsystems, web-primary service core, credential/package/job infra
- [Operational Safety Constraints](safety-constraints.md) — HA/cluster rules, dry-run-first, maintenance windows
- [Security & Public-Repo Hygiene](security-hygiene.md) — what must never be committed once public
- [Use the documentation-tool MCP](use-documentation-tool-mcp.md) — always prefer it for docs lookups, but don't trust exact mgmt_cli param/value spelling without cross-checking (fabricated twice)
- [Keep .env.example in sync](env-example-sync.md) — add every new runtime env var to the tracked example
- [Optional credential storage](optional-credential-storage.md) — per-env toggle; disabled envs use in-memory-only per-job credentials
- [Credential sets](credential-sets.md) — credentials are named login sets assigned to servers (migration v8), not per-host secrets
- [Web UI authentication](web-auth.md) — basic-auth (default on, admin/admin) or LDAP/AD, sessions, idle logout; no-auth ⇒ no credential storage
- [Git workflow](git-workflow.md) — work directly on main; no feature branches; bump `__version__` every batch, in the shipping commit
- [Provisioning command order](provisioning-command-order.md) — RBA role assignment must precede the shell→bash switch
- [MDS discovery command](mds-discovery-command.md) — locate MDSDIR via `/opt/CPmds-R*` glob, don't trust any pre-set env var over SSH exec; SmartEvent on MDS confirmed via API login domain="Global"
- [Environment kind (SMS vs MDS)](environment-kind.md) — `environments.is_mds` flag, set via UI checkbox, drives command selection (not host role)
- [Firewall discovery domain picker](firewall-discovery-domain-picker.md) — no source-server picker (one primary/env); MDS picks a Domain via `show-domains` (unverified against live gear)
- [ClusterXL live state](clusterxl-live-state.md) — Firewalls panel: role is live (cphaprob, every refresh); cluster name is static, Mgmt-API-only + manual fallback, stored on FirewallRow
- [No SSH for cluster name](no-ssh-for-cluster-name.md) — cluster object name is Mgmt-API-only, ever; manual entry is the only valid fallback, never SSH/CLI
- [MDS domain per firewall](mds-domain-per-firewall.md) — FirewallRow.mds_domain tracks each firewall's Domain/CMA so post-hoc API lookups can log in correctly on MDS
- [Config path resolution](config-path-resolution.md) — relative paths.* anchor to config.yaml's own directory, not the process CWD
- [deploy.sh --reset flag](deploy-reset-flag.md) — dev-only full wipe: `./data` (DB + packages) and `.env`, then restores default config.yaml
- [Mgmt API bootstrap MDS profile](mgmt-api-bootstrap-mds-profile.md) — MDS admin uses `multi-domain-profile "Multi-Domain Super User"`, not `permissions-profile "Super User"`
- [Mgmt API add-api-key command](mgmt-api-add-api-key-command.md) — key comes from a separate `add api-key admin-name` call, not `add administrator`; no `api restart` needed
- [Project rename to Convoy](project-rename-convoy.md) — renaming from chkp-cpuse-orch to Convoy before GA; GitHub rename is user's manual step, don't do it proactively
- [Mgmt API SMS System Data domain](mgmt-api-sms-system-data-domain.md) — standalone SMS bootstrap login needs `--domain "System Data"` or add administrator/add api-key fail with err_inappropriate_domain_type
- [API access repair flow](api-access-repair-flow.md) — proactive SSH diagnose right after Connect to Primary succeeds; repair stays confirm-gated, not folded into the provisioning command sequence
- [Punch list workflow](punchlist-workflow.md) — closing a README Punch List bug moves it to Squashed Bugs w/ version, same commit as the fix
- [Spark firewall credential scenarios](spark-firewall-credential-scenarios.md) — adding a Spark firewall prompts direct-vs-bootstrap credentials, requires expert password; modal-on-modal needs explicit z-index (DOM order ≠ nesting order)
- [Table reload race](table-reload-race.md) — loadServers()/loadFirewalls() need a bump-token guard against overlapping calls, or every row silently doubles; recurred once after a partial 2026-07-23 fix
- [SSH username source of truth](ssh-username-source-of-truth.md) — connect() resolves the SSH username from the assigned credential set live (default_client_factory), never from Host.ssh_user, which only survives for storage-disabled hosts
- [Spark firmware patching](spark-firmware-patching.md) — SCP + expert-mode upgrade_revert_image.sh flow; new InteractiveShell/GaiaExpertSession SSH primitive; SFTP-vs-SCP and expert-prompt-text both unvalidated against real hardware, isolated on purpose
- [CPUSE package ID shell safety](cpuse-package-id-shell-safety.md) — _check_id blocklists shell metachars, not an allowlisted charset; real CPUSE display names have spaces
