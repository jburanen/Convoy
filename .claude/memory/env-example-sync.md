---
name: env-example-sync
description: Keep .env.example current whenever a new runtime env var is added
metadata:
  type: project
---

`.env.example` is the tracked, placeholder-only reference for every environment
variable the tool reads at runtime. Keep it in sync.

**Why:** operators configure deployments (compose `environment:` block, shell, or a
secrets store) from this file. A new env var that isn't listed here is effectively
undiscoverable — the operator won't know the knob exists.

**How to apply:**
- Whenever you add or rename a runtime env var (anything actually read via
  `os.environ`, or a `CHKP_CPUSE_*` name), add a matching commented entry to
  `.env.example` in the same change — name, one-line purpose, default.
- Real secrets never get real values here — placeholders only (see
  [[security-hygiene]]). Secret vars (`CHKP_CPUSE_MASTER_KEY`) use `changeme`;
  optional/tunable vars stay commented out showing their default.
- Current runtime env vars: `CHKP_CPUSE_MASTER_KEY` (+ `_FILE`), `CHKP_CPUSE_CONFIG`,
  `CHKP_CPUSE_PACKAGE_RETENTION_DAYS`, and the web-auth set (see [[web-auth]]):
  `CHKP_CPUSE_LDAP_URL`, `CHKP_CPUSE_LDAP_REQUIRED_GROUP`, `CHKP_CPUSE_LDAP_BIND_DN`,
  `CHKP_CPUSE_LDAP_BIND_PASSWORD` (+ `_FILE`), `CHKP_CPUSE_LDAP_USER_BASE_DN`,
  `CHKP_CPUSE_LDAP_USER_FILTER`, `CHKP_CPUSE_LDAP_USER_DN_TEMPLATE`,
  `CHKP_CPUSE_LDAP_MEMBER_OF_ATTR`, `CHKP_CPUSE_LDAP_START_TLS`,
  `CHKP_CPUSE_LDAP_TLS_VERIFY`, `CHKP_CPUSE_LDAP_CA_CERT`,
  `CHKP_CPUSE_SESSION_IDLE_MINUTES`, `CHKP_CPUSE_SESSION_COOKIE_SECURE`.
- Per-host SSH credentials are NOT env vars anymore: they live in the encrypted
  DB-backed `CredentialStore`, added via the web UI. The inventory `secret_ref`
  field and `config.resolve_secret()` are legacy/unused by the resolution path —
  don't add `*_SSH_PASSWORD` vars to `.env.example`.
