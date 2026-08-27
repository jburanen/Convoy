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
  `os.environ`, or a `CONVOY_*` name), add a matching commented entry to
  `.env.example` in the same change — name, one-line purpose, default.
- Real secrets never get real values here — placeholders only (see
  [[security-hygiene]]). Secret vars (`CONVOY_MASTER_KEY`) use `changeme`;
  optional/tunable vars stay commented out showing their default.
- Current runtime env vars: `CONVOY_MASTER_KEY` (+ `_FILE`), `CONVOY_CONFIG`,
  `CONVOY_PACKAGE_RETENTION_DAYS`, `CONVOY_SSL_CERTFILE`/`_KEYFILE` (native
  HTTPS, `web/__main__.py`),
  `CONVOY_WEB_LOG_LEVEL` (`reporting.resolve_log_level`, also applied to
  uvicorn's own logs by `web/__main__.py`), `CONVOY_LOG_API_CALLS`
  (`transport/mgmt_api.py` — sanitized request/response logging), and the
  web-auth set (see [[web-auth]]): `CONVOY_LDAP_URL`,
  `CONVOY_LDAP_REQUIRED_GROUP`, `CONVOY_LDAP_BIND_DN`,
  `CONVOY_LDAP_BIND_PASSWORD` (+ `_FILE`), `CONVOY_LDAP_USER_BASE_DN`,
  `CONVOY_LDAP_USER_FILTER`, `CONVOY_LDAP_USER_DN_TEMPLATE`,
  `CONVOY_LDAP_MEMBER_OF_ATTR`, `CONVOY_LDAP_START_TLS`,
  `CONVOY_LDAP_TLS_VERIFY`, `CONVOY_LDAP_CA_CERT`,
  `CONVOY_SESSION_IDLE_MINUTES`, `CONVOY_SESSION_COOKIE_SECURE`, and the
  basic-auth trio (default backend, on unless LDAP is configured or disabled):
  `BASIC_AUTH_USER`, `BASIC_AUTH_PASSWORD` (both default `admin`),
  `BASIC_AUTH_DISABLE`. Deliberately **not** `CONVOY_`-prefixed — matches the
  literal names requested when this backend was added (2026-07-24).
- Per-host SSH credentials are NOT env vars anymore: they live in the encrypted
  DB-backed `CredentialStore`, added via the web UI. The inventory `secret_ref`
  field and `config.resolve_secret()` are legacy/unused by the resolution path —
  don't add `*_SSH_PASSWORD` vars to `.env.example`.
