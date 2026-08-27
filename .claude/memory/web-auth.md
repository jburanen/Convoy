---
name: web-auth
description: How the web UI's basic-auth/LDAP authentication, sessions, and the no-auth-no-credential-storage rule work
metadata:
  type: project
---

Web UI authentication, shipped 2026-07-20; local basic-auth backend (on by default)
added 2026-07-24. The **CLI is unaffected** (auth guards the FastAPI app only).
Extends the design in [[patching-web-design]].

## Backend precedence (2026-07-24)
Two backends behind one `Authenticator` protocol; `load_active_auth_settings()`
picks one:
1. **LDAP**, when `CONVOY_LDAP_URL` + `CONVOY_LDAP_REQUIRED_GROUP` are set —
   always wins if configured, regardless of the basic-auth vars.
2. **Basic auth**, otherwise — **on by default**: `BASIC_AUTH_USER` /
   `BASIC_AUTH_PASSWORD` (both default `admin`/`admin`, deliberately not
   `CONVOY_`-prefixed — see [[env-example-sync]]), unless `BASIC_AUTH_DISABLE`
   is set.
3. Fully open, only when LDAP is unconfigured **and** `BASIC_AUTH_DISABLE` is set —
   the old "auth-optional" behavior, now opt-in rather than the out-of-the-box
   default.

This is a **behavior change from the 2026-07-20 launch**: a fresh deployment with
zero auth env vars now has a login gate (admin/admin) instead of running open.
Rationale: don't ship an unauthenticated tool that can drive production firewalls
by default; the operator must deliberately opt out.

## Module map
- `web/auth.py` — the whole auth layer:
  - `AuthSettings`/`load_auth_settings` (LDAP) and `BasicAuthSettings`/
    `load_basic_auth_settings` (basic auth) — env-driven config for each backend;
    `load_active_auth_settings()` applies the precedence above. An LDAP URL set
    without a usable rest-of-config still raises `ConfigError` (fails loud).
  - `AuthenticatedUser`, `Authenticator` (Protocol), `SessionSettings` (Protocol —
    just `idle_minutes`/`cookie_secure`, satisfied by both settings types).
  - `LDAPAuthenticator` — search-then-bind against AD/any LDAP; `ldap3` (in the
    `web` extra). Resolves the user DN (service account search **or**
    `USER_DN_TEMPLATE` direct bind), rebinds as the user to verify the password,
    then gates on **direct `memberOf`** of `REQUIRED_GROUP` (`_normalize_dn` makes
    the compare case/space-insensitive). Rejects empty passwords (anonymous-bind
    guard); escapes the username in the search filter.
  - `BasicAuthenticator` — one configured username, argon2 password hash (via
    `argon2.PasswordHasher`, already a base dependency for the credential-store
    master key). `change_password()` re-verifies the current password, then hashes
    and persists the new one to the `meta` table (`BASIC_AUTH_PASSWORD_HASH_META_KEY`
    = `"basic_auth_password_hash"`) — this DB-stored hash overrides the env-var
    default from then on, so a password change survives a restart without
    touching `BASIC_AUTH_PASSWORD`.
  - `AuthManager` — ties an `Authenticator` to the session store + settings:
    `login/validate/logout/purge_idle`, plus `backend` (`"basic"`/`"ldap"`, an
    `isinstance` check — drives the UI's change-password affordance) and
    `change_password(username, current, new)` (delegates to `BasicAuthenticator`,
    raises `AuthError` under LDAP or a fake/test authenticator).
- `store.py` — `sessions` table (**migration v7**) + `SessionRow` and CRUD, plus the
  `meta` key/value table (**v1**, reused — no new migration needed) for the
  basic-auth password-hash override. Only `sha256(token)` is stored for sessions,
  never the raw token. `last_seen_at` drives the sliding idle window.
- `web/app.py` — `create_app(..., authenticator=?, auth_settings=?)` (tests inject a
  fake, no live directory); lifespan calls `load_active_auth_settings()` and builds
  `LDAPAuthenticator` or `BasicAuthenticator(store, settings)` accordingly.
  `_register_auth_middleware` guards everything except `_PUBLIC_PATHS`
  (`/health`, `/login.html`, `/js/login.js`, `/css/app.css`, `/api/auth/login`,
  `/api/auth/config`, favicon). `/api/*` → 401; HTML nav → 302 `/login.html`.
  Routes: `POST /api/auth/login|logout|password`, `GET /api/auth/me|config`.
  `/api/auth/me` now also returns `backend`.
- Static: `login.html` + `js/login.js` (separate page, backend-agnostic — same
  username/password form works for both); `app.js` gained `initAuth()` (logout
  control + idle timer + wires the username button to the User Settings modal only
  when `backend === "basic"`), 401→login handling in `api()`, and the idle/logout
  path calls `cacheClearCreds()`. `index.html`'s `#user-settings-modal` is the
  password-change form (current + new + confirm), styled `.static` (plain text, no
  underline/pointer) when the backend isn't basic.

## Invariants (don't regress)
- **No auth ⇒ no credential storage.** When `app.state.auth is None`, both enabling
  storage (`/credential-storage {enabled:true}`) and `PUT .../credentials` return
  **409**. Operator-mandated (2026-07-20): no persistent secrets without a login
  gate. Startup logs a warning for any pre-existing storage-enabled env when auth is
  off (non-destructive). Basic auth being on by default means this gate is now
  satisfied out of the box too, not just under LDAP.
- **Auth is optional**, not mandatory — but as of 2026-07-24 that requires an
  explicit `BASIC_AUTH_DISABLE` (with LDAP also unconfigured), not just doing
  nothing.
- Cookie is `HttpOnly`, `SameSite=Strict`, `Secure` per `SESSION_COOKIE_SECURE` —
  which itself defaults to `_default_cookie_secure(env)`: true only when native TLS
  (`CONVOY_SSL_CERTFILE`/`KEYFILE`) is configured, false otherwise (2026-07-25;
  an explicit `SESSION_COOKIE_SECURE` always overrides the guess). **Why:** a
  `Secure` cookie set over plain HTTP is silently dropped by the browser — login
  "succeeds" (server sets it) but every request after looks unauthenticated,
  bouncing straight back to the login page with no visible error (hit on a
  TLS-less dev host — no error surfaces because the *login* request itself
  returned 200; it's the *next* request that 401s). Set it `true` explicitly when
  TLS is terminated by a reverse proxy instead (native certs correctly unset here,
  but the browser only ever sees https).
- Idle timeout is enforced **server-side** (the client timer is UX only). Logout,
  idle, and any 401 clear the tab's cached credentials.
- Password changes are **basic-auth only** — `AuthManager.change_password` raises
  `AuthError` (→ 400) under LDAP or any non-`BasicAuthenticator` backend.

## Testing
`tests/fakes.py::FakeAuthenticator` + `create_app(authenticator=...)` — no live LDAP.
**Tests default to auth fully OFF** via an autouse `conftest.py` fixture that sets
`BASIC_AUTH_DISABLE=true` for every test (preserves pre-2026-07-24 "no authenticator
passed → auth off" behavior everywhere basic auth isn't the thing under test);
individual tests override via `monkeypatch.delenv`/`setenv` to exercise the real
default-on `BasicAuthenticator` path. The shared `client` fixture in
`test_web_api.py` logs in via the fake LDAP authenticator (credential storage needs
auth). `test_auth.py` covers gating, login/logout, idle expiry, the
credential-storage 409, settings parsing, the pure group-check logic, and (new)
default admin/admin login, `BASIC_AUTH_DISABLE`, LDAP-over-basic-auth precedence,
and password change (success, wrong current password, rejected under LDAP);
`test_store.py` covers the session table. Env vars are listed in
[[env-example-sync]].
