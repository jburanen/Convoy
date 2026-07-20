---
name: web-auth
description: How the web UI's LDAP authentication, sessions, and the no-auth-no-credential-storage rule work
metadata:
  type: project
---

Web UI authentication, shipped 2026-07-20. The **CLI is unaffected** (auth guards
the FastAPI app only). Extends the design in [[patching-web-design]].

## Module map
- `web/auth.py` — the whole auth layer:
  - `AuthSettings` + `load_auth_settings(environ)` — env-driven config; returns
    `None` when unconfigured (auth-optional), raises `ConfigError` on a *partial*
    config (fails loud, never silently open).
  - `AuthenticatedUser`, `Authenticator` (Protocol) — backend seam; a local
    basic-auth backend can slot in behind this later.
  - `LDAPAuthenticator` — search-then-bind against AD/any LDAP; `ldap3` (in the
    `web` extra). Resolves the user DN (service account search **or**
    `USER_DN_TEMPLATE` direct bind), rebinds as the user to verify the password,
    then gates on **direct `memberOf`** of `REQUIRED_GROUP` (`_normalize_dn` makes
    the compare case/space-insensitive). Rejects empty passwords (anonymous-bind
    guard); escapes the username in the search filter.
  - `AuthManager` — ties an `Authenticator` to the session store + settings:
    `login/validate/logout/purge_idle`.
- `store.py` — `sessions` table (**migration v7**) + `SessionRow` and CRUD. Only
  `sha256(token)` is stored, never the raw token. `last_seen_at` drives the sliding
  idle window.
- `web/app.py` — `create_app(..., authenticator=?, auth_settings=?)` (tests inject a
  fake, no live directory); lifespan builds `LDAPAuthenticator` from env otherwise.
  `_register_auth_middleware` guards everything except `_PUBLIC_PATHS`
  (`/health`, `/login.html`, `/js/login.js`, `/css/app.css`, `/api/auth/login`,
  `/api/auth/config`, favicon). `/api/*` → 401; HTML nav → 302 `/login.html`.
  Routes: `POST /api/auth/login|logout`, `GET /api/auth/me|config`.
- Static: `login.html` + `js/login.js` (separate page); `app.js` gained
  `initAuth()` (logout control + idle timer), 401→login handling in `api()`, and the
  idle/logout path calls `cacheClearCreds()`.

## Invariants (don't regress)
- **No auth ⇒ no credential storage.** When `app.state.auth is None`, both enabling
  storage (`/credential-storage {enabled:true}`) and `PUT .../credentials` return
  **409**. Operator-mandated (2026-07-20): no persistent secrets without a login
  gate. Startup logs a warning for any pre-existing storage-enabled env when auth is
  off (non-destructive).
- **Auth is optional**, not mandatory — unset LDAP env keeps the app open (trusted
  network), matching prior behaviour.
- Cookie is `HttpOnly`, `SameSite=Strict`, `Secure` per `SESSION_COOKIE_SECURE`
  (set false only for plain-HTTP dev / TestClient).
- Idle timeout is enforced **server-side** (the client timer is UX only). Logout,
  idle, and any 401 clear the tab's cached credentials.

## Testing
`tests/fakes.py::FakeAuthenticator` + `create_app(authenticator=...)` — no live LDAP.
The shared `client` fixture in `test_web_api.py` now logs in (credential storage
needs auth). `test_auth.py` covers gating, login/logout, idle expiry, the
credential-storage 409, settings parsing, and the pure group-check logic;
`test_store.py` covers the session table. Env vars are listed in [[env-example-sync]].
