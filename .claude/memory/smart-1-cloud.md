---
name: smart-1-cloud
description: S1C tenant is stored as an ordinary management server row with the tenant UUID in mgmt_api_context; three fields, api-key login, no SSH
metadata:
  type: project
---

Smart-1 Cloud is Check Point's **hosted** management: they own the management
server, so there is no SSH, no expert mode, no CPUSE on it, and no file system to
reach. An S1C environment is the `api_only` environment type (see
[[environment-kind]] for the SMS/MDS flag it sits beside).

**The connection is three fields**, all printed on one screen — Smart-1 Cloud →
**Settings → API & SmartConsole** — which shows the login request verbatim:

```
https://<maas-url-prefix>.maas.checkpoint.com/<tenant-uuid>/web_api/login
{ "api-key": "<generated key>" }
```

* **maas URL prefix** — the tenant's subdomain of `maas.checkpoint.com`
* **tenant UUID** — the path segment before `/web_api`
* **Management API key** — generated (and re-generated/revoked) on that screen

Auth is therefore the *classic* Management API flow: `{"api-key": ...}` → `sid` →
`X-chkp-sid`. **Not** the Infinity Portal `clientId`/`accessKey` →
`cloudinfra-gw.portal.checkpoint.com/auth/external/user` → bearer-token flow —
that is a different key for different (Infinity Portal) services, and Check
Point's docs do not establish that its token is accepted at `web_api`. Operator
supplied the S1C screen as the source of truth, 2026-08-27.

**Design: an S1C tenant is not a new kind of object.** It is stored as the
environment's one management server (`env_hosts`) with the tenant UUID in
`mgmt_api_context` (migration v29, `Host.mgmt_api_context`), and its key as an
ordinary credential set assigned to that row. Discovery, package-repo pushes and
every other Management API caller are unchanged, because a `Host` plus an API key
is exactly what they already need. The only code that knows about S1C is:

* `transport/mgmt_api.py` — inserts the context segment into the base URL, and
  defaults `verify_tls` **True** when one is present (a public Check Point host
  with a real certificate, unlike a self-signed on-prem server)
* `services/s1c.py` — `Smart1CloudService`, synchronous + audited like
  [[credential-sets]] CRUD; verifies by logging in *before* storing anything
* the Provisioning tab's Smart-1 Cloud panel, which **replaces** Management
  Servers for these environments (`updateApiOnlyVisibility` shows exactly one)

`mgmt_api_context` is validated to a bare identifier (`[A-Za-z0-9._-]{1,128}`) by
the `Host` model: it is interpolated into the URL the environment's API key is
sent to, so a value carrying a slash or scheme could redirect that key.

Firewalls in an S1C environment are **unaffected** — still reached over SSH and
patched exactly as anywhere else. `api_only` only ever described the management
plane (see [[optional-credential-storage]] for how the key is stored).
