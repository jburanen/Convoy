---
name: ssh-username-source-of-truth
description: SSH login username comes from the assigned credential set's ssh_username, live, when one exists — never from Host.ssh_user in that case; that field stayed silently stale
metadata:
  type: project
---

Found 2026-08-19 debugging a real failure: firewall `lab02-1550`'s
`Host.ssh_user` was `"svc-patchmgr"` but its assigned credential set's
`ssh_username` was `"admin"`. `SSHClient.connect()` (`transport/ssh.py`) used
`host.ssh_user` **exclusively** — it never consulted the credential's own
username, even though `Credential.username` was already populated from the
credential set (`credentials.py`'s `_add()`, from `ssh_username`). The result:
SSH auth failed with the *right password for the wrong account*, while the
operator's manual login (using the correct username) looked fine — a
confusing, hard-to-diagnose failure mode.

**Why they diverged**: the UI tried to keep `Host.ssh_user` in sync by
copying the credential set's username into the hidden field at Add/Edit-
submit time, but that's a one-time snapshot, not a live link. It goes stale
whenever: a credential set's username is edited afterward (the credential-
set edit modal never cascaded to assigned hosts); a *different* credential
set is reassigned via the standalone assign-credential action (never touched
`ssh_user` at all); or — the actual `lab02-1550` case — Discover
Firewalls/Servers import stamped every row with the *primary's* stored
`ssh_user`, regardless of which credential set ended up assigned to that
specific row (a brand-new, distinct Spark credential set in this case).

**Fix**: `services/common.py`'s `default_client_factory` — the single choke
point every host-touching job resolves a `Transport` through (CPUSE, CDT,
Spark patching, gateway bootstrap, discovery/state checks all route through
`HostConnector.connect()` → this function) — now resolves the username from
the credential itself (`cred.username`) when present, passing it to
`SSHClient`'s new `username` override param (`transport/ssh.py`), and falls
back to `host.ssh_user` only when the credential carries none. `Credential.
username` is populated identically whether the bundle came from a stored
credential set or an inline per-job credential, so this is storage-mode-
agnostic by construction — no branching needed.

**`Host.ssh_user` still exists and still matters** for storage-disabled
environments (no credential set is ever assigned there) — it was
deliberately left alone: no schema migration, no field removal from
`FirewallIn`/`EnvServerIn`. The frontend (`app.js`) stopped *writing* a
derived `ssh_user` when storage is enabled (Add/Edit Server/Firewall
submits, both Discover import loops) since it's no longer read at connect
time in that case — sending it was just confusing, unused data. The
Management Servers "SSH user" column (`.srv-user`) now displays the
*assigned credential set's* `ssh_username` live when one exists, falling
back to the stored `srv.ssh_user` only when nothing is assigned.

**Explicitly out of scope**: `ConnectPrimaryIn.ssh_user`
(`services/connect_primary.py`) is overloaded — it's also the seed name for
the Management API administrator account the bootstrap flow *creates* on the
primary, not purely an SSH-auth field, and it runs before any credential set
exists. Left untouched.

**Apply this lesson generally**: any time a fact is duplicated across two
records (here: an entity's own field vs. its assigned credential set's
field) with only a copy-on-save sync and no live link, expect it to drift.
Prefer resolving from the single authoritative source at the point of use
over copying a snapshot around.
