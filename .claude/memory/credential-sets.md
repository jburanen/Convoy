---
name: credential-sets
description: Credentials are named "login sets" assigned to servers, not per-host secrets (migration v8)
metadata:
  type: project
---

Since **migration v8** (2026-07-20), a stored credential is a **named login set**
(operator-chosen name, unique per environment), not a per-`(host, kind)` row. The old
`credentials` table and its `*` fleet-wide default were **dropped and wiped** (operator
chose re-entry over data migration). Applies to storage-enabled environments only;
storage-disabled envs keep the unchanged inline-prompt path (see
[[optional-credential-storage]]).

## Shape
One set bundles everything needed to reach a Gaia server: `ssh_username` + **one of**
`ssh_password` / `ssh_private_key`, plus optional `expert_password` and `api_key`. Each
secret is a nullable Fernet-ciphertext column on `credential_sets` (reuses the existing
key/canary machinery in `credentials.py`).

**`expert_password` was removed in migration v23** (2026-08-18, operator-directed:
it was captured/decrypted into every `CredentialBundle` but no CPUSE/CDT code path
consumed it), then **restored the same day in migration v24** (operator reversed the
call — the option to define/store an expert-mode password per credential set is
needed after all). Since SQLite migrations are append-only and v23 already shipped
(`ALTER TABLE credential_sets DROP COLUMN expert_password_ct`), v24 re-adds it as a
fresh `ALTER TABLE ... ADD COLUMN expert_password_ct BLOB` rather than editing v23 —
functionally the same field, restored end-to-end: `CredentialSetRow`/
`CredentialSetInfo.has_expert`/`CredentialKind.EXPERT_PASSWORD`, `put_set`/
`get_set_bundle`, the `CredentialSetIn` API model, and both UI surfaces — the
Provisioning tab's credential-set add/edit modal (`cs-expert`) and the separate
storage-disabled "Enter credentials" job-time prompt (`cm-expert`, `#cred-modal` — a
distinct ephemeral-credential path, not a named set). Still no CPUSE/CDT code path
reads it back out — it's storage only, for the operator's own reference/manual use,
same as before v23.

**`require_expert` (added 2026-08-18, same day):** `CredentialSetIn` gained a
`require_expert: bool = False` field, checked in `put_credential_set`
(`web/app.py`) before it ever reaches `submit_put`/`put_set` — the *only*
role-aware point in this whole otherwise role-agnostic path. Set by the Spark
firewall credential-scenario flow (see [[spark-firewall-credential-scenarios]])
when saving a *new* credential set for a Spark firewall, since Spark patching
needs an expert password. Everywhere else (the plain Credentials panel,
`saveBootstrapCredential`) omits it and is unaffected.

## Assignment
A management server references **one** set; a set is assignable to **many** servers
(the reuse pattern that replaced `*`). Stored as `env_hosts.credential_set_id` FK →
`credential_sets(id)` **ON DELETE SET NULL** (deleting a set auto-unassigns its servers;
`PRAGMA foreign_keys=ON` per connection makes this fire). `inventory.Host` carries
`credential_set_id`, populated from `env_hosts` in `EnvironmentManager.rebuild`.

## Where the wiring lives
- `store.py`: `credential_sets` table + `CredentialSetRow`; `upsert/list/get/delete_
  credential_set`, `assign_credential_set`, `delete_environment_credential_sets`.
  `assign_credential_set` is separate from `upsert_env_host`, so editing a server never
  clears its assignment.
- `credentials.py::CredentialStore`: `put_set` (requires an SSH secret; pw XOR key),
  `list_sets`, `get_set_bundle(set_id, server_name)` → the same `CredentialBundle`
  (`dict[CredentialKind, Credential]`) downstream code already consumes, `set_name`,
  `delete_set`. `CredentialSetInfo` is the secret-free listing view (`ssh_auth` =
  password|key|none, `has_expert`, `has_api`).
- `services/common.py::HostConnector.host_credentials` resolves via
  `host.credential_set_id` → `get_set_bundle`; unassigned → `CredentialError("no
  credential assigned … assign on the Management tab")`. `assigned_credential(host)`
  returns the set name for listings.
- `services/environments.py::EnvironmentManager.assign_credential(env, host, set_name|None)`.
- `web/app.py`: `GET/PUT /api/env/{env}/credentials` (list/create sets, `PUT` body
  `CredentialSetIn`), `DELETE …/credentials/{name}`, and
  `POST /api/env/{env}/servers/{name}/credential {set: name|null}` to assign. The
  servers listing carries `credential_set` (assigned name|null).

## UI
Credentials panel (Provisioning tab) creates/lists/deletes login sets; the Management
tab's per-server credential column is a `<select>` that POSTs the assignment on change
(disabled in storage-disabled envs). See app.js `loadCredentialSets`, `assignCredential`.

## Deploy note
v8 **wipes** existing stored credentials — after deploying, sets must be re-created and
re-assigned per environment on the dev host ([[test-host-deploy]]).
