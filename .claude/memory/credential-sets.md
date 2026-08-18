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
`ssh_password` / `ssh_private_key`, plus an optional `api_key`. Each secret is a
nullable Fernet-ciphertext column on `credential_sets` (reuses the existing
key/canary machinery in `credentials.py`).

**`expert_password` was removed in migration v23** (2026-08-18, operator-directed):
it was captured, encrypted, and decrypted into every `CredentialBundle`
(`CredentialKind.EXPERT_PASSWORD`) but no CPUSE/CDT code path ever read it back
out — dead since it was added. Removed end-to-end: DB column (`ALTER TABLE
credential_sets DROP COLUMN expert_password_ct`), `CredentialSetRow`/
`CredentialSetInfo`/`CredentialKind`, `put_set`/`get_set_bundle`, the
`CredentialSetIn` API model, and both UI surfaces — the Provisioning tab's
credential-set add/edit modal (`cs-expert`) *and* the separate storage-disabled
"Enter credentials" job-time prompt (`cm-expert`, `#cred-modal` — a distinct
ephemeral-credential path, not a named set). If a real Spark/expert-mode
escalation need ever comes back, re-add it as a fresh field with an actual
consumer wired up first, rather than reviving this one.

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
  password|key|none, `has_api`).
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
