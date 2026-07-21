---
name: environment-kind
description: Environments declare SMS vs Multi-Domain (MDS) once via an is_mds flag, instead of the tool guessing per-request from a host's role
metadata:
  type: project
---

An environment is always entirely an **SMS estate** or entirely a **Multi-Domain
(MDS)** one, never a mix (operator-stated invariant, 2026-07-21). This is now
tracked explicitly rather than inferred:

- **Storage:** `environments.is_mds` (migration v10 in `store.py`), boolean,
  default `False` (SMS) — mirrors the existing `credential_storage_enabled`
  column/pattern.
- **API:** `POST /api/environments` accepts `is_mds` at creation; `POST
  /api/environments/{env}/kind` toggles it later (mirrors the
  `/credential-storage` toggle). `GET /api/environments` includes it.
- **UI:** the "Manage environments" modal ([[patching-web-design]]) has a
  "Multi-Domain (MDS) environment" checkbox on the create form and a per-row
  toggle in the environment list.
- **Propagation:** `EnvironmentManager.rebuild()` passes `is_mds` into
  `HostConnector` (`services/common.py`) alongside `credential_storage_enabled`,
  so any service holding a connector can read `connector.is_mds` without a
  round-trip to the store.
- **Seeding:** `EnvironmentManager.seed_from_config()` infers `is_mds` from the
  seeded inventory file's host roles (any `primary_mds`/`secondary_mds`/`mlm`/
  legacy `mds` role) — a config-defined environment doesn't need the operator to
  redeclare what its own inventory already states. UI-created environments
  default to SMS and the operator ticks the box explicitly.

**Why:** `services/discovery.py` used to infer SMS-vs-MDS command variants from
whichever host happened to be the discovery *primary* (`primary.role in
(PRIMARY_MDS, ...)`). That's fragile — it re-derives a fact that's actually
environment-wide every single call, from a value (the primary's role) that only
happens to correlate with it. `DiscoveryService.discover()` now reads
`connector.is_mds` directly instead.

**How to apply:** any *future* task that needs to pick between SMS-flavored and
MDS-flavored commands (not just discovery) should read `connector.is_mds` the
same way — don't re-derive it from a host role. See [[mds-discovery-command]] for
the specific commands this currently gates.
