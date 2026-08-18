---
name: spark-firewall-credential-scenarios
description: Adding a Spark firewall (manual or Discover import) prompts direct-use-vs-bootstrap credential scenario, requires expert password
metadata:
  type: project
---

Added 2026-08-18 (operator-directed, same day as [[credential-sets]]'s
`require_expert` restore). When a Spark (Gaia Embedded) firewall is added in a
storage-enabled environment — role changed to Spark Firewall in the manual Add
Firewall modal, or a Spark row during Discover Firewalls import — the operator
is asked which of two situations applies, then resolved to a credential set
either way:

1. **Direct** — they already have working admin creds on the box, used as-is.
2. **Bootstrap** — they'll use existing admin creds out-of-band (in clish,
   themselves) to create a brand-new dedicated account for this tool.

Both scenarios end at the same place: a credential set assigned to the
firewall, picked from the store or created inline with `require_expert: true`
(see [[credential-sets]]) since Spark patching needs an expert password. The
scenario choice only changes the modal's copy and whether the *existing*
`#fw-spark-bootstrap-modal`/`preview_spark_admin_commands` flow (unchanged —
renders the `add administrator` clish line from whatever credential set is
*currently assigned* to the named firewall) auto-opens right after a
successful add, for the operator to paste into clish themselves.

## Where it lives
- `web/app.py`: no new routes — reuses `PUT /api/env/{env}/credentials`
  (`require_expert` flag) and `POST /api/environments/{env}/firewalls`
  (`FirewallIn.credential_set`, already atomic-looking) exactly as-is.
- `index.html`: `#fw-spark-cred-modal` — scenario radios + a credential-set
  `<select>` defaulting to "+ Create new credential set", with inline fields
  shown only in that case.
- `app.js`: `resolveSparkFirewallCredentials(targetLabel)` →
  `Promise<{credentialSetName, scenario} | null>`, shared by both entry
  points. `saveSparkCredential(...)` mirrors `saveBootstrapCredential`
  (same `promptOverwriteChoice` collision handling) but always passes
  `require_expert: true` and actually checks `job.status === "succeeded"`
  before reporting success (an existing gap in `saveBootstrapCredential`
  itself, deliberately left alone — out of scope for this batch).
  - Manual Add Firewall: a `change` listener on `#fm-role`, active only in
    add mode (`editingFirewallName === null`), calls it when the value
    becomes `spark_firewall`; on resolve it just calls the existing
    `populateFirewallCredSelect(name)` so `#fm-cred-select` reflects the
    pick — the submit handler needed zero changes for assignment. A
    `pendingSparkBootstrap` flag (reset on any role change away from Spark,
    or when the Add/Edit modal opens) makes the submit handler open
    `#fw-spark-bootstrap-modal` after a successful add.
  - Discover Firewalls import: inside the existing per-row `for` loop, Spark
    rows call it instead of inheriting `discoverFwPrimaryCredSet` like every
    other imported firewall; a bootstrap-scenario row `await`s
    `openSparkBootstrapModal` before continuing to the next row.

## Gotcha: modal-on-modal needs an explicit z-index
Every `.modal` shares `z-index: 100`; with no tiebreak, stacking falls back
to **DOM order**, not JS-visibility order. `#fw-spark-cred-modal` opens while
`#firewall-modal` or `#discover-firewalls-modal` is still open, and
`#fw-spark-bootstrap-modal` opens while `#discover-firewalls-modal` is still
open (the per-row import case) — but both sit *earlier* in `index.html` than
those two, so without a fix the outer modal painted on top and silently ate
clicks meant for the inner one (caught via a live Playwright smoke test, not
by pytest — nothing here is server-side). Fixed with explicit overrides in
`app.css`: `#fw-spark-cred-modal, #fw-spark-bootstrap-modal { z-index: 101; }`
and `#prov-overwrite-modal { z-index: 102; }` (the collision-choice modal
`saveSparkCredential` can trigger while `#fw-spark-cred-modal` is open).
**Any future modal opened from inside another modal needs the same
treatment** — don't rely on DOM position matching runtime nesting.
