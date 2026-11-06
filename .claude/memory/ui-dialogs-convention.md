---
name: ui-dialogs-convention
description: Web UI never uses native alert/confirm/prompt; use confirmDialog() for yes/no gates and toast(msg, kind) for messages
metadata:
  type: project
---

Since v1.2.0 the web UI uses **no native browser dialogs**. Operator-directed
2026-10-02 (closed the "standardize confirmations to the modal UI" punch-list
item).

- **Yes/no gates:** `await confirmDialog({ title, message, confirmLabel, danger })`
  in `app.js`, backed by the shared `#confirm-modal`. Resolves true only on the
  action button. `danger: true` makes the button red and puts initial focus on
  Cancel. Escape cancels only the confirmation (capture-phase handler), not the
  modal it was opened from.
- **Messages:** `toast(message, kind)` with kind `"info"` (default, fades after
  6s, hover holds it), `"warn"` or `"error"` (both sticky until dismissed). Any
  failure toast must pass `"error"` so it can't be missed.
- **Layers:** `#confirm-modal` is z-index 200 and `#toast-stack` 300, above every
  other modal (100-102; see [[spark-firewall-credential-scenarios]] for why
  nested modals need explicit ranks).
- Purpose-built gates stay separate: typed-name uninstall, the connect-primary
  and API-repair command previews, the Spark major-version warning.

**Why:** native dialogs froze the page (job polling stopped), couldn't carry
danger styling, and browsers let users suppress them, which silently drops
alert() error messages.

**How to apply:** never add `alert(`, `confirm(` or `prompt(` to the UI. pytest
cannot see this layer; verify UI changes with a Playwright smoke test against a
local instance.
