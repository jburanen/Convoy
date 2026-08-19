---
name: table-reload-race
description: loadServers()/loadFirewalls() (and any future table reloader) must guard against overlapping calls with a bump-token, not just clear-then-append
metadata:
  type: project
---

`loadFirewalls()`/`loadServers()` (`app.js`) rebuild their `<table>` from
scratch on every call: clear the `tbody`, `await` a few API calls, then
append fresh rows. If two calls overlap — the action that triggered a reload
(e.g. removing a firewall) landing at the same moment as an unrelated
`pollJobs()`-triggered reload, or two calls to either function racing each
other directly — **both** clear the tbody and **both** later append their
own full row set, so every row silently doubles (or triples/quadruples with
more overlapping callers) until a manual page refresh.

**First fixed 2026-07-23** (v0.35.1) for one specific instance: `pollJobs()`
itself used to call both `loadServers()` and `loadFirewalls()` on the same
tick, when `loadServers()` already calls `loadFirewalls()` at its own tail —
fixed by never calling `loadFirewalls()` directly from `pollJobs()`, only
`loadServers()`. **Recurred 2026-08-18** (operator-reported: removing a
firewall duplicated the whole table) via a *different* pair of callers — the
firewall-remove handler's own `loadFirewalls()` call racing a
`pollJobs()`-triggered reload — because the 2026-07-23 fix addressed that one
call-site pairing, not the underlying reentrancy problem.

**Fixed properly this time** with a bump-token guard in both functions: each
call increments a module-level counter and captures its own value; after the
`await`s, if the counter has moved on (a newer call started), the stale call
returns without touching the DOM at all — `tbody.replaceChildren()` and the
render loop also moved to *after* that check, not before it. Verified live
with Playwright: forcing `Promise.all([loadFirewalls(), loadFirewalls(),
loadFirewalls()])` against the unfixed code tripled a single row (1→3); the
fixed code holds at 1→1.

**Apply this pattern to any future table-reload function of this shape**
(clear + rebuild from an async fetch) — a naive clear-then-append is only
safe if the function can never be called twice in overlapping fashion, which
in this app's polling + user-action model is not a safe assumption to make
even once, let alone leave unguarded a second time.
