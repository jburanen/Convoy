/*
  chkp-cpuse-orch — UI logic.
  Plain JS on purpose: no framework, no build step. All markup lives in
  index.html <template> elements; this file only fills in data and wires events.

  Layout of this file:
    1. tiny fetch helper
    2. status chips
    3. servers section (list, live CPUSE state, import/install actions)
    4. packages section (upload, list, delete)
    5. credentials section (save, list, delete)
    6. jobs section (list, expandable progress log, cancel, polling)
*/

"use strict";

/* ---------- 1. fetch helper ---------- */

async function api(path, options = {}) {
  const resp = await fetch(path, options);
  if (resp.status === 401) {
    // Session expired (server enforces the idle window). Clear cached creds and
    // bounce to the login page rather than surfacing a confusing error.
    handleSessionExpired();
    throw new Error("session expired");
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail ?? detail; } catch { /* not json */ }
    throw new Error(detail);
  }
  return resp.status === 204 ? null : resp.json();
}

function el(tplId) {
  // Clone the first element of a <template> from index.html.
  return document.getElementById(tplId).content.firstElementChild.cloneNode(true);
}

function toast(message) {
  // Minimal feedback channel; replace with something fancier if you like.
  alert(message);
}

function fmtBytes(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(0) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(0) + " MB";
  if (n >= 1e3) return (n / 1e3).toFixed(0) + " kB";
  return n + " B";
}

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleDateString() : "";
}

/* ---------- 1b. authentication / session ---------- */

// Whether LDAP auth is active (from /api/auth/config). When false the tool runs
// open and credential storage is not permitted (server-enforced too).
let authEnabled = false;
let _redirectingToLogin = false;
let _idleTimer = null;
let _idleMs = 30 * 60 * 1000; // overridden by the server's configured window

// End the session locally: wipe any credentials cached in this tab, then go to
// the login page. Used on explicit logout, idle timeout, and 401 from the API.
function handleSessionExpired() {
  if (_redirectingToLogin) return;
  _redirectingToLogin = true;
  cacheClearCreds();
  window.location.replace("/login.html");
}

async function logout() {
  cacheClearCreds(); // clear temporarily cached credentials before leaving
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } catch { /* best effort — the local redirect still ends the session here */ }
  handleSessionExpired();
}

function resetIdleTimer() {
  if (!authEnabled) return;
  if (_idleTimer) clearTimeout(_idleTimer);
  _idleTimer = setTimeout(logout, _idleMs);
}

async function initAuth() {
  let cfg;
  try { cfg = await api("/api/auth/config"); } catch { return; }
  authEnabled = !!cfg.auth_enabled;
  if (!authEnabled) return;
  if (cfg.idle_minutes > 0) _idleMs = cfg.idle_minutes * 60 * 1000;

  try {
    const me = await api("/api/auth/me");
    if (me.username) {
      document.getElementById("session-user").textContent = `Signed in as ${me.username}`;
    }
  } catch { /* header label is best-effort */ }
  document.getElementById("session-row").classList.remove("hidden");
  document.getElementById("logout-btn").addEventListener("click", logout);

  // Any of these gestures counts as activity and restarts the idle countdown.
  for (const evName of ["mousemove", "keydown", "click", "scroll", "touchstart"]) {
    document.addEventListener(evName, resetIdleTimer, { passive: true });
  }
  resetIdleTimer();
}

/* ---------- 1a. environments ---------- */

// Independent management environments (own inventory + credentials each).
// The picker in the header scopes servers, credentials, and CDT; packages
// and the underlying storage are shared. Selection sticks via localStorage.
let currentEnv = localStorage.getItem("currentEnv") || null;

// Per-environment "stores credentials?" flag, refreshed by loadEnvironments.
// When false, SSH actions prompt for credentials (kept in memory only).
let envStorage = {}; // name -> boolean

// Per-environment MDS-vs-SMS kind, refreshed by loadEnvironments — used to
// show/hide the Domain picker in the discover-firewalls modal.
let envIsMds = {}; // name -> boolean

function storageEnabled(name = currentEnv) {
  return envStorage[name] !== false; // unknown → assume enabled (safe default)
}

// Per-environment default for the Management tab's "skip verify" install
// checkbox, refreshed by loadEnvironments — see loadServers().
let envSkipVerifyDefault = {}; // name -> boolean

// Sentinel picker value that opens the new-environment modal instead of
// selecting an environment.
const ENV_MANAGE = "__manage__";

function envUrl(path) {
  return `/api/env/${encodeURIComponent(currentEnv)}${path}`;
}

/* ---------- 1a-cred-prompt. inline credentials (storage-disabled envs) ---------- */

// When the current environment doesn't store credentials, every SSH-backed
// action first collects them here. They ride along with that one request and
// live only in memory server-side until the operation finishes.
let _credResolve = null;

// Optional per-tab credential cache (opt-in "Remember" in the prompt). It lives
// ONLY in this JS variable — never localStorage/sessionStorage, never the
// server — so it dies on tab close or reload. Purely a convenience so the
// operator isn't re-typing on every action; the server still holds credentials
// in memory only for the life of each job. Entries are short-lived and keyed by
// environment + host, and are evicted when an action using them fails.
const CRED_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const credCache = new Map(); // key: JSON.stringify([env, host]) -> { creds, expires }

function _cacheKey(host) { return JSON.stringify([currentEnv, host]); }

function cacheGetCreds(host) {
  const hit = credCache.get(_cacheKey(host));
  if (!hit) return null;
  if (Date.now() > hit.expires) { credCache.delete(_cacheKey(host)); updateCredCacheNote(); return null; }
  return hit.creds;
}
function cachePutCreds(host, creds) {
  credCache.set(_cacheKey(host), { creds, expires: Date.now() + CRED_CACHE_TTL_MS });
  updateCredCacheNote();
}
function cacheEvictCreds(host) {
  if (credCache.delete(_cacheKey(host))) updateCredCacheNote();
}
function cacheClearCreds() {
  if (credCache.size) { credCache.clear(); updateCredCacheNote(); }
}

// Prune expired entries, then show/hide the header note with the live count.
function updateCredCacheNote() {
  for (const [k, v] of credCache) if (Date.now() > v.expires) credCache.delete(k);
  const note = document.getElementById("cred-cache-note");
  const n = credCache.size;
  note.classList.toggle("hidden", n === 0);
  if (n) {
    document.getElementById("cred-cache-text").textContent =
      `🔑 ${n} credential${n === 1 ? "" : "s"} cached in this tab (session only)`;
  }
}

function promptCredentials(host, purpose) {
  const modal = document.getElementById("cred-modal");
  document.getElementById("cred-modal-title").textContent = `Credentials for ${host}`;
  document.getElementById("cred-modal-hint").textContent =
    `This environment doesn't store credentials. Enter them to ${purpose} on ${host} — ` +
    "kept in memory only until the operation finishes, never written to disk.";
  for (const id of ["cm-password", "cm-key", "cm-expert"]) document.getElementById(id).value = "";
  document.getElementById("cm-remember").checked = false;
  document.getElementById("cm-more").open = false;
  modal.classList.remove("hidden");
  document.getElementById("cm-password").focus();
  return new Promise((resolve) => { _credResolve = resolve; });
}

function closeCredModal(result) {
  document.getElementById("cred-modal").classList.add("hidden");
  const resolve = _credResolve;
  _credResolve = null;
  if (resolve) resolve(result);
}

// Returns a body fragment to spread into the request: {} for a storage-enabled
// environment, { credentials: [...] } once collected (from cache or a prompt),
// or null if the operator cancelled. On failure, callers evict via
// cacheEvictCreds(host) so a stale cached password re-prompts next time.
async function operationCredentials(host, purpose) {
  if (storageEnabled()) return {};
  const cached = cacheGetCreds(host);
  if (cached) return { credentials: cached };
  const result = await promptCredentials(host, purpose);
  if (result === null) return null;
  if (result.remember) cachePutCreds(host, result.creds);
  return { credentials: result.creds };
}

document.getElementById("cred-modal-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fields = [
    ["ssh_password", document.getElementById("cm-password").value],
    ["ssh_private_key", document.getElementById("cm-key").value],
    ["expert_password", document.getElementById("cm-expert").value],
  ];
  const creds = fields.filter(([, s]) => s).map(([kind, secret]) => ({ kind, secret }));
  if (!creds.some((c) => c.kind === "ssh_password" || c.kind === "ssh_private_key")) {
    toast("Enter an SSH password or a private key.");
    return;
  }
  closeCredModal({ creds, remember: document.getElementById("cm-remember").checked });
});
document.getElementById("cred-modal-cancel").addEventListener("click", () => closeCredModal(null));
document.getElementById("cred-modal-close").addEventListener("click", () => closeCredModal(null));
document.getElementById("cred-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "cred-modal") closeCredModal(null); // backdrop click cancels
});
document.getElementById("cred-cache-forget").addEventListener("click", () => {
  cacheClearCreds();
  toast("Session credentials cleared from this tab.");
});

async function loadEnvironments() {
  const picker = document.getElementById("env-picker");
  const envs = await api("/api/environments");
  envStorage = Object.fromEntries(envs.map((e) => [e.name, e.credential_storage_enabled]));
  envSkipVerifyDefault = Object.fromEntries(envs.map((e) => [e.name, e.skip_verify_by_default]));
  envIsMds = Object.fromEntries(envs.map((e) => [e.name, e.is_mds]));
  picker.replaceChildren();
  if (!envs.length) {
    // Placeholder so the manage entry is never the pre-selected option — a
    // <select> fires no change event when its current option is re-chosen,
    // which would make "New Environment…" dead with zero environments.
    const placeholder = new Option("— no environments —", "");
    placeholder.disabled = true;
    picker.appendChild(placeholder);
  }
  for (const env of envs) {
    picker.appendChild(new Option(env.name, env.name));
  }
  // Always-present entry opening the manage modal (create + rename; servers
  // and deletion are managed on the Provisioning tab).
  const manage = new Option("Manage Environments…", ENV_MANAGE);
  picker.appendChild(manage);

  if (!envs.some((e) => e.name === currentEnv)) {
    currentEnv = envs.length ? envs[0].name : null;
  }
  picker.value = currentEnv ?? "";
  // Picker is always shown now (it hosts the manage entry even with one env).
  document.getElementById("env-row").classList.remove("hidden");
  return envs;
}

async function selectEnvironment(name) {
  currentEnv = name;
  localStorage.setItem("currentEnv", currentEnv);
  document.getElementById("env-picker").value = name;
  // Reload everything env-scoped; clear CDT state from the previous env.
  cdtCandidates = null;
  renderCdtCandidates();
  document.getElementById("cdt-status").textContent = "";
  await Promise.all([loadServers(), loadPackages(), loadCredentialSets(), refreshStatus()]);
  updateProvisionCollapse();
}

document.getElementById("env-picker").addEventListener("change", async (ev) => {
  if (ev.target.value === ENV_MANAGE) {
    ev.target.value = currentEnv ?? ""; // back to placeholder / current env
    openEnvModal();
    return;
  }
  if (!ev.target.value) return; // the disabled placeholder can't select anything
  await selectEnvironment(ev.target.value);
});

/* ---------- 1a-welcome. first-run dialog ---------- */

// On a brand-new deployment — exactly one environment named "default" with no
// servers, and no credentials or packages anywhere — offer renaming the default
// environment before any data gets attached to its name (uses the real rename
// endpoint, same as the Manage Environments modal).
//
// Only an EXPLICIT choice (Rename / Keep "default") is remembered in
// localStorage; closing via ✕, backdrop, or Escape merely hides the dialog for
// this page load, so an accidental click can't suppress it forever.
const WELCOME_KEY = "welcomeChoiceMade"; // new key: old accidental "welcomeDismissed" flags are ignored

async function maybeShowWelcome(envs) {
  if (localStorage.getItem(WELCOME_KEY)) return;
  if (envs.length !== 1 || envs[0].name !== "default" || envs[0].management_servers !== 0) return;
  try {
    if ((await api("/api/packages")).length) return;
    if ((await api("/api/env/default/credentials")).length) return;
  } catch { /* locked credential store — still clearly a fresh deployment */ }
  document.getElementById("welcome-modal").classList.remove("hidden");
  document.getElementById("welcome-name").focus();
}

function hideWelcome() {
  // Soft close: shows again on the next load while the deployment stays fresh.
  document.getElementById("welcome-modal").classList.add("hidden");
}

function dismissWelcome() {
  // Explicit choice made: never prompt this browser again.
  localStorage.setItem(WELCOME_KEY, "1");
  hideWelcome();
}

document.getElementById("welcome-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = document.getElementById("welcome-name").value.trim();
  if (!name || name === "default") { dismissWelcome(); return; }
  try {
    const renamed = await api("/api/environments/default/rename", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    dismissWelcome();
    await loadEnvironments();
    await selectEnvironment(renamed.name);
  } catch (e) { toast("Rename failed: " + e.message); }
});
document.getElementById("welcome-keep").addEventListener("click", dismissWelcome);
document.getElementById("welcome-close").addEventListener("click", hideWelcome);
document.getElementById("welcome-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "welcome-modal") hideWelcome(); // backdrop click
});

/* ---------- 1a-modal. manage environments (create + rename) ---------- */

// The modal creates and renames environments; servers and deletion are managed
// on the Provisioning tab (section 1a-prov below), scoped to the picker's
// selection. A rename moves servers, credentials, and job history atomically.

function openEnvModal() {
  document.getElementById("env-modal").classList.remove("hidden");
  renderEnvManageList();
}
function closeEnvModal() {
  document.getElementById("env-modal").classList.add("hidden");
}

async function renderEnvManageList() {
  const list = document.getElementById("env-manage-list");
  const envs = await api("/api/environments");
  list.replaceChildren();
  for (const env of envs) {
    const row = el("tpl-env-manage-row");
    const input = row.querySelector(".env-rename-input");
    input.value = env.name;
    row.querySelector(".env-rename-btn").addEventListener("click", async () => {
      const newName = input.value.trim();
      if (!newName || newName === env.name) return;
      try {
        const resp = await api(`/api/environments/${encodeURIComponent(env.name)}/rename`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: newName }),
        });
        cacheClearCreds(); // env name changed — cached keys are now stale
        const wasCurrent = currentEnv === env.name;
        await loadEnvironments();
        if (wasCurrent) await selectEnvironment(resp.name); // refresh env-scoped views
        await renderEnvManageList();
      } catch (e) { toast("Rename failed: " + e.message); }
    });

    // Per-row delete: removes this environment (its servers AND stored credentials).
    row.querySelector(".env-delete-btn").addEventListener("click", async () => {
      if (!confirm(
        `Delete environment "${env.name}"?\n\nIts management-server list AND all ` +
        "stored credentials for it are permanently removed. This cannot be undone. " +
        "Job logs are NOT deleted — they're kept for audit purposes."
      )) return;
      try {
        await api(`/api/environments/${encodeURIComponent(env.name)}`, { method: "DELETE" });
        const wasCurrent = currentEnv === env.name;
        if (wasCurrent) {
          cacheClearCreds(); // deleted the active env — nothing cached should linger
          currentEnv = null;
          localStorage.removeItem("currentEnv");
        }
        await loadEnvironments(); // falls back to the first remaining environment
        if (currentEnv) {
          await selectEnvironment(currentEnv);
        } else {
          await Promise.all([loadServers(), loadCredentialSets(), refreshStatus()]);
        }
        await renderEnvManageList();
      } catch (e) { toast("Delete failed: " + e.message); }
    });

    // MDS-kind toggle. An environment is always entirely SMS or entirely
    // Multi-Domain — this decides which command variants (discovery, etc.) run
    // against every server in it, instead of guessing per-request.
    const mdsToggle = row.querySelector(".env-mds-input");
    mdsToggle.checked = env.is_mds;
    mdsToggle.addEventListener("change", async () => {
      const isMds = mdsToggle.checked;
      try {
        await api(`/api/environments/${encodeURIComponent(env.name)}/kind`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ is_mds: isMds }),
        });
        await loadEnvironments();
        await renderEnvManageList();
      } catch (e) {
        mdsToggle.checked = !isMds; // revert on failure
        toast("Could not change environment kind: " + e.message);
      }
    });

    // Credential-storage toggle. Disabling purges any stored credentials, so we
    // confirm first; the note reminds the operator what each mode means.
    const toggle = row.querySelector(".env-storage-input");
    const note = row.querySelector(".env-storage-note");
    toggle.checked = env.credential_storage_enabled;
    if (!authEnabled && !env.credential_storage_enabled) {
      // Storing secrets requires an auth gate — enabling is blocked server-side.
      toggle.disabled = true;
      note.textContent = "Configure LDAP authentication to allow credential storage";
    } else {
      note.textContent = env.credential_storage_enabled
        ? "Credentials stored encrypted at rest"
        : "Credentials entered and cached for duration of session";
    }
    toggle.addEventListener("change", async () => {
      const enable = toggle.checked;
      if (!enable && !confirm(
        `Disable credential storage for "${env.name}"?\n\n` +
        "Any credentials already stored for this environment are permanently " +
        "deleted, and future actions will prompt for credentials each time."
      )) { toggle.checked = true; return; }
      try {
        await api(`/api/environments/${encodeURIComponent(env.name)}/credential-storage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: enable }),
        });
        cacheClearCreds(); // storage mode changed — drop any cached session creds
        await loadEnvironments();
        if (env.name === currentEnv) await selectEnvironment(currentEnv); // refresh views
        await renderEnvManageList();
      } catch (e) {
        toggle.checked = !enable; // revert on failure
        toast("Could not change credential storage: " + e.message);
      }
    });

    // "Skip verify" default. Purely a UI convenience for environments where
    // `installer verify` chronically fails for reasons unrelated to whether
    // the install itself would succeed — no confirm needed, it never skips
    // verify on its own.
    const skipVerifyToggle = row.querySelector(".env-skip-verify-input");
    skipVerifyToggle.checked = env.skip_verify_by_default;
    skipVerifyToggle.addEventListener("change", async () => {
      const skip = skipVerifyToggle.checked;
      try {
        await api(`/api/environments/${encodeURIComponent(env.name)}/skip-verify-default`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ skip_verify_by_default: skip }),
        });
        await loadEnvironments();
        if (env.name === currentEnv) await loadServers(); // re-check existing rows' boxes
      } catch (e) {
        skipVerifyToggle.checked = !skip; // revert on failure
        toast("Could not change skip-verify default: " + e.message);
      }
    });
    list.appendChild(row);
  }
  if (!envs.length) {
    document.getElementById("env-add-name").focus();
  }
}

document.getElementById("env-modal-close").addEventListener("click", closeEnvModal);
document.getElementById("env-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "env-modal") closeEnvModal(); // click on backdrop closes
});
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape") return;
  closeCredModal(null); // cancels a pending credential prompt (no-op otherwise)
  closeEnvModal();
  closeCredAddModal();
  closeDiscoverModal();
  closePrimaryModal();
  closeServerModal();
  hideWelcome(); // soft close — the welcome dialog returns next load if still fresh
});

document.getElementById("env-add-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("env-add-name");
  const mdsInput = document.getElementById("env-add-is-mds");
  try {
    const created = await api("/api/environments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: input.value, is_mds: mdsInput.checked }),
    });
    input.value = "";
    mdsInput.checked = false;
    closeEnvModal();
    await loadEnvironments();
    await selectEnvironment(created.name); // server-normalized (trimmed) name
    // Land where the new environment's servers are added.
    selectTab("provisioning");
    history.replaceState(null, "", "#tab-provisioning");
  } catch (e) { toast("Create failed: " + e.message); }
});

/* ---------- 1a-prov. environment management (Provisioning tab) ---------- */

// Shared add/update path for the Connect-to-Primary modal and the Add/Edit
// server modal below.
async function addServer({ name, address, role, ssh_user, ssh_port }) {
  await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, address, role, ssh_user, ssh_port }),
  });
}

/* ---------- 1b. add/edit server (modal) ---------- */

// One modal handles both: "Manually add a server" opens it empty with Name
// editable; each row's Edit button opens it prefilled with Name locked (add/
// update is upsert-by-name, so changing it would create a new server rather
// than rename this one).
// Storage-enabled environments pick an SSH identity from a stored credential
// set (no free-text username — the set's ssh_username drives it); storage-
// disabled environments have no sets to pick from, so they type a username.
async function populateServerCredSelect(assignedSetName) {
  const enabled = storageEnabled();
  document.getElementById("sm-user-label").classList.toggle("hidden", enabled);
  document.getElementById("sm-cred-label").classList.toggle("hidden", !enabled);
  if (!enabled) return;
  const select = document.getElementById("sm-cred-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  const sets = await fetchCredentialSets();
  for (const set of sets) {
    const opt = document.createElement("option");
    opt.value = set.name;
    opt.textContent = set.name;
    opt.dataset.sshUser = set.ssh_username || "";
    select.appendChild(opt);
  }
  select.value = assignedSetName || "";
}

async function openAddServerModal() {
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  document.getElementById("server-form").reset();
  document.getElementById("sm-name").disabled = false;
  document.getElementById("server-modal-title").textContent = "Add server";
  document.getElementById("server-modal-submit").textContent = "Add server";
  await populateServerCredSelect();
  document.getElementById("server-modal").classList.remove("hidden");
  document.getElementById("sm-name").focus();
}
async function openEditServerModal(srv, assignedSetName) {
  document.getElementById("sm-name").value = srv.name;
  document.getElementById("sm-name").disabled = true;
  document.getElementById("sm-address").value = srv.address;
  document.getElementById("sm-role").value = srv.role;
  document.getElementById("sm-user").value = srv.ssh_user;
  document.getElementById("sm-port").value = srv.ssh_port;
  document.getElementById("server-modal-title").textContent = `Edit ${srv.name}`;
  document.getElementById("server-modal-submit").textContent = "Save changes";
  await populateServerCredSelect(assignedSetName);
  document.getElementById("server-modal").classList.remove("hidden");
  document.getElementById("sm-address").focus();
}
function closeServerModal() {
  document.getElementById("server-modal").classList.add("hidden");
}

document.getElementById("add-server-btn").addEventListener("click", openAddServerModal);
document.getElementById("server-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) return;
  const name = document.getElementById("sm-name").value.trim();
  const credSelect = document.getElementById("sm-cred-select");
  const credSet = storageEnabled() ? credSelect.value : null;
  const sshUser = storageEnabled()
    ? credSelect.selectedOptions[0]?.dataset.sshUser || "admin"
    : document.getElementById("sm-user").value.trim() || "admin";
  try {
    await addServer({
      name,
      address: document.getElementById("sm-address").value.trim(),
      role: document.getElementById("sm-role").value,
      ssh_user: sshUser,
      ssh_port: Number(document.getElementById("sm-port").value) || 22,
    });
    if (storageEnabled()) {
      await api(envUrl(`/servers/${encodeURIComponent(name)}/credential`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ set: credSet || null }),
      });
    }
    closeServerModal();
    await Promise.all([loadServers(), refreshStatus()]);
  } catch (e) { toast("Save failed: " + e.message); }
});
document.getElementById("server-modal-close").addEventListener("click", closeServerModal);
document.getElementById("server-modal-cancel").addEventListener("click", closeServerModal);
document.getElementById("server-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "server-modal") closeServerModal(); // backdrop closes
});

/* ---------- 1c-primary. connect to primary (empty-inventory modal) ---------- */

async function openPrimaryModal() {
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  document.getElementById("primary-form").reset();
  await populatePrimaryCredSelect();
  document.getElementById("primary-modal").classList.remove("hidden");
  document.getElementById("pm-name").focus();
}
function closePrimaryModal() {
  document.getElementById("primary-modal").classList.add("hidden");
}

// Storage-enabled environments pick an SSH identity from a stored credential
// set (no free-text username — the set's ssh_username drives it); storage-
// disabled environments have no sets to pick from, so they type a username.
async function populatePrimaryCredSelect() {
  const enabled = storageEnabled();
  document.getElementById("pm-user-label").classList.toggle("hidden", enabled);
  document.getElementById("pm-cred-label").classList.toggle("hidden", !enabled);
  if (!enabled) return;
  const select = document.getElementById("pm-cred-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  const sets = await fetchCredentialSets();
  for (const set of sets) {
    const opt = document.createElement("option");
    opt.value = set.name;
    opt.textContent = set.name;
    opt.dataset.sshUser = set.ssh_username || "";
    select.appendChild(opt);
  }
}

document.getElementById("primary-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) return;
  const name = document.getElementById("pm-name").value.trim();
  const credSelect = document.getElementById("pm-cred-select");
  const credSet = storageEnabled() ? credSelect.value : null;
  const sshUser = storageEnabled()
    ? credSelect.selectedOptions[0]?.dataset.sshUser || "admin"
    : document.getElementById("pm-user").value.trim() || "admin";
  try {
    await addServer({
      name,
      address: document.getElementById("pm-address").value.trim(),
      role: document.getElementById("pm-role").value,
      ssh_user: sshUser,
      ssh_port: Number(document.getElementById("pm-port").value) || 22,
    });
    if (credSet) {
      await api(envUrl(`/servers/${encodeURIComponent(name)}/credential`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ set: credSet }),
      });
    }
    closePrimaryModal();
    await Promise.all([loadServers(), refreshStatus()]);
    // Offer discovery from the just-defined primary (operator can Close to keep
    // adding manually — the Discover button stays available either way).
    openDiscoverModal(name);
  } catch (e) { toast("Save failed: " + e.message); }
});

document.getElementById("primary-close").addEventListener("click", closePrimaryModal);
document.getElementById("primary-cancel").addEventListener("click", closePrimaryModal);
document.getElementById("primary-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "primary-modal") closePrimaryModal(); // backdrop closes
});

/* ---------- 1c. discover servers ---------- */

// The discover-from primary's SSH identity, captured when a scan runs so
// imported servers can inherit it (same credential set, or same typed
// username in a storage-disabled environment) instead of defaulting to admin.
let discoverPrimarySshUser = "admin";
let discoverPrimaryCredSet = null;

// Open the Discover modal, populating the "Discover from" picker with the
// environment's Primary SMS/MDS servers only — discovery needs a primary,
// not a secondary or dedicated Log/SmartEvent server. `preselectName`
// pre-picks the just-added primary.
async function openDiscoverModal(preselectName) {
  if (!currentEnv) { toast("Create an environment and add a primary server first."); return; }
  let servers = [];
  try {
    servers = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`);
  } catch (e) { toast("Could not load servers: " + e.message); return; }
  const primaries = servers.filter((s) => s.role === "primary_sms" || s.role === "primary_mds");
  if (!primaries.length) {
    toast("Add a Primary SMS or Primary MDS server before discovering the rest.");
    return;
  }
  const select = document.getElementById("discover-primary");
  select.replaceChildren();
  for (const s of primaries) {
    const opt = document.createElement("option");
    opt.value = s.name;
    opt.textContent = `${s.name} (${roleLabel(s.role)})`;
    select.appendChild(opt);
  }
  if (preselectName) select.value = preselectName;
  resetDiscoverResults();
  document.getElementById("discover-modal").classList.remove("hidden");
}

function resetDiscoverResults() {
  document.getElementById("discover-status").textContent = "";
  const warn = document.getElementById("discover-warnings");
  warn.classList.add("hidden");
  warn.replaceChildren();
  const table = document.getElementById("discover-table");
  table.classList.add("hidden");
  table.querySelector("tbody").replaceChildren();
  document.getElementById("discover-import").disabled = true;
}

function closeDiscoverModal() {
  document.getElementById("discover-modal").classList.add("hidden");
}

document.getElementById("discover-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const primary = document.getElementById("discover-primary").value;
  if (!primary || !currentEnv) return;
  resetDiscoverResults();
  const status = document.getElementById("discover-status");
  status.textContent = `Scanning from ${primary}…`;
  const runBtn = document.getElementById("discover-run");
  runBtn.disabled = true;
  try {
    // Capture the primary's own SSH identity so imported servers can inherit
    // it below, instead of silently defaulting to admin.
    const editableServers = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`);
    const primarySrv = editableServers.find((s) => s.name === primary);
    discoverPrimarySshUser = primarySrv ? primarySrv.ssh_user : "admin";
    discoverPrimaryCredSet = null;
    if (storageEnabled()) {
      const servers = await api(envUrl("/servers"));
      const match = servers.find((s) => s.name === primary);
      discoverPrimaryCredSet = match ? match.credential_set : null;
    }
    const result = await api(`/api/environments/${encodeURIComponent(currentEnv)}/discover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ primary }),
    });
    renderDiscoverResults(result);
  } catch (e) {
    status.textContent = "Discovery failed: " + e.message;
  } finally {
    runBtn.disabled = false;
  }
});

function renderDiscoverResults(result) {
  const status = document.getElementById("discover-status");
  const warn = document.getElementById("discover-warnings");
  for (const w of result.warnings || []) {
    warn.classList.remove("hidden");
    const line = document.createElement("div");
    line.textContent = "⚠ " + w;
    warn.appendChild(line);
  }
  const servers = result.servers || [];
  if (!servers.length) {
    status.textContent = "No additional servers found.";
    return;
  }
  const already = servers.filter((s) => s.already_in_inventory).length;
  status.textContent =
    `Found ${servers.length} server${servers.length === 1 ? "" : "s"}` +
    (already ? ` (${already} already in inventory)` : "") +
    ". Review roles, then import the ones you want.";
  const table = document.getElementById("discover-table");
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren();
  for (const s of servers) {
    const row = el("tpl-discovered-row");
    const pick = row.querySelector(".disc-pick");
    const name = row.querySelector(".disc-name");
    const address = row.querySelector(".disc-address");
    const roleSel = row.querySelector(".disc-role");
    const note = row.querySelector(".disc-note");
    name.value = s.name;
    address.value = s.address;
    roleSel.value = s.role;
    let noteText = s.note || "";
    if (s.already_in_inventory) {
      noteText = "already in inventory";
      pick.checked = false;
      pick.disabled = name.disabled = address.disabled = roleSel.disabled = true;
      row.classList.add("disc-existing");
    } else {
      pick.checked = true;
      if (s.needs_review) {
        noteText = noteText ? noteText + " — review" : "review the detected role";
        row.classList.add("disc-review");
      }
    }
    note.textContent = noteText;
    tbody.appendChild(row);
  }
  table.classList.remove("hidden");
  document.getElementById("discover-import").disabled =
    servers.length === already; // nothing new to import
}

document.getElementById("discover-import").addEventListener("click", async () => {
  const rows = [...document.querySelectorAll("#discover-table tbody tr")];
  const picks = rows.filter((r) => {
    const pick = r.querySelector(".disc-pick");
    return pick.checked && !pick.disabled;
  });
  if (!picks.length) { toast("Nothing selected to import."); return; }
  const importBtn = document.getElementById("discover-import");
  importBtn.disabled = true;
  let ok = 0;
  const failed = [];
  for (const r of picks) {
    const name = r.querySelector(".disc-name").value.trim();
    const address = r.querySelector(".disc-address").value.trim();
    const role = r.querySelector(".disc-role").value;
    if (!name || !address) { failed.push(name || address || "(unnamed)"); continue; }
    try {
      // Inherit the discover-from primary's SSH identity: same credential set
      // in a storage-enabled environment, same typed username otherwise.
      await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, address, role, ssh_user: discoverPrimarySshUser }),
      });
      if (storageEnabled() && discoverPrimaryCredSet) {
        await api(envUrl(`/servers/${encodeURIComponent(name)}/credential`), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ set: discoverPrimaryCredSet }),
        });
      }
      ok++;
    } catch (e) { failed.push(`${name}: ${e.message}`); }
  }
  await Promise.all([loadServers(), refreshStatus()]);
  if (failed.length) {
    toast(`Imported ${ok}. Failed: ${failed.join("; ")}`);
    importBtn.disabled = false;
  } else {
    closeDiscoverModal();
  }
});

// Dual-purpose button: with no servers it opens the Connect-to-Primary modal;
// once a primary exists it runs discovery (re-runnable anytime).
document.getElementById("discover-btn").addEventListener("click", () => {
  if (inventoryHasServers) openDiscoverModal();
  else openPrimaryModal();
});
document.getElementById("discover-close").addEventListener("click", closeDiscoverModal);
document.getElementById("discover-cancel").addEventListener("click", closeDiscoverModal);
document.getElementById("discover-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "discover-modal") closeDiscoverModal(); // backdrop click closes
});

/* ---------- 1b. tabs ---------- */

// Default tab: Provisioning when the inventory has no management servers yet,
// Management otherwise. Decided once at load (chooseDefaultTab); after that the
// user's clicks rule. Deep-linking works too: open /#tab-gateways etc.
let tabChosen = false;

function selectTab(name) {
  // Disabled/WIP tabs can't be opened — including via a #tab- deep link.
  const target = document.querySelector(`#tabs .tab-btn[data-tab="${name}"]`);
  if (target && target.disabled) return;
  for (const btn of document.querySelectorAll("#tabs .tab-btn")) {
    btn.classList.toggle("active", btn.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll(".tab-panel")) {
    panel.classList.toggle("active", panel.id === "tab-" + name);
  }
  // Un-dim the guide blurb for the active tab (normal muted text).
  for (const item of document.querySelectorAll("#tab-guide .tab-guide-item")) {
    item.classList.toggle("active", item.dataset.tab === name);
  }
  positionTabGuide();
  tabChosen = true;
}

// Slide the tab-guide row so the active tab's block centers under its tab title.
// The provisioning tab (left-most) is the exception: it keeps the bar at its
// natural left-edge-aligned position (translateX 0). Every other tab slides left
// by exactly the distance that brings its block's center under its tab's center.
let guideTranslate = 0;
function positionTabGuide() {
  const guide = document.getElementById("tab-guide");
  const viewport = document.getElementById("tab-guide-viewport");
  const activeItem = guide.querySelector(".tab-guide-item.active");
  const activeBtn = document.querySelector("#tabs .tab-btn.active");
  const firstItem = guide.querySelector(".tab-guide-item");
  if (!activeItem || !activeBtn || !firstItem) return;
  if (!guide.offsetParent) return; // hidden (narrow screens) — nothing to place

  // getBoundingClientRect() includes the current transform, so subtract it to
  // recover each block's natural (untranslated) center. Tab buttons never move.
  const centerOf = (el) => { const r = el.getBoundingClientRect(); return r.left + r.width / 2; };
  const naturalCenter = (el) => centerOf(el) - guideTranslate;

  // Provisioning stays left-aligned; others center under their tab (never sliding
  // right past the natural layout).
  const translate = activeItem === firstItem
    ? 0
    : Math.min(0, centerOf(activeBtn) - naturalCenter(activeItem));
  guideTranslate = translate;
  guide.style.transform = `translateX(${translate}px)`;
  viewport.classList.toggle("slid", translate < -1);
}

window.addEventListener("resize", positionTabGuide);
window.addEventListener("load", positionTabGuide); // reflow after fonts settle

function chooseDefaultTab(serverCount) {
  if (tabChosen) return; // user (or a #tab- link) already picked one
  selectTab(serverCount > 0 ? "management" : "provisioning");
}

function initTabs() {
  for (const btn of document.querySelectorAll("#tabs .tab-btn")) {
    btn.addEventListener("click", () => {
      selectTab(btn.dataset.tab);
      history.replaceState(null, "", "#tab-" + btn.dataset.tab);
    });
  }
  const fromHash = location.hash.match(/^#tab-(\w+)$/);
  if (fromHash && document.getElementById("tab-" + fromHash[1])) {
    selectTab(fromHash[1]);
  }
}

/* ---------- 2. status chips ---------- */

async function refreshStatus() {
  const box = document.getElementById("status-chips");
  box.replaceChildren();
  try {
    const s = await api("/api/status");
    document.getElementById("footer-version").textContent = "v" + s.version;
    document.getElementById("job-archive-hint").textContent = s.job_archive_path;
    // Chips are for warnings only (counts live on their own tabs).
    if (!s.credentials_unlocked) {
      addChip(box, "credential store LOCKED — set CHKP_CPUSE_MASTER_KEY and restart", "warn");
    }
  } catch (e) {
    addChip(box, "API unreachable: " + e.message, "warn");
  }
}

function addChip(box, text, cls) {
  const chip = document.createElement("span");
  chip.className = "chip" + (cls ? " " + cls : "");
  chip.textContent = text;
  box.appendChild(chip);
}

/* ---------- 2b. service-account provisioning ---------- */

// Notes prefixed with this marker (from the backend) render emphasized (orange).
const PROV_NOTE_EMPHASIS = "[!] ";

// Render the explanatory notes as normal text (not comments in the code output),
// each group into the notes box that sits directly above the command block it
// describes. `credStatus` reports how saving the bootstrap credential set went.
function renderProvNotes(resp, credStatus) {
  const clishBox = document.getElementById("prov-clish-notes");
  const expertBox = document.getElementById("prov-expert-notes");
  const credBox = document.getElementById("prov-cred-status");
  clishBox.replaceChildren();
  expertBox.replaceChildren();
  credBox.replaceChildren();
  const group = (box, title, notes) => {
    if (!notes || !notes.length) return;
    const h = document.createElement("p");
    h.className = "prov-note-title";
    h.textContent = title;
    box.appendChild(h);
    const ul = document.createElement("ul");
    ul.className = "prov-note-list";
    for (const n of notes) {
      const li = document.createElement("li");
      if (n.startsWith(PROV_NOTE_EMPHASIS)) {
        li.textContent = n.slice(PROV_NOTE_EMPHASIS.length);
        li.classList.add("prov-note-warn");
      } else {
        li.textContent = n;
      }
      ul.appendChild(li);
    }
    box.appendChild(ul);
  };
  group(clishBox, "SSH / Gaia access — run in clish on each management server", resp.notes);
  group(expertBox, "Management API access — run in expert mode on the management server", resp.api_notes);
  // The saved-credential status is a panel-wide outcome, so it goes at the very
  // bottom, below both output boxes.
  if (credStatus) {
    const hasApi = resp.api_commands && resp.api_commands.length;
    if (credStatus.ok) {
      const msg = hasApi
        ? `Saved credential set “${credStatus.name}” to the Credentials table below — ` +
          "Edit it to paste the API key after you generate one."
        : `Saved credential set “${credStatus.name}” to the Credentials table below.`;
      group(credBox, "Credentials", [msg]);
    } else {
      group(credBox, "Credentials", [PROV_NOTE_EMPHASIS +
        `Credentials not saved (${credStatus.reason}). Add them in the Credentials table.`]);
    }
  }
  clishBox.classList.toggle("hidden", !clishBox.childElementCount);
  expertBox.classList.toggle("hidden", !expertBox.childElementCount);
  credBox.classList.toggle("hidden", !credBox.childElementCount);
}

async function copyText(text) {
  // Preferred path (secure contexts: HTTPS / localhost).
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for plain HTTP, where the async Clipboard API is unavailable.
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    if (!document.execCommand("copy")) throw new Error("copy rejected");
  } finally {
    ta.remove();
  }
}

function flashCopied(btn) {
  btn.classList.add("copied");
  setTimeout(() => btn.classList.remove("copied"), 1500);
}

// Generate a credential-set name that doesn't collide with any set already in
// the current environment, by appending "-2", "-3", ... to the base name.
function uniqueCredentialName(base) {
  const taken = new Set(credentialSets.map((s) => s.name));
  if (!taken.has(base)) return base;
  let n = 2;
  while (taken.has(`${base}-${n}`)) n++;
  return `${base}-${n}`;
}

// Resolves once the operator picks an outcome in the overwrite-gate modal:
// "overwrite" | "new" | "skip" (also returned on close/backdrop click).
let _provOverwriteResolve = null;

function promptOverwriteChoice(username, existingName) {
  document.getElementById("prov-overwrite-hint").textContent =
    `The SSH username "${username}" is already stored in credential set "${existingName}". ` +
    "Overwrite that set with the new password, save these as a separate new entry, " +
    "or skip saving entirely?";
  document.getElementById("prov-overwrite-modal").classList.remove("hidden");
  return new Promise((resolve) => { _provOverwriteResolve = resolve; });
}

function closeProvOverwriteModal(result) {
  document.getElementById("prov-overwrite-modal").classList.add("hidden");
  const resolve = _provOverwriteResolve;
  _provOverwriteResolve = null;
  if (resolve) resolve(result);
}

document.getElementById("prov-overwrite-new").addEventListener("click", () => closeProvOverwriteModal("new"));
document.getElementById("prov-overwrite-overwrite").addEventListener("click", () => closeProvOverwriteModal("overwrite"));
document.getElementById("prov-overwrite-skip").addEventListener("click", () => closeProvOverwriteModal("skip"));
document.getElementById("prov-overwrite-close").addEventListener("click", () => closeProvOverwriteModal("skip"));
document.getElementById("prov-overwrite-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "prov-overwrite-modal") closeProvOverwriteModal("skip"); // backdrop click cancels
});

// Save the bootstrap username/password as a named credential set so the operator
// doesn't re-enter them. Best-effort: needs a current environment with credential
// storage enabled. If the username already backs another stored set, the operator
// is asked to overwrite it, save these as a new (auto-uniquified) entry, or skip
// saving altogether. Returns a status for the notes area.
async function saveBootstrapCredential(setName, username, password) {
  if (!currentEnv) return { ok: false, reason: "no environment selected" };
  if (!storageEnabled()) return { ok: false, reason: "credential storage is disabled for this environment" };
  await loadCredentialSets(); // refresh before checking for a username collision
  const existing = credentialSets.find((s) => s.ssh_username === username);
  let name = setName;
  if (existing) {
    const choice = await promptOverwriteChoice(username, existing.name);
    if (choice === "skip") return { ok: false, reason: "you chose not to save them" };
    name = choice === "overwrite" ? existing.name : uniqueCredentialName(setName);
  }
  try {
    // Runs as a cred.add/cred.edit job (services/cred_ops.py) rather than
    // completing synchronously — same model as packages. "ok: true" here
    // means "queued", not "stored"; CRED_JOB_KINDS in pollJobs() reloads the
    // Credentials table once it actually finishes (near-instant in practice).
    const job = await api(envUrl("/credentials"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        ssh_username: username,
        ssh_password: password,
        default_if_none: true, // first credentials become the environment default
      }),
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
    await Promise.all([loadJobs(), loadCredentialSets(), loadServers()]);
    return { ok: true, name };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// Clear the bootstrap form and collapse the generated output, returning the
// button to its "Generate commands" state.
function resetProvForm() {
  document.getElementById("provision-form").reset();
  for (const id of ["prov-clish-notes", "prov-expert-notes",
                    "prov-clish-wrap", "prov-expert-wrap", "prov-cred-status"]) {
    document.getElementById(id).classList.add("hidden");
  }
  const btn = document.getElementById("prov-generate");
  btn.textContent = "Generate commands";
  btn.classList.remove("danger");
  delete btn.dataset.mode;
}

// Once commands are on screen, the button becomes a red Reset control (clears the
// form + collapses the output) instead of re-generating.
document.getElementById("prov-generate").addEventListener("click", (ev) => {
  if (ev.currentTarget.dataset.mode === "reset") {
    ev.preventDefault(); // a click in reset mode must not submit the form
    resetProvForm();
  }
});

document.getElementById("provision-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const passwordInput = document.getElementById("prov-password");
  const username = document.getElementById("prov-username").value.trim();
  const password = passwordInput.value;
  // Credential-set label; defaults to the username when left blank.
  const credName = document.getElementById("prov-cred-name").value.trim() || username;
  try {
    const resp = await api("/api/provision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password,
        // A naive `Number(...) || fallback` would silently turn a deliberately-
        // entered 0 into the fallback (0 is falsy in JS, and Number("") is 0
        // too) — so this only falls back on a genuinely non-numeric value.
        uid: (() => {
          const raw = document.getElementById("prov-uid").value.trim();
          if (raw === "") return 0;
          const n = Number(raw);
          return Number.isNaN(n) ? 0 : n;
        })(),
        mgmt_api: document.getElementById("prov-api").checked,
      }),
    });
    passwordInput.value = ""; // plaintext leaves the page as soon as possible
    // Save the same credentials to the table so the operator needn't re-enter them.
    const credStatus = await saveBootstrapCredential(credName, username, password);
    renderProvNotes(resp, credStatus);
    // Commands only (no comment lines) — clish and expert in separate boxes.
    document.getElementById("prov-clish-output").textContent = resp.commands.join("\n");
    document.getElementById("prov-clish-wrap").classList.remove("hidden");
    const hasApi = resp.api_commands && resp.api_commands.length;
    if (hasApi) {
      document.getElementById("prov-expert-output").textContent = resp.api_commands.join("\n");
    }
    document.getElementById("prov-expert-wrap").classList.toggle("hidden", !hasApi);
    const btn = document.getElementById("prov-generate");
    btn.textContent = "Reset";
    btn.classList.add("danger");
    btn.dataset.mode = "reset";
  } catch (e) {
    toast("Generate failed: " + e.message);
  }
});

// Copy icons: each carries data-copy = the id of the <pre> it copies. Manual only.
for (const btn of document.querySelectorAll(".copy-icon[data-copy]")) {
  btn.addEventListener("click", async () => {
    try {
      await copyText(document.getElementById(btn.dataset.copy).textContent);
      flashCopied(btn);
    } catch {
      toast("Clipboard unavailable — select and copy manually.");
    }
  });
}

/* ---------- 3. servers ---------- */

// Pretty labels for the role values the API stores. Legacy management/mds rows
// (pre-dating the granular roles) still render sensibly.
const ROLE_LABELS = {
  primary_sms: "Primary SMS",
  secondary_sms: "Secondary SMS",
  log_server: "Log Server",
  primary_mds: "Primary MDS",
  secondary_mds: "Secondary MDS",
  mlm: "MLM",
  smartevent: "SmartEvent",
  management: "Management (legacy)",
  mds: "MDS (legacy)",
  gateway: "Gateway",
  cluster_member: "Cluster Member",
};
const roleLabel = (role) => ROLE_LABELS[role] ?? role;

// Management tab's server ordering: primaries first, then secondaries, then
// log-plane roles, then SmartEvent last. Legacy management/mds rows are
// equivalent to a primary (see ROLE_LABELS) so they sort into that tier too.
const ROLE_SORT_RANK = {
  primary_sms: 1,
  primary_mds: 1,
  management: 1,
  mds: 1,
  secondary_sms: 2,
  secondary_mds: 2,
  log_server: 3,
  mlm: 3,
  smartevent: 4,
};
function sortByRole(servers) {
  return [...servers].sort((a, b) => {
    const rank = (ROLE_SORT_RANK[a.role] ?? 99) - (ROLE_SORT_RANK[b.role] ?? 99);
    return rank || a.name.localeCompare(b.name);
  });
}

// Whether the current environment has at least one management server. Drives the
// Provisioning panel's button (Connect-to-Primary vs Discover) and whether the
// "Manually add a server" button is shown.
let inventoryHasServers = false;

function updateServersInfoControls(hasServers) {
  inventoryHasServers = hasServers;
  document.getElementById("discover-btn").textContent =
    hasServers ? "Discover servers" : "Connect to Primary SMS/MDS";
  // "Manually add a server" appears only once a primary exists; the first
  // server is added via the Connect-to-Primary modal.
  document.getElementById("add-server-btn").classList.toggle("hidden", !hasServers);
}

// host name -> "pending" | "running", for hosts (management servers and
// firewalls alike) with a job already in flight. The server also rejects a
// new cpuse.import/import_cloud/install for a busy host (see
// PatchingService._ensure_host_free) — this is the UI side: swap that row's
// selection checkbox for a status glyph and disable its Install control so
// the operator isn't invited to start a second job that would just fail.
let activeJobTargets = new Map();
// JSON fingerprint of the map above, so pollJobs() only pays for a table
// reload when the active set actually changed, not on every 2.5s tick.
let activeJobTargetsSnapshot = "";

async function refreshActiveJobTargets() {
  if (!currentEnv) { activeJobTargets = new Map(); return false; }
  try {
    const jobs = await api(
      `/api/jobs?status=pending&status=running&environment=${encodeURIComponent(currentEnv)}&limit=0`,
    );
    const next = new Map();
    for (const job of jobs) {
      if (!job.target) continue; // pkgs.* jobs: target is a filename, not a host
      if (job.status === "running" || !next.has(job.target)) next.set(job.target, job.status);
    }
    activeJobTargets = next;
    const snapshot = JSON.stringify([...next.entries()].sort());
    const changed = snapshot !== activeJobTargetsSnapshot;
    activeJobTargetsSnapshot = snapshot;
    return changed;
  } catch {
    return false; // transient — keep the previous snapshot, retry next call
  }
}

const JOB_ACTIVE_GLYPH = { pending: "⏳", running: "⚙" };
const JOB_ACTIVE_GLYPH_TITLE = {
  pending: "A job is queued for this host — new jobs are blocked until it finishes",
  running: "A job is running on this host — new jobs are blocked until it finishes",
};

// Called right after a freshly-built row's checkbox is wired up. Returns
// whether the host is busy, so callers can skip other per-row wiring if
// they want (none currently do — the row still renders normally otherwise).
function markRowIfJobActive(selectCb, hostName) {
  const status = activeJobTargets.get(hostName);
  if (!status) return false;
  selectCb.classList.add("hidden");
  selectCb.disabled = true;
  const glyph = document.createElement("span");
  glyph.className = "job-active-glyph";
  glyph.textContent = JOB_ACTIVE_GLYPH[status];
  glyph.title = JOB_ACTIVE_GLYPH_TITLE[status];
  selectCb.after(glyph);
  return true;
}

async function loadServers() {
  const tbody = document.querySelector("#servers-table tbody");
  const infoTbody = document.querySelector("#servers-info-table tbody");

  tbody.replaceChildren();
  infoTbody.replaceChildren();

  if (!currentEnv) {
    // No environments defined yet — prompt the operator toward the create dialog.
    const msg = "No environments. Use the Environment picker → New Environment…";
    emptyRow(infoTbody, 7, msg);
    emptyRow(tbody, 5, msg);
    updateServersInfoControls(false);
    return;
  }

  // Patching view (assigned set per server) + editable inventory + the
  // package catalog (for the bulk-import picker above the table) + which
  // hosts already have a job in flight (blocks starting another).
  const [servers, editable, packages] = await Promise.all([
    api(envUrl("/servers")),
    api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`),
    api("/api/packages"),
  ]);
  await refreshActiveJobTargets();
  const assignedByName = new Map(servers.map((s) => [s.name, s.credential_set]));

  const bulkPackageSelect = document.getElementById("bulk-import-package");
  bulkPackageSelect.replaceChildren(new Option("— package —", ""));
  for (const pkg of packages) bulkPackageSelect.appendChild(new Option(pkg.filename, pkg.filename));

  for (const srv of editable) {
    // Provisioning tab: inventory row with a Remove action (env management —
    // patching actions stay on the Management tab).
    const info = el("tpl-server-info-row");
    info.querySelector(".srv-name").textContent = srv.name;
    info.querySelector(".srv-address").textContent = srv.address;
    info.querySelector(".srv-role").textContent = roleLabel(srv.role);
    info.querySelector(".srv-user").textContent = srv.ssh_user;
    info.querySelector(".srv-port").textContent = srv.ssh_port;
    info.querySelector(".srv-creds").textContent =
      assignedByName.get(srv.name) || "none — not assigned";
    info.querySelector(".btn-edit").addEventListener("click", () => {
      openEditServerModal(srv, assignedByName.get(srv.name));
    });
    info.querySelector(".btn-remove").addEventListener("click", async () => {
      if (!confirm(`Remove server ${srv.name} from ${currentEnv}?`)) return;
      try {
        await api(
          `/api/environments/${encodeURIComponent(currentEnv)}/servers/${encodeURIComponent(srv.name)}`,
          { method: "DELETE" },
        );
        await Promise.all([loadServers(), refreshStatus()]);
      } catch (e) { toast("Remove failed: " + e.message); }
    });
    infoTbody.appendChild(info);
  }

  for (const srv of sortByRole(servers)) {
    // Management tab: the action row. Credential assignment is display-only
    // here — change it via Edit on the Provisioning tab.
    const row = el("tpl-server-row");
    const selectCb = row.querySelector(".srv-select");
    selectCb.dataset.server = srv.name; // read by the bulk-import buttons
    selectCb.addEventListener("change", updateSelectAllState);
    markRowIfJobActive(selectCb, srv.name);
    row.querySelector(".srv-name").textContent = srv.name;
    row.querySelector(".srv-address").textContent = srv.address;
    row.querySelector(".srv-role").textContent = roleLabel(srv.role);
    renderInstallSelect(row, srv.installable ?? [], srv.name);
    row.querySelector(".skip-verify").checked = !!envSkipVerifyDefault[currentEnv];

    const stateRow = el("tpl-server-state-row");
    stateRow.dataset.server = srv.name; // looked up by the "Refresh all" button
    renderStateRow(stateRow, srv.checked_at ? srv : null);
    stateRow
      .querySelector(".srv-refresh-link")
      .addEventListener("click", () => refreshState(srv.name, row, stateRow));
    row.querySelector(".btn-install").addEventListener("click", () => installPackage(srv.name, row));
    tbody.appendChild(row);
    tbody.appendChild(stateRow);
  }

  if (!editable.length) {
    emptyRow(infoTbody, 7, "No management servers yet — click Connect to Primary SMS/MDS above.");
    emptyRow(tbody, 5, "No management servers yet — add them on the Provisioning tab.");
  }
  updateServersInfoControls(editable.length > 0);
  updateSelectAllState(); // rows were just rebuilt — reset to "none selected"

  chooseDefaultTab(servers.length);
  await loadFirewalls();
}

function emptyRow(target, colSpan, text) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = colSpan;
  td.className = "muted";
  td.textContent = text;
  tr.appendChild(td);
  target.appendChild(tr);
}

// `show installer status build` returns something like "Build number: 994000123
// (Agent build is up to date)" — drop the "Build number:" label, keep the
// numeric build and the trailing status string.
function formatAgentBuild(raw) {
  if (!raw) return "—";
  return raw.replace(/^\s*build\s*number\s*:\s*/i, "").replace(/\s+/g, " ").trim();
}

// Detected-state summary row: version/JHF/agent build are derived server-side
// (cpuse.summarize_jumbo) and cached in the DB, so `data` here is either a
// server record carrying those fields (from GET /servers, or a fresh /state
// response) or null when nothing has been checked yet.
function renderStateRow(stateRow, data) {
  const summary = stateRow.querySelector(".srv-summary");
  const checked = stateRow.querySelector(".srv-checked");
  if (data == null) {
    summary.textContent = "Not yet checked.";
    checked.textContent = "";
    return;
  }
  const agentBuild = formatAgentBuild(data.agent_build);
  summary.textContent =
    `Running ${data.version ?? "—"} w/JHF ${data.jhf ?? "—"} | CPUSE Agent `;
  // The DA build normally reports "(Agent build is up to date)". Any other
  // status — a newer build available, an error string — warrants the operator's
  // eye, so render that text in orange instead of the normal muted colour.
  if (agentBuild !== "—" && !/agent build is up to date/i.test(data.agent_build || "")) {
    const attn = document.createElement("span");
    attn.className = "agent-build-attention";
    attn.textContent = agentBuild;
    summary.appendChild(attn);
  } else {
    summary.appendChild(document.createTextNode(agentBuild));
  }
  checked.textContent = data.checked_at ? ` | Refreshed ${fmtTime(data.checked_at)}` : "";
}

// Options are the server's cached `installable` list (imported but not yet
// installed) — refreshed alongside the summary row, never the full package
// catalog, since installing something not yet on the host is Import's job
// (not exposed on this page; see the Provisioning tab's Edit modal for
// credential assignment and .claude/memory/patching-web-design.md for why
// Import isn't here).
function renderInstallSelect(row, installable, hostName) {
  const select = row.querySelector(".install-select");
  const btn = row.querySelector(".btn-install");
  const ready = installable.length > 0;
  const blocked = !!(hostName && activeJobTargets.has(hostName));
  select.replaceChildren(new Option(ready ? "— package —" : "— none ready —", ""));
  for (const id of installable) select.appendChild(new Option(id, id));
  select.disabled = !ready || blocked;
  btn.disabled = !ready || blocked;
}

async function refreshState(name, row, stateRow) {
  const link = stateRow.querySelector(".srv-refresh-link");
  const summary = stateRow.querySelector(".srv-summary");
  const extra = await operationCredentials(name, "query live state");
  if (extra === null) return; // credential prompt cancelled
  link.disabled = true;
  summary.textContent = "querying…";
  stateRow.querySelector(".srv-checked").textContent = "";
  try {
    const state = await api(envUrl(`/servers/${encodeURIComponent(name)}/state`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    renderStateRow(stateRow, state);
    renderInstallSelect(row, state.installable ?? [], name);
  } catch (e) {
    cacheEvictCreds(name); // a cached wrong/stale password re-prompts next time
    summary.textContent = "detect failed: " + e.message;
  } finally {
    link.disabled = false;
  }
}

document.getElementById("refresh-all-btn").addEventListener("click", async () => {
  const btn = document.getElementById("refresh-all-btn");
  btn.disabled = true;
  try {
    const stateRows = [...document.querySelectorAll("#servers-table tr.srv-state-row")];
    for (const stateRow of stateRows) {
      await refreshState(stateRow.dataset.server, stateRow.previousElementSibling, stateRow);
    }
  } finally {
    btn.disabled = false;
  }
});

async function installPackage(name, row) {
  const select = row.querySelector(".install-select");
  if (!select.value) { toast("Choose a package first."); return; }
  const packageId = select.value;
  const verifyFirst = !row.querySelector(".skip-verify").checked;
  // Installs can REBOOT the management server — always confirm explicitly.
  const sure = confirm(
    `Install ${packageId} on ${name}?\n\n` +
    (verifyFirst ? "" : "Skipping `installer verify` — installing directly.\n\n") +
    "This may reboot the management server when it completes. " +
    "Make sure this is inside a maintenance window and any HA peer is healthy."
  );
  if (!sure) return;
  const extra = await operationCredentials(name, "install a package");
  if (extra === null) return;
  try {
    await api(envUrl(`/servers/${encodeURIComponent(name)}/install`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package_id: packageId,
        confirmed: true,
        verify_first: verifyFirst,
        ...extra,
      }),
    });
    await loadJobs();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Install failed to start: " + e.message);
  }
}

/* ---------- 3a. bulk import (above the servers table) ---------- */

function selectedServerNames() {
  return [...document.querySelectorAll("#servers-table .srv-select:checked")]
    .map((cb) => cb.dataset.server);
}

// Keeps the header checkbox in sync with the per-row ones: checked when
// every row is checked, indeterminate when only some are. Rows with a job
// already in flight are disabled (see markRowIfJobActive) and excluded —
// "select all" only ever means "all available rows".
function updateSelectAllState() {
  const boxes = [...document.querySelectorAll("#servers-table .srv-select:not(:disabled)")];
  const selectAll = document.getElementById("srv-select-all");
  const checkedCount = boxes.filter((cb) => cb.checked).length;
  selectAll.checked = boxes.length > 0 && checkedCount === boxes.length;
  selectAll.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
}

document.getElementById("srv-select-all").addEventListener("change", (ev) => {
  for (const cb of document.querySelectorAll("#servers-table .srv-select:not(:disabled)")) {
    cb.checked = ev.target.checked;
  }
  updateSelectAllState();
});

// Shared by every bulk-import button (management servers and firewalls alike):
// runs `perServer(name)` for each checked row in turn (not in parallel —
// mirrors "Refresh all"), refreshes the Jobs tab once done, and re-enables
// `btn` even if a target's import failed to start (so one bad target doesn't
// stop the rest). `getTargets` supplies the checked row names for whichever
// table `btn` belongs to.
async function bulkImport(btn, getTargets, perServer) {
  const targets = getTargets();
  if (!targets.length) {
    toast("Select at least one row below (checkbox in the first column) first.");
    return;
  }
  btn.disabled = true;
  try {
    for (const name of targets) {
      try {
        await perServer(name);
      } catch (e) {
        cacheEvictCreds(name);
        toast(`Import to ${name} failed to start: ${e.message}`);
      }
    }
    await loadJobs();
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("bulk-import-btn").addEventListener("click", () => {
  const btn = document.getElementById("bulk-import-btn");
  const pkg = document.getElementById("bulk-import-package").value;
  if (!pkg) { toast("Choose a package first."); return; }
  bulkImport(btn, selectedServerNames, async (name) => {
    const extra = await operationCredentials(name, "import a package");
    if (extra === null) return; // credential prompt cancelled for this host
    const job = await api(envUrl(`/servers/${encodeURIComponent(name)}/import`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg, ...extra }),
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
  });
});

document.getElementById("bulk-import-cloud-btn").addEventListener("click", () => {
  const btn = document.getElementById("bulk-import-cloud-btn");
  const packageId = document.getElementById("bulk-import-cloud-id").value.trim();
  if (!packageId) { toast("Enter a CPUSE package identifier first."); return; }
  bulkImport(btn, selectedServerNames, async (name) => {
    const extra = await operationCredentials(name, "import a package from Check Point's cloud");
    if (extra === null) return;
    const job = await api(envUrl(`/servers/${encodeURIComponent(name)}/import-cloud`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_id: packageId, ...extra }),
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
  });
});

/* ---------- 3b. firewalls (CPUSE tab; single combined CRUD+action table) ---------- */

// Firewalls patched directly via CPUSE, one host at a time — distinct from the
// CDT bulk gateway-fleet push below. Reuses renderStateRow/renderInstallSelect
// (already generic over row/data shape) and the shared bulkImport() helper.

async function loadFirewalls() {
  const tbody = document.querySelector("#firewalls-table tbody");
  tbody.replaceChildren();

  if (!currentEnv) {
    emptyRow(tbody, 9, "No environments. Use the Environment picker → New Environment…");
    return;
  }

  const [firewalls, editable, packages] = await Promise.all([
    api(envUrl("/firewalls")),
    api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`),
    api("/api/packages"),
  ]);
  await refreshActiveJobTargets();
  const stateByName = new Map(firewalls.map((f) => [f.name, f]));

  const bulkPackageSelect = document.getElementById("fw-bulk-import-package");
  bulkPackageSelect.replaceChildren(new Option("— package —", ""));
  for (const pkg of packages) bulkPackageSelect.appendChild(new Option(pkg.filename, pkg.filename));

  for (const fw of sortByRole(editable)) {
    const state = stateByName.get(fw.name);
    const row = el("tpl-firewall-row");
    const selectCb = row.querySelector(".fw-select");
    selectCb.dataset.firewall = fw.name; // read by the bulk-import buttons
    selectCb.addEventListener("change", updateFirewallSelectAllState);
    markRowIfJobActive(selectCb, fw.name);
    row.querySelector(".fw-name").textContent = fw.name;
    row.querySelector(".fw-address").textContent = fw.address;
    row.querySelector(".fw-role").textContent = roleLabel(fw.role);
    row.querySelector(".fw-user").textContent = fw.ssh_user;
    row.querySelector(".fw-port").textContent = fw.ssh_port;
    row.querySelector(".fw-creds").textContent =
      (state && state.credential_set) || "none — not assigned";
    renderInstallSelect(row, state?.installable ?? [], fw.name);
    row.querySelector(".skip-verify").checked = !!envSkipVerifyDefault[currentEnv];

    const stateRow = el("tpl-firewall-state-row");
    stateRow.dataset.firewall = fw.name; // looked up by the "Refresh all" button
    renderStateRow(stateRow, state && state.checked_at ? state : null);
    stateRow
      .querySelector(".srv-refresh-link")
      .addEventListener("click", () => refreshFirewallState(fw.name, row, stateRow));
    row.querySelector(".btn-install").addEventListener("click", () => installFirewallPackage(fw.name, row));
    row.querySelector(".btn-edit").addEventListener("click", () => {
      openEditFirewallModal(fw, state && state.credential_set);
    });
    row.querySelector(".btn-remove").addEventListener("click", async () => {
      if (!confirm(`Remove firewall ${fw.name} from ${currentEnv}?`)) return;
      try {
        await api(
          `/api/environments/${encodeURIComponent(currentEnv)}/firewalls/${encodeURIComponent(fw.name)}`,
          { method: "DELETE" },
        );
        await loadFirewalls();
      } catch (e) { toast("Remove failed: " + e.message); }
    });
    tbody.appendChild(row);
    tbody.appendChild(stateRow);
  }

  if (!editable.length) {
    emptyRow(tbody, 9, "No firewalls yet — add one manually or discover from a primary.");
  }
  updateFirewallSelectAllState(); // rows were just rebuilt — reset to "none selected"
}

async function refreshFirewallState(name, row, stateRow) {
  const link = stateRow.querySelector(".srv-refresh-link");
  const summary = stateRow.querySelector(".srv-summary");
  const extra = await operationCredentials(name, "query live state");
  if (extra === null) return; // credential prompt cancelled
  link.disabled = true;
  summary.textContent = "querying…";
  stateRow.querySelector(".srv-checked").textContent = "";
  try {
    const state = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/state`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    renderStateRow(stateRow, state);
    renderInstallSelect(row, state.installable ?? [], name);
  } catch (e) {
    cacheEvictCreds(name); // a cached wrong/stale password re-prompts next time
    summary.textContent = "detect failed: " + e.message;
  } finally {
    link.disabled = false;
  }
}

document.getElementById("fw-refresh-all-btn").addEventListener("click", async () => {
  const btn = document.getElementById("fw-refresh-all-btn");
  btn.disabled = true;
  try {
    const stateRows = [...document.querySelectorAll("#firewalls-table tr.srv-state-row")];
    for (const stateRow of stateRows) {
      await refreshFirewallState(stateRow.dataset.firewall, stateRow.previousElementSibling, stateRow);
    }
  } finally {
    btn.disabled = false;
  }
});

async function installFirewallPackage(name, row) {
  const select = row.querySelector(".install-select");
  if (!select.value) { toast("Choose a package first."); return; }
  const packageId = select.value;
  const verifyFirst = !row.querySelector(".skip-verify").checked;
  // Installs can REBOOT the firewall — always confirm explicitly.
  const sure = confirm(
    `Install ${packageId} on ${name}?\n\n` +
    (verifyFirst ? "" : "Skipping `installer verify` — installing directly.\n\n") +
    "This may reboot the firewall when it completes. " +
    "Make sure this is inside a maintenance window and any HA peer is healthy."
  );
  if (!sure) return;
  const extra = await operationCredentials(name, "install a package");
  if (extra === null) return;
  try {
    await api(envUrl(`/firewalls/${encodeURIComponent(name)}/install`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package_id: packageId,
        confirmed: true,
        verify_first: verifyFirst,
        ...extra,
      }),
    });
    await loadJobs();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Install failed to start: " + e.message);
  }
}

function selectedFirewallNames() {
  return [...document.querySelectorAll("#firewalls-table .fw-select:checked")]
    .map((cb) => cb.dataset.firewall);
}

// Rows with a job already in flight are disabled (see markRowIfJobActive)
// and excluded — "select all" only ever means "all available rows".
function updateFirewallSelectAllState() {
  const boxes = [...document.querySelectorAll("#firewalls-table .fw-select:not(:disabled)")];
  const selectAll = document.getElementById("fw-select-all");
  const checkedCount = boxes.filter((cb) => cb.checked).length;
  selectAll.checked = boxes.length > 0 && checkedCount === boxes.length;
  selectAll.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
}

document.getElementById("fw-select-all").addEventListener("change", (ev) => {
  for (const cb of document.querySelectorAll("#firewalls-table .fw-select:not(:disabled)")) {
    cb.checked = ev.target.checked;
  }
  updateFirewallSelectAllState();
});

document.getElementById("fw-bulk-import-btn").addEventListener("click", () => {
  const btn = document.getElementById("fw-bulk-import-btn");
  const pkg = document.getElementById("fw-bulk-import-package").value;
  if (!pkg) { toast("Choose a package first."); return; }
  bulkImport(btn, selectedFirewallNames, async (name) => {
    const extra = await operationCredentials(name, "import a package");
    if (extra === null) return;
    const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/import`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg, ...extra }),
    });
    lastJobStatus.set(job.id, job.status);
  });
});

document.getElementById("fw-bulk-import-cloud-btn").addEventListener("click", () => {
  const btn = document.getElementById("fw-bulk-import-cloud-btn");
  const packageId = document.getElementById("fw-bulk-import-cloud-id").value.trim();
  if (!packageId) { toast("Enter a CPUSE package identifier first."); return; }
  bulkImport(btn, selectedFirewallNames, async (name) => {
    const extra = await operationCredentials(name, "import a package from Check Point's cloud");
    if (extra === null) return;
    const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/import-cloud`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_id: packageId, ...extra }),
    });
    lastJobStatus.set(job.id, job.status);
  });
});

/* ---------- 3c. add/edit firewall (modal) ---------- */

async function populateFirewallCredSelect(assignedSetName) {
  const enabled = storageEnabled();
  document.getElementById("fm-user-label").classList.toggle("hidden", enabled);
  document.getElementById("fm-cred-label").classList.toggle("hidden", !enabled);
  if (!enabled) return;
  const select = document.getElementById("fm-cred-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  const sets = await fetchCredentialSets();
  for (const set of sets) {
    const opt = document.createElement("option");
    opt.value = set.name;
    opt.textContent = set.name;
    opt.dataset.sshUser = set.ssh_username || "";
    select.appendChild(opt);
  }
  select.value = assignedSetName || "";
}

async function addFirewall({ name, address, role, ssh_user, ssh_port }) {
  await api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, address, role, ssh_user, ssh_port }),
  });
}

async function openAddFirewallModal() {
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  document.getElementById("firewall-form").reset();
  document.getElementById("fm-name").disabled = false;
  document.getElementById("firewall-modal-title").textContent = "Add firewall";
  document.getElementById("firewall-modal-submit").textContent = "Add firewall";
  await populateFirewallCredSelect();
  document.getElementById("firewall-modal").classList.remove("hidden");
  document.getElementById("fm-name").focus();
}
async function openEditFirewallModal(fw, assignedSetName) {
  document.getElementById("fm-name").value = fw.name;
  document.getElementById("fm-name").disabled = true;
  document.getElementById("fm-address").value = fw.address;
  document.getElementById("fm-role").value = fw.role;
  document.getElementById("fm-user").value = fw.ssh_user;
  document.getElementById("fm-port").value = fw.ssh_port;
  document.getElementById("firewall-modal-title").textContent = `Edit ${fw.name}`;
  document.getElementById("firewall-modal-submit").textContent = "Save changes";
  await populateFirewallCredSelect(assignedSetName);
  document.getElementById("firewall-modal").classList.remove("hidden");
  document.getElementById("fm-address").focus();
}
function closeFirewallModal() {
  document.getElementById("firewall-modal").classList.add("hidden");
}

document.getElementById("add-firewall-btn").addEventListener("click", openAddFirewallModal);
document.getElementById("firewall-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) return;
  const name = document.getElementById("fm-name").value.trim();
  const credSelect = document.getElementById("fm-cred-select");
  const credSet = storageEnabled() ? credSelect.value : null;
  const sshUser = storageEnabled()
    ? credSelect.selectedOptions[0]?.dataset.sshUser || "admin"
    : document.getElementById("fm-user").value.trim() || "admin";
  try {
    await addFirewall({
      name,
      address: document.getElementById("fm-address").value.trim(),
      role: document.getElementById("fm-role").value,
      ssh_user: sshUser,
      ssh_port: Number(document.getElementById("fm-port").value) || 22,
    });
    if (storageEnabled()) {
      await api(envUrl(`/firewalls/${encodeURIComponent(name)}/credential`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ set: credSet || null }),
      });
    }
    closeFirewallModal();
    await loadFirewalls();
  } catch (e) { toast("Save failed: " + e.message); }
});
document.getElementById("firewall-modal-close").addEventListener("click", closeFirewallModal);
document.getElementById("firewall-modal-cancel").addEventListener("click", closeFirewallModal);
document.getElementById("firewall-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "firewall-modal") closeFirewallModal(); // backdrop closes
});

/* ---------- 3d. discover firewalls ---------- */

// The primary's SSH identity, captured when a scan runs so imported firewalls
// can inherit it — same idea as discoverPrimarySshUser/discoverPrimaryCredSet
// above, kept separate since the two discovery flows are independent (per the
// Firewalls panel's design).
let discoverFwPrimarySshUser = "admin";
let discoverFwPrimaryCredSet = null;

// An environment has exactly one primary (SMS or MDS) — the modal never asks
// the operator to pick a source server, it just finds it.
function findPrimaryServer(servers) {
  return servers.find((s) => s.role === "primary_sms" || s.role === "primary_mds") || null;
}

async function openDiscoverFirewallsModal() {
  if (!currentEnv) { toast("Create an environment and add a primary management server first."); return; }
  let servers = [];
  try {
    servers = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`);
  } catch (e) { toast("Could not load servers: " + e.message); return; }
  if (!findPrimaryServer(servers)) {
    toast("Add a Primary SMS or Primary MDS server on the Provisioning tab before discovering firewalls.");
    return;
  }
  resetDiscoverFirewallsResults();
  const domainLabel = document.getElementById("discover-firewalls-domain-label");
  const domainSelect = document.getElementById("discover-firewalls-domain");
  domainSelect.replaceChildren();
  const status = document.getElementById("discover-firewalls-status");
  if (envIsMds[currentEnv]) {
    domainLabel.classList.remove("hidden");
    status.textContent = "Loading domains…";
    try {
      const { domains, warnings } = await api(`/api/environments/${encodeURIComponent(currentEnv)}/domains`);
      for (const d of domains) domainSelect.appendChild(new Option(d, d));
      status.textContent = domains.length ? "" : "No Domains found on the primary MDS.";
      for (const w of warnings || []) toast(w);
    } catch (e) {
      status.textContent = "Could not load domains: " + e.message;
    }
  } else {
    domainLabel.classList.add("hidden");
  }
  document.getElementById("discover-firewalls-modal").classList.remove("hidden");
}

function resetDiscoverFirewallsResults() {
  document.getElementById("discover-firewalls-status").textContent = "";
  const warn = document.getElementById("discover-firewalls-warnings");
  warn.classList.add("hidden");
  warn.replaceChildren();
  const table = document.getElementById("discover-firewalls-table");
  table.classList.add("hidden");
  table.querySelector("tbody").replaceChildren();
  document.getElementById("discover-firewalls-import").disabled = true;
}

function closeDiscoverFirewallsModal() {
  document.getElementById("discover-firewalls-modal").classList.add("hidden");
}

document.getElementById("discover-firewalls-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) return;
  const isMds = !!envIsMds[currentEnv];
  const domain = isMds ? document.getElementById("discover-firewalls-domain").value : null;
  if (isMds && !domain) { toast("Select a Domain to discover firewalls from."); return; }
  resetDiscoverFirewallsResults();
  const status = document.getElementById("discover-firewalls-status");
  const runBtn = document.getElementById("discover-firewalls-run");
  runBtn.disabled = true;
  try {
    const editableServers = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`);
    const primarySrv = findPrimaryServer(editableServers);
    if (!primarySrv) { status.textContent = "No Primary SMS/MDS server configured."; return; }
    status.textContent = `Scanning from ${primarySrv.name}…`;
    discoverFwPrimarySshUser = primarySrv.ssh_user;
    discoverFwPrimaryCredSet = null;
    if (storageEnabled()) {
      const srvs = await api(envUrl("/servers"));
      const match = srvs.find((s) => s.name === primarySrv.name);
      discoverFwPrimaryCredSet = match ? match.credential_set : null;
    }
    const result = await api(`/api/environments/${encodeURIComponent(currentEnv)}/discover-firewalls`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    renderDiscoverFirewallsResults(result);
  } catch (e) {
    status.textContent = "Discovery failed: " + e.message;
  } finally {
    runBtn.disabled = false;
  }
});

function renderDiscoverFirewallsResults(result) {
  const status = document.getElementById("discover-firewalls-status");
  const warn = document.getElementById("discover-firewalls-warnings");
  for (const w of result.warnings || []) {
    warn.classList.remove("hidden");
    const line = document.createElement("div");
    line.textContent = "⚠ " + w;
    warn.appendChild(line);
  }
  const servers = result.servers || [];
  if (!servers.length) {
    status.textContent = "No additional firewalls found.";
    return;
  }
  const already = servers.filter((s) => s.already_in_inventory).length;
  status.textContent =
    `Found ${servers.length} firewall${servers.length === 1 ? "" : "s"}` +
    (already ? ` (${already} already in inventory)` : "") +
    ". Review roles, then import the ones you want.";
  const table = document.getElementById("discover-firewalls-table");
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren();
  for (const s of servers) {
    const row = el("tpl-discovered-firewall-row");
    const pick = row.querySelector(".disc-pick");
    const name = row.querySelector(".disc-name");
    const address = row.querySelector(".disc-address");
    const roleSel = row.querySelector(".disc-role");
    const note = row.querySelector(".disc-note");
    name.value = s.name;
    address.value = s.address;
    roleSel.value = s.role;
    let noteText = s.note || "";
    if (s.already_in_inventory) {
      noteText = "already in inventory";
      pick.checked = false;
      pick.disabled = name.disabled = address.disabled = roleSel.disabled = true;
      row.classList.add("disc-existing");
    } else {
      pick.checked = true;
      if (s.needs_review) {
        noteText = noteText ? noteText + " — review" : "review the detected role";
        row.classList.add("disc-review");
      }
    }
    note.textContent = noteText;
    tbody.appendChild(row);
  }
  table.classList.remove("hidden");
  document.getElementById("discover-firewalls-import").disabled =
    servers.length === already; // nothing new to import
}

document.getElementById("discover-firewalls-import").addEventListener("click", async () => {
  const rows = [...document.querySelectorAll("#discover-firewalls-table tbody tr")];
  const picks = rows.filter((r) => {
    const pick = r.querySelector(".disc-pick");
    return pick.checked && !pick.disabled;
  });
  if (!picks.length) { toast("Nothing selected to import."); return; }
  const importBtn = document.getElementById("discover-firewalls-import");
  importBtn.disabled = true;
  let ok = 0;
  const failed = [];
  for (const r of picks) {
    const name = r.querySelector(".disc-name").value.trim();
    const address = r.querySelector(".disc-address").value.trim();
    const role = r.querySelector(".disc-role").value;
    if (!name || !address) { failed.push(name || address || "(unnamed)"); continue; }
    try {
      await api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, address, role, ssh_user: discoverFwPrimarySshUser }),
      });
      if (storageEnabled() && discoverFwPrimaryCredSet) {
        await api(envUrl(`/firewalls/${encodeURIComponent(name)}/credential`), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ set: discoverFwPrimaryCredSet }),
        });
      }
      ok++;
    } catch (e) { failed.push(`${name}: ${e.message}`); }
  }
  await loadFirewalls();
  if (failed.length) {
    toast(`Imported ${ok}. Failed: ${failed.join("; ")}`);
    importBtn.disabled = false;
  } else {
    closeDiscoverFirewallsModal();
  }
});

document.getElementById("discover-firewalls-btn").addEventListener("click", openDiscoverFirewallsModal);
document.getElementById("discover-firewalls-close").addEventListener("click", closeDiscoverFirewallsModal);
document.getElementById("discover-firewalls-cancel").addEventListener("click", closeDiscoverFirewallsModal);
document.getElementById("discover-firewalls-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "discover-firewalls-modal") closeDiscoverFirewallsModal(); // backdrop click closes
});

/* ---------- 3e. gateway deployment (CDT) ---------- */

// Candidate rows held in memory between Load and Save. Kept as
// { header: [...], rows: [[...], ...] } exactly as the API speaks.
let cdtCandidates = null;

function cdtServer() {
  const name = document.getElementById("cdt-server").value;
  if (!name) toast("Choose a management server first.");
  return name;
}

async function populateCdtSelectors() {
  const serverSel = document.getElementById("cdt-server");
  const pkgSel = document.getElementById("cdt-package");
  const [servers, packages] = await Promise.all([api(envUrl("/servers")), api("/api/packages")]);
  serverSel.replaceChildren(new Option("— management server —", ""));
  for (const s of servers) serverSel.appendChild(new Option(s.name, s.name));
  pkgSel.replaceChildren(new Option("— package —", ""));
  for (const p of packages) pkgSel.appendChild(new Option(p.filename, p.filename));
}

async function cdtRefreshStatus() {
  const name = cdtServer();
  if (!name) return;
  const extra = await operationCredentials(name, "query CDT status");
  if (extra === null) return;
  const box = document.getElementById("cdt-status");
  box.textContent = "querying…";
  try {
    const s = await api(envUrl(`/cdt/${encodeURIComponent(name)}/status`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    box.textContent =
      (s.available ? "CDT available" : "CDT NOT FOUND on this server") +
      (s.running ? " — RUNNING" : " — idle") +
      (s.brief ? " — " + s.brief : "");
  } catch (e) {
    cacheEvictCreds(name);
    box.textContent = "status failed: " + e.message;
  }
}

async function cdtLoadCandidates() {
  const name = cdtServer();
  if (!name) return;
  const extra = await operationCredentials(name, "read the candidates list");
  if (extra === null) return;
  try {
    cdtCandidates = await api(envUrl(`/cdt/${encodeURIComponent(name)}/candidates/read`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    renderCdtCandidates();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Load failed: " + e.message);
  }
}

function renderCdtCandidates() {
  const headRow = document.querySelector("#cdt-candidates-table thead tr");
  const tbody = document.querySelector("#cdt-candidates-table tbody");
  headRow.replaceChildren();
  tbody.replaceChildren();
  if (!cdtCandidates) return;

  const actionsTh = document.createElement("th"); // order/remove controls column
  headRow.appendChild(actionsTh);
  for (const col of cdtCandidates.header) {
    const th = document.createElement("th");
    th.textContent = col;
    headRow.appendChild(th);
  }

  cdtCandidates.rows.forEach((row, idx) => {
    const tr = el("tpl-cdt-row");
    tr.querySelector(".btn-up").addEventListener("click", () => cdtMoveRow(idx, -1));
    tr.querySelector(".btn-down").addEventListener("click", () => cdtMoveRow(idx, +1));
    tr.querySelector(".btn-remove").addEventListener("click", () => {
      cdtCandidates.rows.splice(idx, 1);
      renderCdtCandidates();
    });
    for (const cell of row) {
      const td = document.createElement("td");
      td.className = "mono";
      td.textContent = cell;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  });
}

function cdtMoveRow(idx, delta) {
  const rows = cdtCandidates.rows;
  const target = idx + delta;
  if (target < 0 || target >= rows.length) return;
  [rows[idx], rows[target]] = [rows[target], rows[idx]];
  renderCdtCandidates();
}

async function cdtSaveCandidates() {
  const name = cdtServer();
  if (!name || !cdtCandidates) { toast("Load candidates first."); return; }
  const extra = await operationCredentials(name, "save the candidates list");
  if (extra === null) return;
  try {
    const resp = await api(envUrl(`/cdt/${encodeURIComponent(name)}/candidates`), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...cdtCandidates, ...extra }),
    });
    toast(`Saved ${resp.rows} candidate(s). Row order is the deployment order.`);
  } catch (e) {
    cacheEvictCreds(name);
    toast("Save failed: " + e.message);
  }
}

async function cdtAction(path, body) {
  const name = cdtServer();
  if (!name) return;
  const extra = await operationCredentials(name, path);
  if (extra === null) return;
  try {
    await api(envUrl(`/cdt/${encodeURIComponent(name)}/${path}`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...(body ?? {}), ...extra }),
    });
    await loadJobs();
  } catch (e) {
    cacheEvictCreds(name);
    toast(`${path} failed to start: ` + e.message);
  }
}

document.getElementById("cdt-stage").addEventListener("click", () => {
  const pkg = document.getElementById("cdt-package").value;
  if (!pkg) { toast("Choose an uploaded package first."); return; }
  cdtAction("stage", { package: pkg });
});
document.getElementById("cdt-generate").addEventListener("click", () => cdtAction("generate"));
document.getElementById("cdt-load").addEventListener("click", cdtLoadCandidates);
document.getElementById("cdt-save").addEventListener("click", cdtSaveCandidates);
document.getElementById("cdt-prepare").addEventListener("click", () =>
  cdtAction("prepare", { extended: document.getElementById("cdt-extended").checked }));
document.getElementById("cdt-status-btn").addEventListener("click", cdtRefreshStatus);
document.getElementById("cdt-execute").addEventListener("click", () => {
  const name = document.getElementById("cdt-server").value;
  const count = cdtCandidates ? cdtCandidates.rows.length : "?";
  // Executing deploys to EVERY gateway in the candidates list, in order.
  const sure = confirm(
    `Execute the CDT deployment from ${name || "?"}?\n\n` +
    `This deploys to ${count} gateway(s) in the saved candidate order, ` +
    "including automatic cluster failovers. Make sure this is inside a " +
    "maintenance window and the candidate list was reviewed and saved."
  );
  if (sure) cdtAction("execute", { confirmed: true });
});

/* ---------- 4. packages ---------- */

async function loadPackages() {
  const tbody = document.querySelector("#packages-table tbody");
  const packages = await api("/api/packages");
  tbody.replaceChildren();
  for (const pkg of packages) {
    const row = el("tpl-package-row");
    row.querySelector(".pkg-filename").textContent = pkg.filename;
    row.querySelector(".pkg-size").textContent = fmtBytes(pkg.size);

    const sha1Row = el("tpl-package-sha1-row");
    sha1Row.querySelector(".pkg-sha1").textContent = `sha1: ${pkg.sha1}`;

    // Retention: ticked "Keep" == pinned (no expiry). Otherwise show the deadline.
    const pin = row.querySelector(".pkg-pin");
    const expiry = sha1Row.querySelector(".pkg-expiry");
    const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
    const renderRetention = (rec) => {
      pin.checked = rec.expires_at == null;
      expiry.textContent = rec.expires_at ? `expires ${fmtDate(rec.expires_at)}` : "kept indefinitely";
      const soon = rec.expires_at != null && new Date(rec.expires_at) - Date.now() <= WEEK_MS;
      expiry.classList.toggle("warn", soon);
    };
    renderRetention(pkg);
    // Retention now runs as a pkgs.keep/pkgs.notkeep job (services/pkgs_ops.py)
    // rather than completing synchronously, so this only reflects whether the
    // job started — same model as every other job-backed action in this app
    // (e.g. installPackage below never waits for the install job itself
    // either). A submit failure reverts the optimistic toggle immediately;
    // the job's own outcome shows up on the Jobs tab, and PKGS_JOB_KINDS in
    // pollJobs() reloads this table once it finishes either way.
    pin.addEventListener("change", async () => {
      pin.disabled = true;
      try {
        const job = await api(`/api/packages/${encodeURIComponent(pkg.filename)}/retention`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pinned: pin.checked }),
        });
        lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
        await loadJobs();
      } catch (e) {
        pin.checked = !pin.checked; // revert the optimistic toggle — the job never even started
        toast("Could not start retention update: " + e.message);
      } finally {
        pin.disabled = false;
      }
    });

    // Delete likewise now runs as a pkgs.delete job — see the comment above.
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete package ${pkg.filename}?`)) return;
      try {
        const job = await api(`/api/packages/${encodeURIComponent(pkg.filename)}`, { method: "DELETE" });
        lastJobStatus.set(job.id, job.status);
        await loadJobs();
      } catch (e) { toast("Delete failed to start: " + e.message); }
    });
    tbody.appendChild(row);
    tbody.appendChild(sha1Row);
  }
  await populateCdtSelectors(); // keep the CDT dropdowns in sync with packages/servers
}

// Shared upload path for the form and drag & drop. The multipart body itself
// is still sent synchronously (inherent to HTTP — the browser is actively
// streaming it during this request), but the server only stages it here; the
// slow part (hash, dedupe, store) runs as a pkgs.upload job, so "done" below
// means "queued", not "stored" — see the retention/delete comment above and
// services/pkgs_ops.py's module docstring for why upload needs the staging step.
async function uploadPackageFile(file) {
  const progress = document.getElementById("upload-progress");
  const btn = document.getElementById("upload-btn");
  const form = new FormData();
  form.append("file", file);
  btn.disabled = true;
  progress.textContent = `uploading ${file.name}… (large packages take a while)`;
  try {
    const job = await api("/api/packages", { method: "POST", body: form });
    lastJobStatus.set(job.id, job.status);
    progress.textContent = `${file.name}: queued — see the Jobs tab for progress`;
    await loadJobs();
  } catch (e) {
    progress.textContent = "";
    toast(`Upload of ${file.name} failed to start: ` + e.message);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("upload-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("upload-file");
  if (!input.files.length) return;
  await uploadPackageFile(input.files[0]);
  input.value = "";
});

// Drag & drop: the whole Packages section is the drop zone. A depth counter
// keeps the highlight stable while dragging across child elements (dragleave
// fires on every child boundary). Multiple files upload sequentially.
{
  const zone = document.getElementById("packages");
  let depth = 0;
  zone.addEventListener("dragenter", (ev) => {
    ev.preventDefault();
    depth += 1;
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragover", (ev) => ev.preventDefault()); // allow drop
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (!depth) zone.classList.remove("dragover");
  });
  zone.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    depth = 0;
    zone.classList.remove("dragover");
    for (const file of ev.dataTransfer.files) {
      await uploadPackageFile(file);
    }
  });
  // A missed drop must not make the browser navigate away to the file.
  window.addEventListener("dragover", (ev) => ev.preventDefault());
  window.addEventListener("drop", (ev) => ev.preventDefault());
}

/* ---------- 5. credential sets ---------- */

// Named login sets for the current environment (name → info), refreshed by
// loadCredentialSets and reused to populate the Management-tab assignment picker.
let credentialSets = [];

async function fetchCredentialSets() {
  if (!currentEnv || !storageEnabled()) return [];
  try {
    return await api(envUrl("/credentials"));
  } catch {
    return []; // store locked / not reachable — dropdowns fall back to none
  }
}

async function loadCredentialSets() {
  const tbody = document.querySelector("#credentials-table tbody");
  tbody.replaceChildren();
  // Storage-disabled environments don't keep credential sets — swap the form
  // for an explanatory notice.
  const enabled = storageEnabled();
  document.getElementById("cred-storage-notice").classList.toggle("hidden", enabled);
  document.getElementById("cred-add-btn").classList.toggle("hidden", !enabled);
  if (!currentEnv || !enabled) { credentialSets = []; return; }
  credentialSets = await fetchCredentialSets();
  const tick = (b) => (b ? "✓" : "—");
  for (const set of credentialSets) {
    const row = el("tpl-credential-row");
    row.querySelector(".cs-name-text").textContent = set.name;
    // The env's default set carries a pill and hides its "Make default" button.
    row.querySelector(".cs-default-pill").classList.toggle("hidden", !set.is_default);
    const defaultBtn = row.querySelector(".btn-default");
    defaultBtn.classList.toggle("hidden", set.is_default);
    defaultBtn.addEventListener("click", async () => {
      try {
        await api(envUrl(`/credentials/${encodeURIComponent(set.name)}/default`), { method: "POST" });
        await loadCredentialSets();
      } catch (e) { toast("Could not set default: " + e.message); }
    });
    row.querySelector(".cs-user").textContent = set.ssh_username ?? "";
    row.querySelector(".cs-auth").textContent = set.ssh_auth; // password | key | none
    row.querySelector(".cs-expert").textContent = tick(set.has_expert);
    row.querySelector(".cs-api").textContent = tick(set.has_api);
    row.querySelector(".btn-edit").addEventListener("click", () => openCredEditModal(set));
    // Runs as a cred.delete job (services/cred_ops.py) — see the credential-form
    // submit handler below for the same "queued, not done" model.
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete credential set "${set.name}"? Servers using it lose access.`)) return;
      try {
        const job = await api(envUrl(`/credentials/${encodeURIComponent(set.name)}`), { method: "DELETE" });
        lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
        await Promise.all([loadJobs(), loadCredentialSets(), loadServers()]);
      } catch (e) { toast("Delete failed to start: " + e.message); }
    });
    tbody.appendChild(row);
  }
}

// Sets the Bootstrap panel's default open/closed state for the current
// environment: collapsed once there's nothing left to set up (storage
// disabled, or storage enabled with a default credential set already
// picked), left open otherwise since bootstrapping is likely still needed.
// Called once per environment load/switch — never on every credential-set
// refresh, so it doesn't yank the panel shut/open out from under an
// operator who's actively working in it.
function updateProvisionCollapse() {
  const hasDefault = credentialSets.some((s) => s.is_default);
  const collapse = !storageEnabled() || hasDefault;
  document.getElementById("provision-details").open = !collapse;
}

// Whether the credential modal is editing an existing set (vs. adding a new one).
// In edit mode, blank secret fields keep the set's current value (backend merges).
let credEditMode = false;

document.getElementById("credential-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pwInput = document.getElementById("cs-ssh-password");
  const keyInput = document.getElementById("cs-ssh-key");
  const password = pwInput.value;
  const key = keyInput.value.trim();
  // Adding a new set needs an SSH secret; editing may leave them blank to keep
  // the existing ones (e.g. adding only the API key to a bootstrap entry).
  if (!password && !key && !credEditMode) { toast("Enter an SSH password or a private key."); return; }
  if (password && key) { toast("Enter an SSH password OR a private key, not both."); return; }
  const expertInput = document.getElementById("cs-expert");
  const apiInput = document.getElementById("cs-api");
  try {
    // Runs as a cred.add/cred.edit job (services/cred_ops.py) rather than
    // completing synchronously — same "queued, not done" model as packages
    // (see uploadPackageFile). CRED_JOB_KINDS in pollJobs() reloads the
    // Credentials table once it actually finishes (near-instant in practice).
    const job = await api(envUrl("/credentials"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: document.getElementById("cs-name").value.trim(),
        ssh_username: document.getElementById("cs-ssh-user").value.trim() || null,
        ssh_password: password || null,
        ssh_private_key: key || null,
        expert_password: expertInput.value || null,
        api_key: apiInput.value || null,
      }),
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
    closeCredAddModal(); // resets the form so no secrets linger in the DOM
    await Promise.all([loadJobs(), loadCredentialSets(), loadServers()]);
  } catch (e) {
    toast("Save failed to start: " + e.message);
  }
});

// The credential-set editor lives in a modal opened from the panel's header.
function openCredAddModal() {
  const form = document.getElementById("credential-form");
  form.reset(); // fresh, empty each open
  credEditMode = false;
  document.getElementById("cred-add-title").textContent = "Add credential set";
  document.getElementById("cred-add-hint").classList.remove("hidden");
  document.getElementById("cred-edit-hint").classList.add("hidden");
  document.getElementById("cs-name").readOnly = false;
  document.getElementById("cred-add-modal").classList.remove("hidden");
  document.getElementById("cs-name").focus();
}
// Edit an existing set: prefill name (locked) + SSH username; blank secret fields
// are kept. Handy for pasting the API key into a bootstrapped entry afterwards.
function openCredEditModal(set) {
  const form = document.getElementById("credential-form");
  form.reset();
  credEditMode = true;
  document.getElementById("cred-add-title").textContent = "Edit credential set";
  document.getElementById("cred-add-hint").classList.add("hidden");
  const editHint = document.getElementById("cred-edit-hint");
  editHint.textContent =
    `Editing "${set.name}". Leave a secret field blank to keep its current value.`;
  editHint.classList.remove("hidden");
  const nameInput = document.getElementById("cs-name");
  nameInput.value = set.name;
  nameInput.readOnly = true; // name identifies the set being updated
  document.getElementById("cs-ssh-user").value = set.ssh_username ?? "";
  document.getElementById("cred-add-modal").classList.remove("hidden");
  document.getElementById("cs-api").focus(); // the common edit is pasting the API key
}
function closeCredAddModal() {
  document.getElementById("cred-add-modal").classList.add("hidden");
  document.getElementById("credential-form").reset(); // never leave secrets in the DOM
  document.getElementById("cs-name").readOnly = false;
  credEditMode = false;
}
document.getElementById("cred-add-btn").addEventListener("click", openCredAddModal);
document.getElementById("cred-add-close").addEventListener("click", closeCredAddModal);
document.getElementById("cred-add-cancel").addEventListener("click", closeCredAddModal);
document.getElementById("cred-add-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "cred-add-modal") closeCredAddModal(); // backdrop click closes
});

/* ---------- 6. jobs ---------- */

const openJobLogs = new Set(); // job ids whose progress log is expanded

// Last-seen status per job id, so pollJobs() can notice an import job
// finishing and reload the Management tab (see pollJobs()) — otherwise the
// server's newly-cached "refreshed …" timestamp and install picker only
// show up after a manual reload/tab switch, since nothing else re-fetches
// #servers-table on a timer.
const IMPORT_JOB_KINDS = ["cpuse.import", "cpuse.import_cloud"];
// Same idea for package actions (see services/pkgs_ops.py) — upload/keep/
// unkeep/delete all run as jobs now, so the Packages tab needs the same
// terminal-transition-triggers-a-reload treatment as the Management tab gets
// for imports, otherwise a package's new retention/existence state only
// shows up after a manual reload.
const PKGS_JOB_KINDS = ["pkgs.upload", "pkgs.keep", "pkgs.notkeep", "pkgs.delete"];
// Same idea for credential-set actions (see services/cred_ops.py) — the
// Credentials table (and any server/firewall row showing an assigned set's
// name) needs the same reload-on-finish treatment.
const CRED_JOB_KINDS = ["cred.add", "cred.edit", "cred.delete"];
const lastJobStatus = new Map();
const TERMINAL_JOB_STATUSES = ["succeeded", "failed", "cancelled", "interrupted"];

// Live count of not-yet-finished jobs, shown as a pill on the Jobs tab button.
function updateJobsBadge(jobs) {
  const pill = document.getElementById("jobs-badge");
  const n = jobs.filter((j) => j.status === "running" || j.status === "pending").length;
  pill.textContent = n;
  pill.title = `${n} job${n === 1 ? "" : "s"} running or queued`;
  pill.classList.toggle("hidden", n === 0);
}

function jobStatusClass(status) {
  return status === "succeeded" ? "ok" : status === "running" || status === "pending" ? "warn" : "err";
}

// Fills in one job row's cells/badge/cancel-button visibility. Never touches
// listeners — those are attached once in wireJobRow when the row is created,
// so calling this repeatedly (every poll) is safe and cheap.
function renderJobRow(row, job) {
  row.querySelector(".job-kind").textContent = job.kind;
  // pkgs.* jobs (upload/keep/unkeep/delete) aren't scoped to a management
  // environment and don't have a host target — they act on a package file
  // shared across every environment (visible on the Packages tab itself).
  // Give them a synthetic "Packages" env label; the Output column stays the
  // normal outcome text like every other job kind.
  const isPkgs = job.kind.startsWith("pkgs.");
  // cred.* jobs (add/edit/delete) DO have a real target — the credential set
  // name — so that stays in the Target column as-is; only the Env label is
  // overridden, since credential sets are a distinct category rather than a
  // deployment against that environment's hosts.
  const isCred = job.kind.startsWith("cred.");
  row.querySelector(".job-target").textContent = isPkgs ? "" : (job.target ?? "");
  row.querySelector(".job-env").textContent =
    isPkgs ? "Packages" : isCred ? "Credentials" : (job.environment ?? "");
  row.querySelector(".job-user").textContent = job.username ?? "";
  const badge = row.querySelector(".job-status .badge");
  badge.textContent = job.status;
  badge.className = "badge " + jobStatusClass(job.status); // reset, not add — status can change
  row.querySelector(".job-started").textContent = fmtTime(job.started_at ?? job.created_at);
  const errorCell = row.querySelector(".job-error");
  errorCell.textContent =
    job.status === "succeeded" ? `Succeeded ${fmtTime(job.finished_at)}` : (job.error ?? "");
  errorCell.title = job.status === "succeeded" ? "" : (job.error ?? ""); // full text on hover even while truncated/collapsed
  row.querySelector(".btn-cancel").classList.toggle(
    "hidden", !(job.status === "pending" || job.status === "running"),
  );
}

// A copy of CPUSE's own install log file content, once an install job has
// one (only after it finishes and CPUSE reported a log path to fetch it
// from) — a collapsed-by-default section under the job row, below the
// command-output box (the job-events row) when one is open, like the
// package hash lines on the Packages tab but foldable since log files can be
// long. Inserted/updated/removed as it appears; a <details> element keeps
// its own open/closed state across re-renders as long as the row itself
// isn't torn down, which the "sameShape" fast path in loadJobs() guarantees.
// Located by data-job-id, not position — a fixed "always row's next sibling"
// assumption broke once the events row could also claim that slot
// (operator-reported, 2026-07-23; the same class of bug toggleJobLog()
// below was already fixed for). Must run after `row` is attached to the
// table (`.after()` is a no-op on a detached node). The summary line (the
// <details> toggle) shows the on-host path the content was fetched from —
// display only, since CPUSE may since have rotated or deleted that file —
// so an operator can go find the original without digging through job
// events. Older jobs captured before install_log_path existed just omit it.
function syncInstallLogRow(row, job) {
  const jobId = row.dataset.jobId;
  let logRow = document.querySelector(`#jobs-table tr.job-install-log-row[data-job-id="${jobId}"]`);
  if (job.install_log) {
    if (!logRow) {
      logRow = el("tpl-job-install-log-row");
      logRow.dataset.jobId = jobId;
      // Below the command-output box when one is open, otherwise right
      // after the job row.
      const eventsRow = document.querySelector(`#jobs-table tr.job-events-row[data-job-id="${jobId}"]`);
      (eventsRow ?? row).after(logRow);
    }
    logRow.querySelector(".job-install-log-summary").textContent = job.install_log_path
      ? `Installation log (${fmtBytes(job.install_log.length)}): ${job.install_log_path}`
      : `Installation log (${fmtBytes(job.install_log.length)})`;
    logRow.querySelector(".job-install-log").textContent = job.install_log;
  } else if (logRow) {
    logRow.remove();
  }
}

function wireJobRow(row, jobId) {
  row.dataset.jobId = jobId;
  row.addEventListener("click", () => toggleJobLog(jobId, row));
  row.querySelector(".btn-cancel").addEventListener("click", async (ev) => {
    ev.stopPropagation(); // don't also toggle the log row
    try { await api(`/api/jobs/${jobId}/cancel`, { method: "POST" }); }
    catch (e) { toast("Cancel failed: " + e.message); }
    await loadJobs();
  });
}

// Persisted across reloads, like currentEnv. "0" means unlimited (the "All"
// option) — matches the API's own limit<=0 convention, so it passes straight
// through to /api/jobs without translation.
function jobsLimit() {
  const select = document.getElementById("jobs-limit");
  return select.value;
}

const savedJobsLimit = localStorage.getItem("jobsLimit");
if (savedJobsLimit) document.getElementById("jobs-limit").value = savedJobsLimit;
document.getElementById("jobs-limit").addEventListener("change", async () => {
  localStorage.setItem("jobsLimit", jobsLimit());
  await loadJobs();
});

// Column -> query param name; also the "jobs-filter-<field>" select id
// suffix. FACETS_KEY maps each to its /api/jobs/facets response key — NOT a
// naive "<field>s" (that broke "status", whose facets key is "statuses":
// "status" + "s" is "statuss", not a real key, so facets[...] was undefined
// and the for-of loop below threw — operator-reported, 2026-07-23, as "the
// filters show the right options but no jobs show" — because that throw
// aborted loadJobFacets() (and the loadJobs() call awaiting it) partway
// through the field loop, after kind/target/environment had already
// populated but before the table ever got rebuilt).
const JOBS_FILTER_FIELDS = ["kind", "target", "environment", "status", "user"];
const JOBS_FACETS_KEY = {
  kind: "kinds",
  target: "targets",
  environment: "environments",
  status: "statuses",
  user: "usernames",
};

function jobsFilterSelect(field) {
  return document.getElementById(`jobs-filter-${field}`);
}

// Repeated query params (?kind=a&kind=b&...), one multiselect's selections
// per field, OR'd within a field and AND'd across fields by the API.
function jobsFilterParams() {
  const params = new URLSearchParams();
  for (const field of JOBS_FILTER_FIELDS) {
    for (const opt of jobsFilterSelect(field).selectedOptions) params.append(field, opt.value);
  }
  return params;
}

// Populates each filter <select>'s options from every job that exists
// (not just the currently displayed page — that's the whole point of
// /api/jobs/facets), preserving whatever the operator already had selected.
async function loadJobFacets() {
  const facets = await api("/api/jobs/facets");
  for (const field of JOBS_FILTER_FIELDS) {
    const select = jobsFilterSelect(field);
    const selected = new Set([...select.selectedOptions].map((o) => o.value));
    select.replaceChildren();
    for (const value of facets[JOBS_FACETS_KEY[field]]) {
      const opt = new Option(value, value);
      opt.selected = selected.has(value);
      select.appendChild(opt);
    }
  }
  updateJobsFilterCount();
}

// Shown next to "Filters" even while the section is collapsed, so an active
// filter narrowing the Jobs list is never invisible (operator-reported,
// 2026-07-23 — a stuck, unnoticed filter looked exactly like missing jobs).
function updateJobsFilterCount() {
  const n = JOBS_FILTER_FIELDS.reduce(
    (total, field) => total + jobsFilterSelect(field).selectedOptions.length,
    0,
  );
  document.getElementById("jobs-filters-count").textContent = n ? `(${n} active)` : "";
}

for (const field of JOBS_FILTER_FIELDS) {
  const select = jobsFilterSelect(field);
  select.addEventListener("change", () => {
    updateJobsFilterCount();
    loadJobs();
  });
  // A plain click on a native <select multiple> option REPLACES the whole
  // selection (Ctrl/Cmd-click is required to add one) — not obvious, and an
  // easy way to accidentally filter the list down to almost nothing with a
  // single unmodified click (operator-reported, 2026-07-23). Intercept the
  // click and toggle just that option instead, so every click behaves like a
  // checkbox regardless of modifier keys.
  select.addEventListener("mousedown", (ev) => {
    if (ev.target.tagName !== "OPTION") return;
    ev.preventDefault();
    ev.target.selected = !ev.target.selected;
    select.dispatchEvent(new Event("change"));
  });
}
document.getElementById("jobs-filter-clear").addEventListener("click", async () => {
  for (const field of JOBS_FILTER_FIELDS) {
    for (const opt of jobsFilterSelect(field).options) opt.selected = false;
  }
  updateJobsFilterCount();
  await loadJobs();
});

async function loadJobs() {
  const tbody = document.querySelector("#jobs-table tbody");
  // The badge is deliberately NOT updated from this fetch — pollJobs() tracks
  // it separately from its own fixed, generous limit, so a small display
  // limit here (e.g. "10") never makes the running/pending count look lower
  // than it really is.
  const params = jobsFilterParams();
  params.set("limit", jobsLimit());
  const jobs = await api(`/api/jobs?${params.toString()}`);

  // Drop tracking for any job that's aged out of the visible list — its log
  // row won't exist after the rebuild below, so there'd be nothing to refresh.
  const currentIds = new Set(jobs.map((j) => j.id));
  for (const id of openJobLogs) if (!currentIds.has(id)) openJobLogs.delete(id);

  // While the same set of jobs (same ids, same order — the common case on a
  // poll tick) is still showing, update each row's text/badge in place
  // instead of tearing down and rebuilding the table. Rebuilding every 2.5s
  // was the source of the visible flicker, and it also blew away any open
  // log's scroll position on every tick.
  const existingRows = [...tbody.querySelectorAll("tr.job-row")];
  const sameShape =
    existingRows.length === jobs.length &&
    existingRows.every((row, i) => row.dataset.jobId === jobs[i].id);

  if (sameShape) {
    jobs.forEach((job, i) => {
      renderJobRow(existingRows[i], job);
      syncInstallLogRow(existingRows[i], job);
    });
  } else {
    // The visible set just changed shape — a plausible moment for a new
    // kind/target/environment/status to have shown up too, so refresh the
    // filter options (cheap; preserves the operator's current selections).
    // A failure here must never block rendering the jobs table itself —
    // that already happened once (2026-07-23: a facets bug threw here and
    // silently left the whole Jobs tab blank even though the job fetch
    // above had already succeeded).
    try {
      await loadJobFacets();
    } catch (e) {
      console.error("could not refresh job filter options:", e);
    }
    tbody.replaceChildren();
    for (const job of jobs) {
      const row = el("tpl-job-row");
      wireJobRow(row, job.id);
      renderJobRow(row, job);
      tbody.appendChild(row);
      // Events row (if open) before the install-log row, per the fixed order
      // (job-row, events-row, install-log-row) — syncInstallLogRow() looks
      // for an existing events row and homes the install-log row below it,
      // so build the events row first.
      if (openJobLogs.has(job.id)) row.after(buildJobLogRow(job.id));
      syncInstallLogRow(row, job);
    }
  }

  for (const jobId of openJobLogs) await refreshJobLogRow(jobId);
}

async function toggleJobLog(jobId, row) {
  if (openJobLogs.has(jobId)) {
    openJobLogs.delete(jobId);
    // Find it by id, not by position — it was previously assumed to always
    // be row's immediate next sibling, which broke (leaving it stuck open
    // and duplicating on every click) once an install-log row could also
    // occupy that slot (operator-reported, 2026-07-23).
    document.querySelector(`#jobs-table tr.job-events-row[data-job-id="${jobId}"]`)?.remove();
  } else {
    openJobLogs.add(jobId);
    // Always directly after the job row — the command-output box comes
    // first, per the fixed row order (job-row, events-row, install-log-row).
    // If an install-log row is already sitting there, this pushes it down to
    // follow the events row instead; syncInstallLogRow() locates it by
    // data-job-id rather than position, so that re-homing doesn't race with it.
    row.after(buildJobLogRow(jobId));
    await refreshJobLogRow(jobId);
  }
}

function buildJobLogRow(jobId) {
  const logRow = el("tpl-job-events");
  logRow.dataset.jobId = jobId;
  logRow.querySelector(".job-events").textContent = "loading…";
  return logRow;
}

// Updates an already-open log row's text in place. Skips the DOM write
// entirely when nothing changed, and — when the operator was scrolled to the
// bottom (following live output) — re-pins the scroll position after growing;
// otherwise leaves their scroll position alone so reading an earlier error
// isn't disrupted by the next poll.
async function refreshJobLogRow(jobId) {
  const logRow = document.querySelector(`#jobs-table tr.job-events-row[data-job-id="${jobId}"]`);
  if (!logRow) return;
  const pre = logRow.querySelector(".job-events");
  let text;
  try {
    const events = await api(`/api/jobs/${jobId}/events`);
    text = events.map((e) => `${fmtTime(e.ts)}  [${e.level}]  ${e.message}`).join("\n") || "(no events yet)";
  } catch (e) {
    text = "failed to load events: " + e.message;
  }
  if (text === pre.textContent) return;
  const wasAtBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 20;
  pre.textContent = text;
  if (wasAtBottom) pre.scrollTop = pre.scrollHeight;
}

/* Poll while any job is active so statuses and logs stay live. */
async function pollJobs() {
  try {
    const jobs = await api("/api/jobs?limit=25");
    updateJobsBadge(jobs); // keep the tab pill live even when we don't re-render

    // An import job's last step (services/patching.py) refreshes and caches
    // that server's detected state — reload the Management tab the moment
    // one finishes so the operator sees it without a manual reload. Same idea
    // for pkgs.* jobs and the Packages tab.
    let reloadServers = false;
    let reloadPackages = false;
    let reloadCredentials = false;
    for (const job of jobs) {
      const prev = lastJobStatus.get(job.id);
      const justFinished =
        (prev === "pending" || prev === "running") && TERMINAL_JOB_STATUSES.includes(job.status);
      if (justFinished && IMPORT_JOB_KINDS.includes(job.kind)) reloadServers = true;
      if (justFinished && PKGS_JOB_KINDS.includes(job.kind)) reloadPackages = true;
      if (justFinished && CRED_JOB_KINDS.includes(job.kind)) reloadCredentials = true;
      lastJobStatus.set(job.id, job.status);
    }
    const currentIds = new Set(jobs.map((j) => j.id));
    for (const id of lastJobStatus.keys()) if (!currentIds.has(id)) lastJobStatus.delete(id);

    const active = jobs.some((j) => j.status === "pending" || j.status === "running");
    if (active || openJobLogs.size) await loadJobs();
    // Any job starting/finishing for a server or firewall can change which
    // rows are blocked (see markRowIfJobActive) — not just import jobs — so
    // this is checked independently of reloadServers above.
    const targetsChanged = await refreshActiveJobTargets();
    if (reloadServers || targetsChanged) await loadServers();
    if (reloadPackages) await loadPackages();
    // A credential set's name/default status can show up on the servers/
    // firewalls tables too (assigned-set column), not just the Credentials
    // table itself.
    if (reloadCredentials) await Promise.all([loadCredentialSets(), loadServers()]);
  } catch { /* transient — next tick will retry */ }
  setTimeout(pollJobs, 2500);
}

/* ---------- boot ---------- */

(async function init() {
  initTabs();
  await initAuth(); // establish session state (logout control, idle timer) first
  const envs = await loadEnvironments(); // must resolve currentEnv before env-scoped loads
  await refreshStatus();
  await Promise.all([loadServers(), loadPackages(), loadCredentialSets(), loadJobs()]);
  updateProvisionCollapse();
  pollJobs();
  await maybeShowWelcome(envs);
})();
