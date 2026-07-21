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
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
  if (n >= 1e3) return (n / 1e3).toFixed(0) + " kB";
  return n + " B";
}

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
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

function storageEnabled(name = currentEnv) {
  return envStorage[name] !== false; // unknown → assume enabled (safe default)
}

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
        "stored credentials for it are permanently removed. This cannot be undone."
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
function openAddServerModal() {
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  document.getElementById("server-form").reset();
  document.getElementById("sm-name").disabled = false;
  document.getElementById("server-modal-title").textContent = "Add server";
  document.getElementById("server-modal-submit").textContent = "Add server";
  document.getElementById("server-modal").classList.remove("hidden");
  document.getElementById("sm-name").focus();
}
function openEditServerModal(srv) {
  document.getElementById("sm-name").value = srv.name;
  document.getElementById("sm-name").disabled = true;
  document.getElementById("sm-address").value = srv.address;
  document.getElementById("sm-role").value = srv.role;
  document.getElementById("sm-user").value = srv.ssh_user;
  document.getElementById("sm-port").value = srv.ssh_port;
  document.getElementById("server-modal-title").textContent = `Edit ${srv.name}`;
  document.getElementById("server-modal-submit").textContent = "Save changes";
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
  try {
    await addServer({
      name: document.getElementById("sm-name").value.trim(),
      address: document.getElementById("sm-address").value.trim(),
      role: document.getElementById("sm-role").value,
      ssh_user: document.getElementById("sm-user").value.trim() || "admin",
      ssh_port: Number(document.getElementById("sm-port").value) || 22,
    });
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

// Fill the primary-modal's credential-set picker from this environment's stored
// sets; storage-disabled environments have none, so hide it instead.
async function populatePrimaryCredSelect() {
  const label = document.getElementById("pm-cred-label");
  const select = document.getElementById("pm-cred-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  applyPrimaryCredUser(); // reset the SSH-user field/lock before repopulating
  const enabled = storageEnabled();
  label.classList.toggle("hidden", !enabled);
  if (!enabled) return;
  const sets = await fetchCredentialSets();
  for (const set of sets) {
    const opt = document.createElement("option");
    opt.value = set.name;
    opt.textContent = set.name;
    opt.dataset.sshUser = set.ssh_username || "";
    select.appendChild(opt);
  }
}

// A credential set already carries its own SSH username — re-typing it in the
// primary modal is redundant. When a set with one is selected, derive the SSH
// user field from it and lock it; otherwise leave it free-text.
function applyPrimaryCredUser() {
  const select = document.getElementById("pm-cred-select");
  const userInput = document.getElementById("pm-user");
  const sshUser = select.selectedOptions[0]?.dataset.sshUser;
  if (sshUser) {
    userInput.value = sshUser;
    userInput.disabled = true;
    userInput.title = "From the selected credential set";
  } else {
    userInput.disabled = false;
    userInput.title = "";
  }
}
document.getElementById("pm-cred-select").addEventListener("change", applyPrimaryCredUser);

document.getElementById("primary-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) return;
  const name = document.getElementById("pm-name").value.trim();
  const credSet = document.getElementById("pm-cred-select").value;
  try {
    await addServer({
      name,
      address: document.getElementById("pm-address").value.trim(),
      role: document.getElementById("pm-role").value,
      ssh_user: document.getElementById("pm-user").value.trim() || "admin",
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

// Open the Discover modal, populating the "Discover from" picker with the
// environment's current servers. `preselectName` pre-picks the just-added primary.
async function openDiscoverModal(preselectName) {
  if (!currentEnv) { toast("Create an environment and add a primary server first."); return; }
  let servers = [];
  try {
    servers = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`);
  } catch (e) { toast("Could not load servers: " + e.message); return; }
  if (!servers.length) {
    toast("Add a primary management server before discovering the rest.");
    return;
  }
  const select = document.getElementById("discover-primary");
  select.replaceChildren();
  for (const s of servers) {
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
      await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, address, role }),
      });
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

// Save the bootstrap username/password as a named credential set so the operator
// doesn't re-enter them. Best-effort: needs a current environment with credential
// storage enabled. Returns a status for the notes area.
async function saveBootstrapCredential(setName, username, password) {
  if (!currentEnv) return { ok: false, reason: "no environment selected" };
  if (!storageEnabled()) return { ok: false, reason: "credential storage is disabled for this environment" };
  try {
    await api(envUrl("/credentials"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: setName,
        ssh_username: username,
        ssh_password: password,
        default_if_none: true, // first credentials become the environment default
      }),
    });
    await Promise.all([loadCredentialSets(), loadServers()]);
    return { ok: true, name: setName };
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
        uid: Number(document.getElementById("prov-uid").value) || 2600,
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
};
const roleLabel = (role) => ROLE_LABELS[role] ?? role;

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

async function loadServers() {
  const tbody = document.querySelector("#servers-table tbody");
  const infoTbody = document.querySelector("#servers-info-table tbody");

  tbody.replaceChildren();
  infoTbody.replaceChildren();
  document.getElementById("prov-env-name").textContent = currentEnv ?? "—";

  if (!currentEnv) {
    // No environments defined yet — prompt the operator toward the create dialog.
    const msg = "No environments. Use the Environment picker → New Environment…";
    emptyRow(infoTbody, 7, msg);
    emptyRow(tbody, 5, msg);
    updateServersInfoControls(false);
    return;
  }

  // Patching view (assigned set per server) + editable inventory + packages +
  // the environment's credential sets (to populate the assignment dropdowns).
  const [servers, editable, packages, sets] = await Promise.all([
    api(envUrl("/servers")),
    api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`),
    api("/api/packages"),
    fetchCredentialSets(),
  ]);
  const assignedByName = new Map(servers.map((s) => [s.name, s.credential_set]));
  const storageOn = storageEnabled();

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
    info.querySelector(".btn-edit").addEventListener("click", () => openEditServerModal(srv));
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

  for (const srv of servers) {
    // Management tab: the action row, with the credential-set assignment picker.
    const row = el("tpl-server-row");
    row.querySelector(".srv-name").textContent = srv.name;
    row.querySelector(".srv-address").textContent = srv.address;

    const credSelect = row.querySelector(".srv-cred-select");
    for (const set of sets) {
      const opt = document.createElement("option");
      opt.value = set.name;
      opt.textContent = set.name;
      credSelect.appendChild(opt);
    }
    credSelect.value = srv.credential_set ?? "";
    if (storageOn) {
      credSelect.addEventListener("change", () => assignCredential(srv.name, credSelect));
    } else {
      // Storage-disabled: assignment is N/A; actions prompt for credentials.
      credSelect.disabled = true;
      credSelect.title = "This environment doesn't store credentials — actions prompt for them.";
    }

    // package dropdown for the Import action
    const select = row.querySelector(".pkg-select");
    for (const pkg of packages) {
      const opt = document.createElement("option");
      opt.value = pkg.filename;
      opt.textContent = pkg.filename;
      select.appendChild(opt);
    }

    row.querySelector(".btn-refresh").addEventListener("click", () => refreshState(srv.name, row));
    row.querySelector(".btn-import").addEventListener("click", () => importPackage(srv.name, row));
    tbody.appendChild(row);
  }

  if (!editable.length) {
    emptyRow(infoTbody, 7, "No management servers yet — click Connect to Primary SMS/MDS above.");
    emptyRow(tbody, 5, "No management servers yet — add them on the Provisioning tab.");
  }
  updateServersInfoControls(editable.length > 0);

  chooseDefaultTab(servers.length);
}

async function assignCredential(name, select) {
  const value = select.value || null;
  try {
    await api(envUrl(`/servers/${encodeURIComponent(name)}/credential`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ set: value }),
    });
    await Promise.all([loadServers(), refreshStatus()]);
  } catch (e) {
    toast("Assign failed: " + e.message);
    await loadServers(); // revert the dropdown to the stored assignment
  }
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

async function refreshState(name, row) {
  const btn = row.querySelector(".btn-refresh");
  const agentDiv = row.querySelector(".srv-agent");
  const pkgsDiv = row.querySelector(".srv-packages");
  const extra = await operationCredentials(name, "query live state");
  if (extra === null) return; // credential prompt cancelled
  btn.disabled = true;
  agentDiv.textContent = "querying…";
  try {
    const state = await api(envUrl(`/servers/${encodeURIComponent(name)}/state`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    agentDiv.textContent = state.agent_build ? `DA build ${state.agent_build}` : "";
    pkgsDiv.replaceChildren();
    for (const pkg of state.packages) {
      const card = el("tpl-detected-package");
      card.querySelector(".pkg-id").textContent = pkg.identifier;
      const badge = card.querySelector(".pkg-status");
      badge.textContent = pkg.status;
      badge.classList.add(pkg.is_installed ? "ok" : pkg.is_imported ? "warn" : "");
      // Install only makes sense for imported-but-not-installed packages.
      if (pkg.is_imported && !pkg.is_installed) {
        const ibtn = card.querySelector(".btn-install");
        ibtn.classList.remove("hidden");
        ibtn.addEventListener("click", () => installPackage(name, pkg.identifier));
      }
      pkgsDiv.appendChild(card);
    }
    if (!state.packages.length) {
      agentDiv.textContent += " — no packages reported";
    }
  } catch (e) {
    cacheEvictCreds(name); // a cached wrong/stale password re-prompts next time
    agentDiv.textContent = "detect failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function importPackage(name, row) {
  const select = row.querySelector(".pkg-select");
  if (!select.value) { toast("Choose an uploaded package first."); return; }
  const extra = await operationCredentials(name, "import a package");
  if (extra === null) return;
  try {
    await api(envUrl(`/servers/${encodeURIComponent(name)}/import`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: select.value, ...extra }),
    });
    await loadJobs();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Import failed to start: " + e.message);
  }
}

async function installPackage(name, packageId) {
  // Installs can REBOOT the management server — always confirm explicitly.
  const sure = confirm(
    `Install ${packageId} on ${name}?\n\n` +
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
      body: JSON.stringify({ package_id: packageId, confirmed: true, ...extra }),
    });
    await loadJobs();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Install failed to start: " + e.message);
  }
}

/* ---------- 3b. gateway deployment (CDT) ---------- */

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
    const sha1 = row.querySelector(".pkg-sha1");
    sha1.textContent = pkg.sha1;
    sha1.title = pkg.sha1;
    const sha256 = row.querySelector(".pkg-sha256");
    sha256.textContent = pkg.sha256;
    sha256.title = pkg.sha256;

    // Retention: ticked "Keep" == pinned (no expiry). Otherwise show the deadline.
    const pin = row.querySelector(".pkg-pin");
    const expiry = row.querySelector(".pkg-expiry");
    const renderRetention = (rec) => {
      pin.checked = rec.expires_at == null;
      expiry.textContent = rec.expires_at ? `expires ${fmtTime(rec.expires_at)}` : "kept indefinitely";
    };
    renderRetention(pkg);
    pin.addEventListener("change", async () => {
      pin.disabled = true;
      try {
        const updated = await api(`/api/packages/${encodeURIComponent(pkg.filename)}/retention`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pinned: pin.checked }),
        });
        renderRetention(updated);
      } catch (e) {
        pin.checked = !pin.checked; // revert the optimistic toggle
        toast("Could not update retention: " + e.message);
      } finally {
        pin.disabled = false;
      }
    });

    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete package ${pkg.filename}?`)) return;
      try {
        await api(`/api/packages/${encodeURIComponent(pkg.filename)}`, { method: "DELETE" });
        await Promise.all([loadPackages(), loadServers(), refreshStatus()]);
      } catch (e) { toast("Delete failed: " + e.message); }
    });
    tbody.appendChild(row);
  }
  await populateCdtSelectors(); // keep the CDT dropdowns in sync with packages/servers
}

// Shared upload path for the form and drag & drop.
async function uploadPackageFile(file) {
  const progress = document.getElementById("upload-progress");
  const btn = document.getElementById("upload-btn");
  const form = new FormData();
  form.append("file", file);
  btn.disabled = true;
  progress.textContent = `uploading ${file.name}… (large packages take a while)`;
  try {
    await api("/api/packages", { method: "POST", body: form });
    progress.textContent = `${file.name}: done`;
    await Promise.all([loadPackages(), loadServers(), refreshStatus()]);
  } catch (e) {
    progress.textContent = "";
    toast(`Upload of ${file.name} failed: ` + e.message);
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
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete credential set "${set.name}"? Servers using it lose access.`)) return;
      try {
        await api(envUrl(`/credentials/${encodeURIComponent(set.name)}`), { method: "DELETE" });
        await Promise.all([loadCredentialSets(), loadServers()]);
      } catch (e) { toast("Delete failed: " + e.message); }
    });
    tbody.appendChild(row);
  }
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
    await api(envUrl("/credentials"), {
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
    closeCredAddModal(); // resets the form so no secrets linger in the DOM
    await Promise.all([loadCredentialSets(), loadServers()]);
  } catch (e) {
    toast("Save failed: " + e.message);
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

// Live count of not-yet-finished jobs, shown as a pill on the Jobs tab button.
function updateJobsBadge(jobs) {
  const pill = document.getElementById("jobs-badge");
  const n = jobs.filter((j) => j.status === "running" || j.status === "pending").length;
  pill.textContent = n;
  pill.title = `${n} job${n === 1 ? "" : "s"} running or queued`;
  pill.classList.toggle("hidden", n === 0);
}

async function loadJobs() {
  const tbody = document.querySelector("#jobs-table tbody");
  const jobs = await api("/api/jobs?limit=25");
  updateJobsBadge(jobs);
  tbody.replaceChildren();
  for (const job of jobs) {
    const row = el("tpl-job-row");
    row.querySelector(".job-kind").textContent = job.kind;
    row.querySelector(".job-target").textContent = job.target ?? "";
    row.querySelector(".job-env").textContent = job.environment ?? "";
    const badge = row.querySelector(".job-status .badge");
    badge.textContent = job.status;
    badge.classList.add(
      job.status === "succeeded" ? "ok" :
      job.status === "running" || job.status === "pending" ? "warn" : "err",
    );
    row.querySelector(".job-started").textContent = fmtTime(job.started_at ?? job.created_at);
    row.querySelector(".job-error").textContent = job.error ?? "";

    if (job.status === "pending" || job.status === "running") {
      const cbtn = row.querySelector(".btn-cancel");
      cbtn.classList.remove("hidden");
      cbtn.addEventListener("click", async (ev) => {
        ev.stopPropagation(); // don't also toggle the log row
        try { await api(`/api/jobs/${job.id}/cancel`, { method: "POST" }); }
        catch (e) { toast("Cancel failed: " + e.message); }
        await loadJobs();
      });
    }

    row.addEventListener("click", () => toggleJobLog(job.id, row));
    tbody.appendChild(row);

    if (openJobLogs.has(job.id)) {
      tbody.appendChild(await buildJobLogRow(job.id));
    }
  }
}

async function toggleJobLog(jobId, row) {
  if (openJobLogs.has(jobId)) {
    openJobLogs.delete(jobId);
    row.nextElementSibling?.classList.contains("job-events-row") && row.nextElementSibling.remove();
  } else {
    openJobLogs.add(jobId);
    row.after(await buildJobLogRow(jobId));
  }
}

async function buildJobLogRow(jobId) {
  const logRow = el("tpl-job-events");
  try {
    const events = await api(`/api/jobs/${jobId}/events`);
    logRow.querySelector(".job-events").textContent = events
      .map((e) => `${fmtTime(e.ts)}  [${e.level}]  ${e.message}`)
      .join("\n") || "(no events yet)";
  } catch (e) {
    logRow.querySelector(".job-events").textContent = "failed to load events: " + e.message;
  }
  return logRow;
}

/* Poll while any job is active so statuses and logs stay live. */
async function pollJobs() {
  try {
    const jobs = await api("/api/jobs?limit=25");
    updateJobsBadge(jobs); // keep the tab pill live even when we don't re-render
    const active = jobs.some((j) => j.status === "pending" || j.status === "running");
    if (active || openJobLogs.size) await loadJobs();
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
  pollJobs();
  await maybeShowWelcome(envs);
})();
