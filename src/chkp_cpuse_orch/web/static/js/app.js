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

  const sessionUserBtn = document.getElementById("session-user");
  try {
    const me = await api("/api/auth/me");
    if (me.username) {
      sessionUserBtn.textContent = `Signed in as ${me.username}`;
    }
    // Only basic-auth passwords are ours to change — LDAP is directory-managed.
    // The username reads as plain text (see .static in app.css) unless clickable.
    if (me.backend === "basic") {
      sessionUserBtn.addEventListener("click", openUserSettingsModal);
    } else {
      sessionUserBtn.classList.add("static");
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

// User Settings modal (basic-auth only): change the signed-in user's password.
function openUserSettingsModal() {
  const modal = document.getElementById("user-settings-modal");
  document.getElementById("user-settings-form").reset();
  document.getElementById("user-settings-error").classList.add("hidden");
  modal.classList.remove("hidden");
  document.getElementById("us-current-password").focus();
}

function closeUserSettingsModal() {
  document.getElementById("user-settings-modal").classList.add("hidden");
  document.getElementById("user-settings-form").reset(); // plaintext leaves the DOM
}

document.getElementById("user-settings-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const errorBox = document.getElementById("user-settings-error");
  errorBox.classList.add("hidden");
  const current = document.getElementById("us-current-password").value;
  const next = document.getElementById("us-new-password").value;
  const confirm = document.getElementById("us-confirm-password").value;
  if (next !== confirm) {
    errorBox.textContent = "New password and confirmation don't match.";
    errorBox.classList.remove("hidden");
    return;
  }
  try {
    await api("/api/auth/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: current, new_password: next }),
    });
    closeUserSettingsModal();
    toast("Password changed.");
  } catch (e) {
    errorBox.textContent = e.message;
    errorBox.classList.remove("hidden");
  }
});
document.getElementById("user-settings-cancel").addEventListener("click", closeUserSettingsModal);
document.getElementById("user-settings-close").addEventListener("click", closeUserSettingsModal);
document.getElementById("user-settings-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "user-settings-modal") closeUserSettingsModal(); // backdrop click cancels
});

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
async function operationCredentials(host, purpose, env = currentEnv) {
  if (storageEnabled(env)) return {};
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
  closeConnectPrimaryConfirmModal();
  closeApiKeyRevealModal();
  closeServerModal();
  closeUninstallModal();
  hideWelcome(); // soft close — the welcome dialog returns next load if still fresh
});

document.getElementById("env-add-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("env-add-name");
  try {
    const created = await api("/api/environments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: input.value }),
    });
    input.value = "";
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
// `credential_set` (string, null, or omitted/undefined) rides in the same
// prov.add/prov.edit job the server (add or edit) itself now runs as — see
// services/prov_ops.py. Undefined serializes to an absent JSON key (leave any
// existing/default-on-create assignment alone); null explicitly clears it.
// Executes immediately (services/prov_ops.py) — returns the already-finished
// JobRecord; callers still prime lastJobStatus with it so pollJobs() (and any
// other tab/session polling) picks up the real outcome without a re-fetch.
async function addServer({ name, address, role, ssh_user, ssh_port, credential_set }) {
  return await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, address, role, ssh_user, ssh_port, credential_set }),
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
  populateRoleSelect(document.getElementById("sm-role"), !!envIsMds[currentEnv]);
  await populateServerCredSelect();
  document.getElementById("server-modal").classList.remove("hidden");
  document.getElementById("sm-name").focus();
}
async function openEditServerModal(srv, assignedSetName) {
  document.getElementById("sm-name").value = srv.name;
  document.getElementById("sm-name").disabled = true;
  document.getElementById("sm-address").value = srv.address;
  populateRoleSelect(document.getElementById("sm-role"), !!envIsMds[currentEnv], srv.role);
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
    // Executes immediately as a tracked prov.add/prov.edit job
    // (services/prov_ops.py) — the response is already the finished job, so
    // a validation failure (e.g. bad role, name collision) is known right
    // here, not just on a later Jobs-tab poll.
    const job = await addServer({
      name,
      address: document.getElementById("sm-address").value.trim(),
      role: document.getElementById("sm-role").value,
      ssh_user: sshUser,
      ssh_port: Number(document.getElementById("sm-port").value) || 22,
      // Storage-enabled: always explicit (clears to null if left at "none"),
      // matching this modal's previous always-fires-the-assignment behavior.
      credential_set: storageEnabled() ? (credSet || null) : undefined,
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
    if (job.status !== "succeeded") {
      toast("Save failed: " + (job.error || "unknown error"));
      await loadJobs();
      return;
    }
    closeServerModal();
    await Promise.all([loadJobs(), loadServers(), refreshStatus()]);
  } catch (e) { toast("Save failed: " + e.message); }
});
document.getElementById("server-modal-close").addEventListener("click", closeServerModal);
document.getElementById("server-modal-cancel").addEventListener("click", closeServerModal);
document.getElementById("server-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "server-modal") closeServerModal(); // backdrop closes
});

/* ---------- 1c-primary. connect to primary (inline panel + confirm/reveal modals) ---------- */

// Storage-enabled environments pick an SSH identity from a stored credential
// set (no free-text username — the set's ssh_username drives it); storage-
// disabled environments have no sets to pick from, so they type a username.
// Called from loadCredentialSets() so the select stays in sync with the
// Credentials table (this panel is always inline, never opened on demand).
function populateConnectPrimaryCredSelect() {
  const enabled = storageEnabled();
  document.getElementById("cp-user-label").classList.toggle("hidden", enabled);
  document.getElementById("cp-cred-label").classList.toggle("hidden", !enabled);
  if (!enabled) return;
  const select = document.getElementById("cp-cred-select");
  const previous = select.value;
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  let defaultName = "";
  for (const set of credentialSets) {
    const opt = document.createElement("option");
    opt.value = set.name;
    opt.textContent = set.name;
    opt.dataset.sshUser = set.ssh_username || "";
    select.appendChild(opt);
    if (set.is_default) defaultName = set.name;
  }
  // Keep an already-chosen set across reloads (e.g. after a job finishes);
  // otherwise auto-pick the one marked "default" instead of leaving this on
  // the "none — assign later" placeholder.
  const stillExists = credentialSets.some((s) => s.name === previous);
  select.value = stillExists ? previous : defaultName;
}

function connectPrimaryStatus(message, cls) {
  const box = document.getElementById("cp-status");
  box.textContent = message;
  box.classList.remove("prov-note-warn", "prov-note-err", "prov-note-ok");
  if (cls) box.classList.add(`prov-note-${cls}`);
  box.classList.toggle("hidden", !message);
}

// Set by the form submit (after a successful preview fetch), read by the
// confirm modal's Run button — the two-step "preview then confirm" flow this
// repo's dry-run-first convention calls for before mutating a management
// server over SSH.
let _connectPrimaryPayload = null;

document.getElementById("connect-primary-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  const name = document.getElementById("cp-name").value.trim();
  const address = document.getElementById("cp-address").value.trim();
  if (!name || !address) { toast("Name and address are required."); return; }
  const credSelect = document.getElementById("cp-cred-select");
  const credSet = storageEnabled() ? credSelect.value || null : null;
  const sshUser = storageEnabled()
    ? credSelect.selectedOptions[0]?.dataset.sshUser || "admin"
    : document.getElementById("cp-user").value.trim() || "admin";
  _connectPrimaryPayload = {
    name,
    address,
    role: document.getElementById("cp-role").value,
    ssh_user: sshUser,
    ssh_port: Number(document.getElementById("cp-port").value) || 22,
    credential_set: credSet,
  };
  try {
    const preview = await api(
      `/api/environments/${encodeURIComponent(currentEnv)}/connect-primary/preview` +
        `?username=${encodeURIComponent(sshUser)}`,
    );
    document.getElementById("connect-primary-confirm-target").textContent = `${name} (${address})`;
    document.getElementById("connect-primary-confirm-output").textContent = preview.commands.join("\n");
    const notesBox = document.getElementById("connect-primary-confirm-notes");
    notesBox.replaceChildren();
    for (const n of preview.notes || []) {
      const p = document.createElement("p");
      const warn = n.startsWith(PROV_NOTE_EMPHASIS);
      p.textContent = warn ? n.slice(PROV_NOTE_EMPHASIS.length) : n;
      if (warn) p.classList.add("prov-note-warn");
      notesBox.appendChild(p);
    }
    notesBox.classList.toggle("hidden", !notesBox.childElementCount);
    document.getElementById("connect-primary-confirm-modal").classList.remove("hidden");
  } catch (e) {
    toast("Could not render command preview: " + e.message);
  }
});

function closeConnectPrimaryConfirmModal() {
  document.getElementById("connect-primary-confirm-modal").classList.add("hidden");
}
document.getElementById("connect-primary-confirm-close").addEventListener("click", closeConnectPrimaryConfirmModal);
document.getElementById("connect-primary-confirm-cancel").addEventListener("click", closeConnectPrimaryConfirmModal);
document.getElementById("connect-primary-confirm-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "connect-primary-confirm-modal") closeConnectPrimaryConfirmModal();
});

document.getElementById("connect-primary-confirm-run").addEventListener("click", async () => {
  if (!_connectPrimaryPayload || !currentEnv) return;
  const payload = _connectPrimaryPayload;
  _connectPrimaryPayload = null;
  closeConnectPrimaryConfirmModal();
  const btn = document.getElementById("connect-primary-btn");
  btn.disabled = true;
  connectPrimaryStatus(`Connecting to ${payload.name}…`);
  try {
    const job = await api(`/api/environments/${encodeURIComponent(currentEnv)}/connect-primary`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if it finishes fast
    await Promise.all([loadJobs(), loadServers(), refreshStatus()]);
    // A real correctness dependency (not just cosmetic), same rationale as
    // discovery's own waitForJobDone use: the reveal-key fetch right below
    // only makes sense once the job has actually finished. SSH + several
    // mgmt_cli round-trips can take a while, so this gets a longer budget
    // than the 5s default.
    const finished = await waitForJobDone(job.id, { timeoutMs: 30000 });
    if (!finished) {
      connectPrimaryStatus("Still running — check the Jobs tab for progress.", "warn");
      return;
    }
    await Promise.all([loadJobs(), loadServers(), loadCredentialSets(), refreshStatus()]);
    if (finished.status !== "succeeded") {
      connectPrimaryStatus(
        `Connect to Primary failed: ${finished.error || "see the Jobs tab for details"}`,
        "err",
      );
      return;
    }
    connectPrimaryStatus("Connected — Management API access provisioned.", "ok");
    const reveal = await api(`/api/jobs/${encodeURIComponent(job.id)}/reveal-api-key`);
    if (reveal.api_key) openApiKeyRevealModal(reveal.api_key, payload.credential_set);
    // Explicit collapse right at the success moment this workflow step asks
    // for — updateProvisionCollapse() itself only runs on env load/switch, by
    // design, so it wouldn't otherwise react to finishing this just now.
    if (hasProvisionedPrimary) {
      document.getElementById("provision-details").open = false;
      document.getElementById("connect-primary-details").open = false;
    }
    // Proactively confirm the Management API is actually reachable right where
    // it was just provisioned, rather than leaving an accessibility problem to
    // surface later as a confusing 403 during discovery.
    checkApiAccessAfterConnect();
  } catch (e) {
    connectPrimaryStatus("Connect to Primary failed: " + e.message, "err");
  } finally {
    btn.disabled = false;
  }
});

/* ---------- api accessibility check — proactive follow-up to Connect to --- */
/* ---------- Primary above, over SSH (see services/api_access.py) ---------- */

// Same orange/red/green convention as connectPrimaryStatus (prov-note-warn/
// -err/-ok) — used here so a functionality-blocking accessibility problem
// (restricted to localhost, or the API not started at all) reads as an
// unmissable orange call-out instead of blending into the muted hint text.
function setApiAccessMessage(text, cls) {
  const msg = document.getElementById("cp-api-access-message");
  msg.textContent = text;
  msg.classList.remove("prov-note-warn", "prov-note-err", "prov-note-ok");
  if (cls) msg.classList.add(`prov-note-${cls}`);
}

async function checkApiAccessAfterConnect() {
  if (!currentEnv) return;
  const box = document.getElementById("cp-api-access");
  const repairBtn = document.getElementById("cp-api-access-repair");
  box.classList.remove("hidden");
  repairBtn.classList.add("hidden");
  setApiAccessMessage("Checking API accessibility over SSH…");
  try {
    const diag = await api(
      `/api/environments/${encodeURIComponent(currentEnv)}/api-access/diagnose`,
      { method: "POST" },
    );
    if (diag.error) {
      setApiAccessMessage("Could not check API accessibility: " + diag.error, "err");
    } else if (diag.restricted_to_local) {
      setApiAccessMessage(
        "Heads up: the Management API only accepts connections from the management " +
          "server itself (accessibility: require local) — this app won't be able to reach " +
          "it for discovery or package-repo pushes until that's widened.",
        "warn",
      );
      repairBtn.classList.remove("hidden");
    } else if (!diag.overall_started) {
      setApiAccessMessage(
        "Heads up: the API service does not appear to be started on this server — " +
          "check `api status` on it directly, or start it with `api start`.",
        "warn",
      );
    } else {
      box.classList.add("hidden"); // reachable and unrestricted — nothing to show
    }
  } catch (e) {
    setApiAccessMessage("Could not check API accessibility: " + e.message, "err");
  }
}

document.getElementById("cp-api-access-repair").addEventListener("click", async () => {
  if (!currentEnv) return;
  try {
    const preview = await api(
      `/api/environments/${encodeURIComponent(currentEnv)}/api-access/repair-preview`,
    );
    document.getElementById("api-access-repair-confirm-output").textContent =
      preview.commands.join("\n");
    document.getElementById("api-access-repair-confirm-modal").classList.remove("hidden");
  } catch (e) {
    toast("Could not render command preview: " + e.message);
  }
});

function closeApiAccessRepairConfirmModal() {
  document.getElementById("api-access-repair-confirm-modal").classList.add("hidden");
}
document.getElementById("api-access-repair-confirm-close").addEventListener(
  "click", closeApiAccessRepairConfirmModal,
);
document.getElementById("api-access-repair-confirm-cancel").addEventListener(
  "click", closeApiAccessRepairConfirmModal,
);
document.getElementById("api-access-repair-confirm-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "api-access-repair-confirm-modal") closeApiAccessRepairConfirmModal();
});

document.getElementById("api-access-repair-confirm-run").addEventListener("click", async () => {
  if (!currentEnv) return;
  closeApiAccessRepairConfirmModal();
  setApiAccessMessage("Repairing API access over SSH…");
  try {
    const job = await api(`/api/environments/${encodeURIComponent(currentEnv)}/api-access/repair`, {
      method: "POST",
    });
    lastJobStatus.set(job.id, job.status);
    await loadJobs();
    // api restart plus several mgmt_cli round-trips can take a while — same
    // longer budget as connect-primary's own waitForJobDone use.
    const finished = await waitForJobDone(job.id, { timeoutMs: 30000 });
    if (!finished) {
      setApiAccessMessage("Still running — check the Jobs tab for progress.", "warn");
      return;
    }
    await loadJobs();
    if (finished.status !== "succeeded") {
      setApiAccessMessage(
        `Repair failed: ${finished.error || "see the Jobs tab for details"}`,
        "err",
      );
      return;
    }
    setApiAccessMessage("Repaired — the API now accepts connections from this server.", "ok");
    document.getElementById("cp-api-access-repair").classList.add("hidden");
  } catch (e) {
    setApiAccessMessage("Repair failed: " + e.message, "err");
  }
});

function openApiKeyRevealModal(apiKey, credentialSetName) {
  document.getElementById("api-key-reveal-output").textContent = apiKey;
  const saved = document.getElementById("api-key-reveal-saved");
  if (credentialSetName) {
    saved.textContent = `Also saved to credential set "${credentialSetName}".`;
    saved.classList.remove("hidden");
  } else {
    saved.classList.add("hidden");
  }
  document.getElementById("api-key-reveal-modal").classList.remove("hidden");
}
function closeApiKeyRevealModal() {
  document.getElementById("api-key-reveal-modal").classList.add("hidden");
  document.getElementById("api-key-reveal-output").textContent = ""; // don't linger in the DOM
}
document.getElementById("api-key-reveal-close").addEventListener("click", closeApiKeyRevealModal);
document.getElementById("api-key-reveal-done").addEventListener("click", closeApiKeyRevealModal);
document.getElementById("api-key-reveal-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "api-key-reveal-modal") closeApiKeyRevealModal();
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
    populateRoleSelect(roleSel, !!envIsMds[currentEnv], s.role);
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
      // Add executes immediately as a prov.add job (services/prov_ops.py), so
      // the response already carries the real outcome (e.g. a name collision
      // fails the job right here, not just on a later Jobs-tab poll).
      const job = await api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name, address, role, ssh_user: discoverPrimarySshUser,
          credential_set: (storageEnabled() && discoverPrimaryCredSet) || undefined,
        }),
      });
      lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
      if (job.status === "succeeded") ok++;
      else failed.push(`${name}: ${job.error || "unknown error"}`);
    } catch (e) { failed.push(`${name}: ${e.message}`); }
  }
  await Promise.all([loadJobs(), loadServers(), refreshStatus()]);
  if (failed.length) {
    toast(`Imported ${ok}. Failed: ${failed.join("; ")}`);
    importBtn.disabled = false;
  } else {
    closeDiscoverModal();
  }
});

// Hidden until hasProvisionedPrimary (see updateServersInfoControls) — the
// primary itself is now added via the Connect to Primary panel above, not a
// modal reached from here.
document.getElementById("discover-btn").addEventListener("click", () => openDiscoverModal());
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
    // CHKP_CPUSE_SHOW_TAB_HINTS (default true — hide only on an explicit false).
    document.getElementById("tab-guide-viewport").classList.toggle("hidden", s.show_tab_hints === false);
    positionTabGuide();
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
// into the notes box that sits directly above the clish command block.
// `credStatus` reports how saving the bootstrap credential set went.
function renderProvNotes(resp, credStatus) {
  const clishBox = document.getElementById("prov-clish-notes");
  const credBox = document.getElementById("prov-cred-status");
  clishBox.replaceChildren();
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
  // The saved-credential status is a panel-wide outcome, so it goes at the very
  // bottom, below the output box.
  if (credStatus) {
    if (credStatus.ok) {
      group(credBox, "Credentials", [
        `Saved credential set “${credStatus.name}” to the Credentials table below — ` +
          "pick it in step 2 (Connect to Primary) once you've applied these commands.",
      ]);
    } else {
      group(credBox, "Credentials", [PROV_NOTE_EMPHASIS +
        `Credentials not saved (${credStatus.reason}). Add them in the Credentials table.`]);
    }
  }
  clishBox.classList.toggle("hidden", !clishBox.childElementCount);
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
    // Executes immediately (services/cred_ops.py); "ok: true" means "stored",
    // not "queued" — tracked as a finished cred.add/cred.edit job for the
    // Jobs tab only.
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
    lastJobStatus.set(job.id, job.status);
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
  for (const id of ["prov-clish-notes", "prov-clish-wrap", "prov-cred-status"]) {
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
      // No uid field — this tool always provisions uid 0 (matching the
      // built-in adminRole accounts it mirrors), so the backend's default
      // applies unconditionally; there's nothing here for the operator to change.
      body: JSON.stringify({ username, password }),
    });
    passwordInput.value = ""; // plaintext leaves the page as soon as possible
    // Save the same credentials to the table so the operator needn't re-enter them.
    const credStatus = await saveBootstrapCredential(credName, username, password);
    renderProvNotes(resp, credStatus);
    // Commands only (no comment lines).
    document.getElementById("prov-clish-output").textContent = resp.commands.join("\n");
    document.getElementById("prov-clish-wrap").classList.remove("hidden");
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
  spark_firewall: "Spark Firewall",
};
const roleLabel = (role) => ROLE_LABELS[role] ?? role;

// Role choices offered when adding/editing a management server, filtered by
// the environment's SMS-vs-MDS kind (an environment is always entirely one
// or the other — see envIsMds/loadEnvironments). SmartEvent applies to both.
const SMS_SERVER_ROLES = ["primary_sms", "secondary_sms", "log_server", "smartevent"];
const MDS_SERVER_ROLES = ["primary_mds", "secondary_mds", "mlm", "smartevent"];

// Rebuilds a role <select>'s options for the given SMS/MDS kind. If `selected`
// isn't one of that kind's roles (e.g. a legacy management/mds row being
// edited), it's kept as an extra leading option so saving doesn't silently
// change it.
function populateRoleSelect(select, isMds, selected) {
  const roles = isMds ? MDS_SERVER_ROLES : SMS_SERVER_ROLES;
  const values = selected && !roles.includes(selected) ? [selected, ...roles] : roles;
  select.replaceChildren(...values.map((role) => {
    const opt = document.createElement("option");
    opt.value = role;
    opt.textContent = roleLabel(role);
    return opt;
  }));
  select.value = selected ?? roles[0];
}

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

// Whether the environment's primary management server is fully provisioned:
// present in inventory AND (storage-enabled environments only — see
// loadServers) its assigned credential set already has a working API key.
// Drives whether "Discover servers"/"Manually add a server" are shown, and
// (via updateProvisionCollapse) the Bootstrap/Connect-to-Primary panels'
// default collapse state.
let hasProvisionedPrimary = false;

function updateServersInfoControls(provisioned) {
  hasProvisionedPrimary = provisioned;
  document.getElementById("discover-btn").classList.toggle("hidden", !provisioned);
  document.getElementById("add-server-btn").classList.toggle("hidden", !provisioned);
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

// loadServers()/loadFirewalls() tear down and rebuild every row from scratch
// on each call — including background polls the operator never asked for
// (pollJobs() reloads the whole table on ANY job's active-set change in the
// environment, not just the row in question — see refreshActiveJobTargets).
// Without this, a poll landing between "pick a package" and "click Install"
// silently resets the row's <select> to its blank placeholder and disables
// the Install button out from under the operator — a disabled button doesn't
// even dispatch a click, so it looked like the first click "did nothing" and
// a second one (after unknowingly re-picking the package) was needed
// (operator-reported, 2026-07-31). Capture each row's in-flight choice before
// the rebuild and reapply it by host name afterward.
function captureRowSelections(tbody, nameSelector) {
  const saved = new Map();
  for (const row of tbody.querySelectorAll("tr.srv-row")) {
    const name = row.querySelector(nameSelector)?.textContent;
    if (!name) continue;
    saved.set(name, {
      value: row.querySelector(".install-select").value,
      skipVerify: row.querySelector(".skip-verify").checked,
    });
  }
  return saved;
}

function restoreRowSelection(row, hostName, saved) {
  const prior = saved.get(hostName);
  if (!prior || !prior.value) return;
  const select = row.querySelector(".install-select");
  if (!select.querySelector(`option[value="${CSS.escape(prior.value)}"]`)) return; // no longer offered
  select.value = prior.value;
  row.querySelector(".skip-verify").checked = prior.skipVerify;
  syncActionButtons(row);
}

// See loadFirewalls()'s matching guard/comment — same race, same fix: bail
// out of a stale call rather than let two concurrent loads each clear-then-
// append and double every row.
let _serversLoadToken = 0;

async function loadServers() {
  const token = ++_serversLoadToken;
  const tbody = document.querySelector("#servers-table tbody");
  const infoTbody = document.querySelector("#servers-info-table tbody");

  if (!currentEnv) {
    // No environments defined yet — prompt the operator toward the create dialog.
    tbody.replaceChildren();
    infoTbody.replaceChildren();
    const msg = "No environments. Use the Environment picker → New Environment…";
    emptyRow(infoTbody, 7, msg);
    emptyRow(tbody, 5, msg);
    updateServersInfoControls(false);
    return;
  }

  // Patching view (assigned set per server) + editable inventory + the
  // package catalog (for the bulk-import picker above the table) + credential
  // sets (to check the primary's API-key status) + which hosts already have a
  // job in flight (blocks starting another). Fetched here directly (not read
  // off the shared `credentialSets` global) since this can run concurrently
  // with loadCredentialSets() (see selectEnvironment) and a stale read would
  // wrongly gate the Discover/Add-a-server buttons.
  const [servers, editable, packages, sets] = await Promise.all([
    api(envUrl("/servers")),
    api(`/api/environments/${encodeURIComponent(currentEnv)}/servers`),
    api("/api/packages"),
    fetchCredentialSets(),
  ]);
  await refreshActiveJobTargets();
  if (token !== _serversLoadToken) return; // a newer call started — let it render instead

  const savedSelections = captureRowSelections(tbody, ".srv-name-link");
  tbody.replaceChildren();
  infoTbody.replaceChildren();
  const assignedByName = new Map(servers.map((s) => [s.name, s.credential_set]));
  const stateByName = new Map(servers.map((s) => [s.name, s]));

  const bulkPackageSelect = document.getElementById("bulk-import-package");
  bulkPackageSelect.replaceChildren(new Option("— package —", ""));
  for (const pkg of packages) bulkPackageSelect.appendChild(new Option(pkg.filename, pkg.filename));

  for (const srv of sortByRole(editable)) {
    // Provisioning tab: inventory row with a Remove action (env management —
    // patching actions stay on the Management tab). Same ordering as the
    // CPUSE tab's table below (sortByRole) for consistency between the two.
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
        // Executes immediately as a tracked prov.delete job — see the server
        // form submit handler above for the same immediate-outcome model.
        const job = await api(
          `/api/environments/${encodeURIComponent(currentEnv)}/servers/${encodeURIComponent(srv.name)}`,
          { method: "DELETE" },
        );
        lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
        if (job.status !== "succeeded") toast("Remove failed: " + (job.error || "unknown error"));
        await Promise.all([loadJobs(), loadServers(), refreshStatus()]);
      } catch (e) { toast("Remove failed: " + e.message); }
    });
    infoTbody.appendChild(info);
  }

  for (const srv of sortByRole(editable)) {
    // Management tab: the action row. Credential assignment is display-only
    // here — change it via Edit on the Provisioning tab. Iterates `editable`
    // (full CRUD fields, including ssh_port) rather than the patching-view
    // `servers` list, cross-referenced via stateByName for the cached CPUSE
    // state — same split loadFirewalls() uses, needed here too now that the
    // name doubles as the row's Edit trigger (openEditServerModal wants
    // ssh_port, which the patching view doesn't carry).
    const state = stateByName.get(srv.name);
    const row = el("tpl-server-row");
    const selectCb = row.querySelector(".srv-select");
    selectCb.dataset.server = srv.name; // read by the bulk-import buttons
    selectCb.addEventListener("change", updateSelectAllState);
    markRowIfJobActive(selectCb, srv.name);
    row.querySelector(".srv-name-link").textContent = srv.name;
    row.querySelector(".srv-address").textContent = srv.address;
    row.querySelector(".srv-role").textContent = roleLabel(srv.role);
    renderInstallSelect(row, state?.installable ?? [], state?.installed ?? [], srv.name);
    row.querySelector(".skip-verify").checked = !!envSkipVerifyDefault[currentEnv];
    restoreRowSelection(row, srv.name, savedSelections);

    const stateRow = el("tpl-server-state-row");
    stateRow.dataset.server = srv.name; // looked up by the "Refresh all" button
    renderStateRow(stateRow, state && state.checked_at ? state : null);
    stateRow
      .querySelector(".srv-refresh-link")
      .addEventListener("click", () => refreshState(srv.name, row, stateRow));
    row.querySelector(".btn-install").addEventListener("click", () => installPackage(srv.name, row));
    row.querySelector(".btn-uninstall").addEventListener("click", () => openUninstallModal("server", srv.name, row));
    // The name itself is a second Edit trigger, mirroring the Firewalls
    // table below — the Provisioning tab's own Edit button (above) still
    // works the same way.
    row.querySelector(".srv-name-link").addEventListener("click", () => {
      openEditServerModal(srv, assignedByName.get(srv.name));
    });
    tbody.appendChild(row);
    tbody.appendChild(stateRow);
  }

  if (!editable.length) {
    emptyRow(infoTbody, 7, "No management servers yet — complete Connect to Primary above.");
    emptyRow(tbody, 5, "No management servers yet — add them on the Provisioning tab.");
  }
  // Primary must both exist and (storage-enabled environments only — there's
  // no durable "already provisioned" signal without a stored credential set)
  // have a working API key on its assigned credential set.
  const primary = editable.find((s) => s.role === "primary_sms" || s.role === "primary_mds");
  let provisioned = !!primary;
  if (primary && storageEnabled()) {
    const setName = assignedByName.get(primary.name);
    const set = setName ? sets.find((s) => s.name === setName) : null;
    provisioned = !!set?.has_api;
  }
  updateServersInfoControls(provisioned);
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
  summary.replaceChildren();
  if (data == null) {
    summary.textContent = "Not yet checked.";
    checked.textContent = "";
    return false;
  }
  // ClusterXL role, when this host is a live cluster member. cluster_role is
  // refreshed every check (live `cphaprob`); cluster_name is the firewall's
  // stored real cluster object name (set at discovery time, or via the edit
  // modal's "Re-check cluster membership") — see clusterxl-live-state memory.
  // Only shown once both are known; a role with no stored name yet (e.g. a
  // manually-added firewall never re-checked) omits this first line entirely
  // rather than showing a misleading blank. cluster_name is only ever present
  // on firewall records (never management servers — see /api/env/{env}/servers
  // in app.py), so this branch never fires for the Servers table's shared
  // renderStateRow call.
  const hasClusterLine = !!(data.cluster_role && data.cluster_name);
  if (hasClusterLine) {
    const role = data.cluster_role.toUpperCase();
    const label = role.startsWith("ACTIVE") ? "Active"
      : role.startsWith("STANDBY") ? "Standby"
      : data.cluster_role;
    const cluster = document.createElement("span");
    cluster.className = role.startsWith("ACTIVE") ? "cluster-active"
      : role.startsWith("STANDBY") ? "cluster-standby"
      : "cluster-other";
    cluster.textContent = `${label} cluster member in ${data.cluster_name}`;
    summary.appendChild(cluster);
    summary.appendChild(document.createElement("br"));
  }
  const agentBuild = formatAgentBuild(data.agent_build);
  summary.appendChild(document.createTextNode(
    `Running ${data.version ?? "—"} w/JHF ${data.jhf ?? "—"} | CPUSE Agent `
  ));
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
  return hasClusterLine;
}

// Options are the server's cached `installable` (imported, not yet installed)
// and `installed` lists — refreshed alongside the summary row, never the
// full package catalog, since importing something not yet on the host is
// Import's job (not exposed on this page; see the Provisioning tab's Edit
// modal for credential assignment and .claude/memory/patching-web-design.md
// for why Import isn't here). Grouped into optgroups so an operator can tell
// at a glance which action a given identifier will trigger — selecting one
// from "Installed" swaps the Install button for a red Uninstall button (see
// syncActionButtons) rather than exposing separate pickers per action.
function renderInstallSelect(row, installable, installedPkgs, hostName) {
  const select = row.querySelector(".install-select");
  const blocked = !!(hostName && activeJobTargets.has(hostName));
  const hasAny = installable.length > 0 || installedPkgs.length > 0;
  select.replaceChildren(new Option(hasAny ? "— package —" : "— none ready —", ""));
  if (installable.length) {
    const group = document.createElement("optgroup");
    group.label = "Imported — ready to install";
    for (const id of installable) {
      const opt = new Option(id, id);
      opt.dataset.kind = "installable";
      group.appendChild(opt);
    }
    select.appendChild(group);
  }
  if (installedPkgs.length) {
    const group = document.createElement("optgroup");
    group.label = "Installed";
    for (const id of installedPkgs) {
      const opt = new Option(id, id);
      opt.dataset.kind = "installed";
      group.appendChild(opt);
    }
    select.appendChild(group);
  }
  select.disabled = !hasAny || blocked;
  // Reassigning .onchange (rather than addEventListener) is safe to call
  // repeatedly — renderInstallSelect re-runs on the same row element every
  // Refresh, and this avoids piling up duplicate listeners.
  select.onchange = () => syncActionButtons(row);
  syncActionButtons(row);
}

// Toggles which action button is visible/enabled for the row's currently
// selected package: Install (green) for an "installable" pick, Uninstall
// (red) for an "installed" one. "skip verify" only applies to installs.
function syncActionButtons(row) {
  const select = row.querySelector(".install-select");
  const installBtn = row.querySelector(".btn-install");
  const uninstallBtn = row.querySelector(".btn-uninstall");
  const skipVerifyLabel = row.querySelector(".skip-verify-label");
  const selected = select.selectedOptions[0];
  const isUninstall = !!(selected && selected.dataset.kind === "installed");
  installBtn.classList.toggle("hidden", isUninstall);
  uninstallBtn.classList.toggle("hidden", !isUninstall);
  if (skipVerifyLabel) skipVerifyLabel.classList.toggle("hidden", isUninstall);
  const hasSelection = !!select.value;
  installBtn.disabled = select.disabled || !hasSelection || isUninstall;
  uninstallBtn.disabled = select.disabled || !hasSelection || !isUninstall;
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
    renderInstallSelect(row, state.installable ?? [], state.installed ?? [], name);
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

/* ---------- 3a-uninstall. uninstall confirmation modal (servers + firewalls) --- */

// Uninstall is destructive (reverts the host to a prior version, may reboot
// it) so it gets its own modal requiring the operator to type the exact
// target host name, rather than installPackage's plain confirm() dialog.
// Shared by both the Management tab's server rows and the Firewalls panel —
// `kind` ("server" | "firewall") picks the API path.
let uninstallModalCtx = null;

function openUninstallModal(kind, name, row) {
  const select = row.querySelector(".install-select");
  const packageId = select.value;
  if (!packageId) { toast("Choose a package first."); return; }
  uninstallModalCtx = { kind, name, packageId };
  document.getElementById("uninstall-modal-package").textContent = packageId;
  document.getElementById("uninstall-modal-host").textContent = name;
  document.getElementById("uninstall-modal-host-echo").textContent = name;
  const input = document.getElementById("uninstall-modal-confirm-name");
  input.value = "";
  document.getElementById("uninstall-modal-submit").disabled = true;
  document.getElementById("uninstall-modal").classList.remove("hidden");
  input.focus();
}

function closeUninstallModal() {
  document.getElementById("uninstall-modal").classList.add("hidden");
  uninstallModalCtx = null;
}

document.getElementById("uninstall-modal-confirm-name").addEventListener("input", (ev) => {
  document.getElementById("uninstall-modal-submit").disabled =
    !(uninstallModalCtx && ev.target.value === uninstallModalCtx.name);
});

document.getElementById("uninstall-modal-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!uninstallModalCtx) return;
  const { kind, name, packageId } = uninstallModalCtx;
  const submit = document.getElementById("uninstall-modal-submit");
  submit.disabled = true;
  const base = kind === "firewall" ? "firewalls" : "servers";
  const extra = await operationCredentials(name, "uninstall a package");
  if (extra === null) { submit.disabled = false; return; } // credential prompt cancelled
  try {
    await api(envUrl(`/${base}/${encodeURIComponent(name)}/uninstall`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_id: packageId, confirmed: true, ...extra }),
    });
    await loadJobs();
    closeUninstallModal();
  } catch (e) {
    cacheEvictCreds(name);
    toast("Uninstall failed to start: " + e.message);
    submit.disabled = false;
  }
});

document.getElementById("uninstall-modal-close").addEventListener("click", closeUninstallModal);
document.getElementById("uninstall-modal-cancel").addEventListener("click", closeUninstallModal);
document.getElementById("uninstall-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "uninstall-modal") closeUninstallModal(); // backdrop click cancels
});

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

// Human-readable byte count, matching the backend's _fmt_bytes style — used
// in the disk-space precheck's confirm()/toast messages.
function fmtBytes(n) {
  let size = n;
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (size < 1024) return unit === "B" ? `${size.toFixed(0)} B` : `${size.toFixed(1)} ${unit}`;
    size /= 1024;
  }
  return `${size.toFixed(1)} TB`;
}

// Runs the server-side disk-space precheck (PatchingService.
// check_import_disk_space) before an import job is submitted, and — when
// the shortfall is eligible (still >=1.5x the package's own size) — offers
// the operator a confirm() to proceed anyway. Below that floor there is no
// override; the check_import_disk_space docstring in patching.py is the
// source of truth for why. Returns { proceed, force }: proceed=false means
// don't submit the import at all; force=true must be sent back as
// force_low_space so the job's own re-check lets it through.
async function checkDiskSpaceBeforeImport(kind, name, pkg, extra) {
  let checks;
  try {
    checks = await api(envUrl(`/${kind}/${encodeURIComponent(name)}/import/disk-space`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg, ...extra }),
    });
  } catch (e) {
    toast(`Disk space check for ${name} failed: ${e.message}`);
    return { proceed: false, force: false };
  }
  const short = checks.filter((c) => !c.ok);
  if (!short.length) return { proceed: true, force: false };
  const lines = short.map(
    (c) =>
      `${c.path}: ${fmtBytes(c.available)} available, ${fmtBytes(c.required)} required ` +
      `(${c.multiplier}x the package size)`
  );
  if (short.some((c) => !c.override_eligible)) {
    toast(
      `Not enough disk space on ${name} to import — below 1.5x the package size, cannot ` +
      `override:\n${lines.join("\n")}`
    );
    return { proceed: false, force: false };
  }
  const sure = confirm(
    `${name} is short on disk space for this import, but still has at least 1.5x the ` +
    `package size free:\n\n${lines.join("\n")}\n\nProceed with the import anyway?`
  );
  // A declined override must not fail silently — in a multi-select bulk import
  // this confirm() fires once per short-on-space host in turn, and a operator
  // clicking through a run of them can easily decline one without meaning to
  // skip it outright (operator-reported, 2026-07-25: a second selected server
  // appeared to get no job at all, with no indication why).
  if (!sure) toast(`Skipped ${name}: disk space override declined.`);
  return { proceed: sure, force: sure };
}

document.getElementById("bulk-import-btn").addEventListener("click", () => {
  const btn = document.getElementById("bulk-import-btn");
  const pkg = document.getElementById("bulk-import-package").value;
  if (!pkg) { toast("Choose a package first."); return; }
  bulkImport(btn, selectedServerNames, async (name) => {
    const extra = await operationCredentials(name, "import a package");
    if (extra === null) { toast(`Skipped ${name}: credentials not provided.`); return; }
    const { proceed, force } = await checkDiskSpaceBeforeImport("servers", name, pkg, extra);
    if (!proceed) return;
    const job = await api(envUrl(`/servers/${encodeURIComponent(name)}/import`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg, force_low_space: force, ...extra }),
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
    if (extra === null) { toast(`Skipped ${name}: credentials not provided.`); return; }
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

// Mirrors packages.py's package_kind() — same three-line extension check,
// kept in sync by hand (packages.py can't import this, and this can't
// import Python; see .claude/memory/spark-firmware-patching.md). Drives the
// Firewalls-panel package/firewall mutual filtering below — the Management
// Servers panel's equivalent selectors are untouched.
function packageKind(filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".img")) return "spark_image";
  if (lower.endsWith(".tar") || lower.endsWith(".tgz") || lower.endsWith(".tar.gz")) return "archive";
  return "unknown";
}

function firewallRowKind(role) {
  return role === "spark_firewall" ? "spark_image" : "archive";
}

// Disables (never removes) any firewall row whose kind doesn't match `kind`
// (null = no lock, nothing disabled by kind) and unchecks it if it was
// checked — a row already job-active (markRowIfJobActive hid its checkbox)
// is left alone, that disable reason is independent of this one. Shared by
// both filtering directions below so there's one source of truth for what
// "locked" means on a row.
function setFirewallRowLock(kind) {
  for (const cb of document.querySelectorAll("#firewalls-table .fw-select")) {
    if (cb.classList.contains("hidden")) continue; // job-active — not ours to touch
    const row = cb.closest("tr");
    const mismatched = kind !== null && firewallRowKind(row.dataset.role) !== kind;
    cb.disabled = mismatched;
    if (mismatched && cb.checked) cb.checked = false;
  }
  updateFirewallSelectAllState();
}

function checkedFirewallRowKind() {
  const cb = document.querySelector("#firewalls-table .fw-select:checked");
  return cb ? firewallRowKind(cb.closest("tr").dataset.role) : null;
}

// Row-driven direction: called on loadFirewalls() rebuild and on every row
// checkbox change. Derives the locked kind from whichever rows are already
// checked, then filters the bulk-import package <select> to match (clearing
// the current pick if it no longer qualifies) and locks the remaining rows.
function applyFirewallPackageFilter() {
  const kind = checkedFirewallRowKind();
  const select = document.getElementById("fw-bulk-import-package");
  let selectionStillMatches = !select.value;
  for (const opt of select.options) {
    if (!opt.value) continue; // the "— package —" placeholder
    const mismatched = kind !== null && packageKind(opt.value) !== kind;
    opt.disabled = mismatched;
    if (opt.value === select.value) selectionStillMatches = !mismatched;
  }
  if (!selectionStillMatches) {
    select.value = "";
    toast("Cleared the package selection — it no longer matches the firewalls you've selected.");
  }
  setFirewallRowLock(kind);
}

// Package-driven direction: called on #fw-bulk-import-package's own change.
function applyFirewallRowLockFromPackage() {
  const value = document.getElementById("fw-bulk-import-package").value;
  setFirewallRowLock(value ? packageKind(value) : null);
}

// Bumped on every call, checked after the awaits below — any two callers
// racing loadFirewalls() (e.g. the firewall-remove handler's own reload
// landing mid-flight with a pollJobs()-triggered loadServers()->loadFirewalls()
// tail call, or with each other) used to each clear the tbody and then each
// append their own full row set, doubling every row (operator-reported,
// 2026-07-23 and again 2026-08-18 — see loadServers()'s matching guard and
// pollJobs()'s reloadProv comment, which only fixed one specific instance of
// this). A stale call now bails out before touching the DOM instead.
let _firewallsLoadToken = 0;

async function loadFirewalls() {
  const token = ++_firewallsLoadToken;
  const tbody = document.querySelector("#firewalls-table tbody");

  if (!currentEnv) {
    tbody.replaceChildren();
    emptyRow(tbody, 6, "No environments. Use the Environment picker → New Environment…");
    return;
  }

  const [firewalls, editable, packages] = await Promise.all([
    api(envUrl("/firewalls")),
    api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`),
    api("/api/packages"),
  ]);
  await refreshActiveJobTargets();
  if (token !== _firewallsLoadToken) return; // a newer call started — let it render instead

  const savedSelections = captureRowSelections(tbody, ".fw-name-link");
  tbody.replaceChildren();
  const stateByName = new Map(firewalls.map((f) => [f.name, f]));

  const bulkPackageSelect = document.getElementById("fw-bulk-import-package");
  bulkPackageSelect.replaceChildren(new Option("— package —", ""));
  for (const pkg of packages) bulkPackageSelect.appendChild(new Option(pkg.filename, pkg.filename));

  for (const fw of sortByRole(editable)) {
    const state = stateByName.get(fw.name);
    const row = el("tpl-firewall-row");
    const selectCb = row.querySelector(".fw-select");
    selectCb.dataset.firewall = fw.name; // read by the bulk-import buttons
    selectCb.addEventListener("change", applyFirewallPackageFilter);
    markRowIfJobActive(selectCb, fw.name);
    row.querySelector(".fw-name-link").textContent = fw.name;
    row.querySelector(".fw-address").textContent = fw.address;
    row.querySelector(".fw-role").textContent = roleLabel(fw.role);
    row.querySelector(".fw-creds").textContent =
      (state && state.credential_set) || "none — not assigned";
    renderInstallSelect(row, state?.installable ?? [], state?.installed ?? [], fw.name);
    row.querySelector(".skip-verify").checked = !!envSkipVerifyDefault[currentEnv];
    restoreRowSelection(row, fw.name, savedSelections);

    const stateRow = el("tpl-firewall-state-row");
    stateRow.dataset.firewall = fw.name; // looked up by the "Refresh all" button
    const hasClusterLine = renderStateRow(stateRow, state && state.checked_at ? state : null);
    row.classList.toggle("fw-cluster-member", hasClusterLine);
    row.dataset.role = fw.role; // read by refreshFirewallState to pick the right bootstrap link
    stateRow
      .querySelector(".srv-refresh-link")
      .addEventListener("click", () => refreshFirewallState(fw.name, row, stateRow));
    stateRow
      .querySelector(".srv-bootstrap-creds-link")
      .addEventListener("click", () => openBootstrapCredsConfirm(fw.name, stateRow));
    stateRow
      .querySelector(".srv-spark-bootstrap-link")
      .addEventListener("click", () => openSparkBootstrapModal(fw.name));
    const sparkTestCredsLink = stateRow.querySelector(".srv-spark-test-creds-link");
    // Shown proactively for every Spark row (not just reactively after an
    // auth failure like the bootstrap link above) — it's useful any time.
    sparkTestCredsLink.classList.toggle("hidden", fw.role !== "spark_firewall");
    sparkTestCredsLink.addEventListener("click", () => testSparkCredentials(fw.name));
    row.querySelector(".btn-install").addEventListener("click", () => installFirewallPackage(fw.name, row));
    row.querySelector(".btn-uninstall").addEventListener("click", () => openUninstallModal("firewall", fw.name, row));
    // The name itself is the row's only Edit trigger now — Remove lives inside
    // the modal it opens, rather than its own row button.
    row.querySelector(".fw-name-link").addEventListener("click", () => {
      openEditFirewallModal(
        fw,
        state && state.credential_set,
        state && state.cluster_name,
        state && state.mds_domain,
      );
    });
    tbody.appendChild(row);
    tbody.appendChild(stateRow);
  }

  if (!editable.length) {
    emptyRow(tbody, 6, "No firewalls yet — add one manually or discover from a primary.");
  }
  // Rows were just rebuilt — reset select-all state and the package/row kind
  // lock together (restored selections may already imply a lock).
  applyFirewallPackageFilter();
}

async function refreshFirewallState(name, row, stateRow) {
  const link = stateRow.querySelector(".srv-refresh-link");
  const bootstrapLink = stateRow.querySelector(".srv-bootstrap-creds-link");
  const sparkBootstrapLink = stateRow.querySelector(".srv-spark-bootstrap-link");
  const isSpark = row.dataset.role === "spark_firewall";
  const summary = stateRow.querySelector(".srv-summary");
  const extra = await operationCredentials(name, "query live state");
  if (extra === null) return; // credential prompt cancelled
  link.disabled = true;
  bootstrapLink.classList.add("hidden"); // re-evaluated fresh on every attempt
  sparkBootstrapLink.classList.add("hidden");
  summary.textContent = "querying…";
  stateRow.querySelector(".srv-checked").textContent = "";
  try {
    const state = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/state`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    const hasClusterLine = renderStateRow(stateRow, state);
    row.classList.toggle("fw-cluster-member", hasClusterLine);
    renderInstallSelect(row, state.installable ?? [], state.installed ?? [], name);
  } catch (e) {
    cacheEvictCreds(name); // a cached wrong/stale password re-prompts next time
    summary.textContent = "detect failed: " + e.message;
    // Loose match (not a literal "Authentication Failed" string) — paramiko's
    // exact wording isn't a stable contract to pin an exact match to. Spark
    // gets the display-only "Show Bootstrap Commands" link instead of the
    // full-Gaia auto-push one — its clish speaks `add administrator`, not
    // `add user`/`set user password-hash`, and there's no automated push for
    // it (see services/gateway_bootstrap.py's module docstring).
    if (/auth/i.test(e.message)) {
      (isSpark ? sparkBootstrapLink : bootstrapLink).classList.remove("hidden");
    }
  } finally {
    link.disabled = false;
  }
}

// Spark rows' "Test Credentials" link — SSH login + expert-mode escalation,
// nothing more (see services/spark_patching.py). Submit-and-toast, like
// every other job-submitting action in this app; progress/result show up on
// the Jobs tab rather than an inline poll here.
async function testSparkCredentials(name) {
  const extra = await operationCredentials(name, "test SSH login and the expert-mode password");
  if (extra === null) return; // credential prompt cancelled
  try {
    const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/spark-test-credentials`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    lastJobStatus.set(job.id, job.status);
    toast(`Credential test started for ${name} — see the Jobs tab for the result.`);
  } catch (e) {
    toast("Could not start the credential test: " + e.message);
  }
}

let fwBootstrapCredsCtx = null;

async function openBootstrapCredsConfirm(name, stateRow) {
  try {
    const preview = await api(
      envUrl(`/firewalls/${encodeURIComponent(name)}/bootstrap-credentials/preview`),
    );
    fwBootstrapCredsCtx = { name, stateRow };
    document.getElementById("fw-bootstrap-creds-confirm-target").textContent = name;
    document.getElementById("fw-bootstrap-creds-confirm-output").textContent =
      preview.commands.join("\n");
    document.getElementById("fw-bootstrap-creds-confirm-modal").classList.remove("hidden");
  } catch (e) {
    toast("Could not render command preview: " + e.message);
  }
}

function closeBootstrapCredsConfirmModal() {
  document.getElementById("fw-bootstrap-creds-confirm-modal").classList.add("hidden");
  fwBootstrapCredsCtx = null;
}
document.getElementById("fw-bootstrap-creds-confirm-close").addEventListener(
  "click", closeBootstrapCredsConfirmModal,
);
document.getElementById("fw-bootstrap-creds-confirm-cancel").addEventListener(
  "click", closeBootstrapCredsConfirmModal,
);
document.getElementById("fw-bootstrap-creds-confirm-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "fw-bootstrap-creds-confirm-modal") closeBootstrapCredsConfirmModal();
});

document.getElementById("fw-bootstrap-creds-confirm-run").addEventListener("click", async () => {
  if (!fwBootstrapCredsCtx) return;
  const { name, stateRow } = fwBootstrapCredsCtx;
  closeBootstrapCredsConfirmModal();
  const summary = stateRow.querySelector(".srv-summary");
  summary.textContent = "bootstrapping credentials…";
  try {
    const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/bootstrap-credentials`), {
      method: "POST",
    });
    lastJobStatus.set(job.id, job.status);
    await loadJobs();
    const finished = await waitForJobDone(job.id, { timeoutMs: 30000 });
    if (!finished) {
      summary.textContent = "Still running — check the Jobs tab for progress.";
      return;
    }
    await loadJobs();
    if (finished.status !== "succeeded") {
      summary.textContent = `Bootstrap failed: ${finished.error || "see the Jobs tab for details"}`;
      return;
    }
    // Confirm the fix worked by re-running the same refresh that surfaced the failure.
    const row = stateRow.previousElementSibling;
    await refreshFirewallState(name, row, stateRow);
  } catch (e) {
    summary.textContent = "Bootstrap failed to start: " + e.message;
  }
});

// Spark (Gaia Embedded) equivalent of openBootstrapCredsConfirm above —
// display-only, no Run button: the operator pastes the command into the
// device's own clish shell themselves (services/gateway_bootstrap.py's
// preview_spark_admin_commands has no matching submit_*).
//
// Resolves once the operator closes the modal, so a caller stepping through
// several firewalls in sequence (the Discover Firewalls import loop) can
// `await` it and avoid clobbering one row's commands with the next before
// the operator has copied them; the single-shot caller below (Firewalls
// panel's own "Show Bootstrap Commands" link) just doesn't await it.
let _fwSparkBootstrapResolve = null;

async function openSparkBootstrapModal(name) {
  try {
    const preview = await api(
      envUrl(`/firewalls/${encodeURIComponent(name)}/spark-bootstrap-admin/preview`),
    );
    document.getElementById("fw-spark-bootstrap-target").textContent = name;
    document.getElementById("fw-spark-bootstrap-output").textContent = preview.commands.join("\n");
    document.getElementById("fw-spark-bootstrap-modal").classList.remove("hidden");
  } catch (e) {
    toast("Could not render command preview: " + e.message);
    return;
  }
  await new Promise((resolve) => { _fwSparkBootstrapResolve = resolve; });
}

function closeSparkBootstrapModal() {
  document.getElementById("fw-spark-bootstrap-modal").classList.add("hidden");
  const resolve = _fwSparkBootstrapResolve;
  _fwSparkBootstrapResolve = null;
  if (resolve) resolve();
}
document.getElementById("fw-spark-bootstrap-close").addEventListener("click", closeSparkBootstrapModal);
document.getElementById("fw-spark-bootstrap-ok").addEventListener("click", closeSparkBootstrapModal);
document.getElementById("fw-spark-bootstrap-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "fw-spark-bootstrap-modal") closeSparkBootstrapModal();
});

// ---- Spark firewall credential scenario modal ------------------------------
// Shared by the Add Firewall modal (role changed to Spark Firewall) and the
// Discover Firewalls import loop — both need the same "which scenario, which
// credential set" prompt (#fw-spark-cred-modal in index.html). Resolves to
// {credentialSetName, scenario} ("direct" | "bootstrap"), or null on
// Cancel/backdrop click.
let _fwSparkCredResolve = null;

function toggleSparkCredNewFields() {
  const isNew = document.getElementById("fw-spark-cred-select").value === "";
  document.getElementById("fw-spark-cred-new-fields").classList.toggle("hidden", !isNew);
}
document.getElementById("fw-spark-cred-select").addEventListener("change", toggleSparkCredNewFields);

async function resolveSparkFirewallCredentials(targetLabel) {
  document.getElementById("fw-spark-cred-target").textContent = targetLabel;
  document.getElementById("fw-spark-cred-form").reset();
  const select = document.getElementById("fw-spark-cred-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  for (const set of await fetchCredentialSets()) select.appendChild(new Option(set.name, set.name));
  select.value = "";
  toggleSparkCredNewFields();
  document.getElementById("fw-spark-cred-modal").classList.remove("hidden");
  return new Promise((resolve) => { _fwSparkCredResolve = resolve; });
}

function closeSparkCredModal(result) {
  document.getElementById("fw-spark-cred-modal").classList.add("hidden");
  const resolve = _fwSparkCredResolve;
  _fwSparkCredResolve = null;
  if (resolve) resolve(result);
}

// Save a new credential set from the Spark scenario modal — same name-collision
// handling as saveBootstrapCredential (prompt overwrite/new/skip), but expert
// password is required (require_expert: true) and the set never becomes the
// environment default (that's reserved for management-server bootstrap creds,
// see saveBootstrapCredential). Unlike saveBootstrapCredential, this checks the
// returned job actually succeeded before reporting success.
async function saveSparkCredential({ name, ssh_username, ssh_password, expert_password, api_key }) {
  await loadCredentialSets(); // refresh before checking for a username collision
  const existing = credentialSets.find((s) => s.ssh_username === ssh_username);
  let setName = name;
  if (existing) {
    const choice = await promptOverwriteChoice(ssh_username, existing.name);
    if (choice === "skip") return { ok: false, reason: "you chose not to save them" };
    setName = choice === "overwrite" ? existing.name : uniqueCredentialName(name);
  }
  try {
    const job = await api(envUrl("/credentials"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: setName,
        ssh_username,
        ssh_password,
        expert_password,
        api_key: api_key || null,
        require_expert: true,
      }),
    });
    lastJobStatus.set(job.id, job.status);
    await Promise.all([loadJobs(), loadCredentialSets()]);
    if (job.status !== "succeeded") return { ok: false, reason: job.error || "unknown error" };
    return { ok: true, name: setName };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

document.getElementById("fw-spark-cred-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const scenario = document.querySelector('input[name="fw-spark-cred-scenario"]:checked').value;
  const select = document.getElementById("fw-spark-cred-select");
  if (select.value) {
    closeSparkCredModal({ credentialSetName: select.value, scenario });
    return;
  }
  const name = document.getElementById("fw-spark-cred-name").value.trim();
  const ssh_username = document.getElementById("fw-spark-cred-user").value.trim();
  const ssh_password = document.getElementById("fw-spark-cred-password").value;
  const expert_password = document.getElementById("fw-spark-cred-expert").value;
  const api_key = document.getElementById("fw-spark-cred-api").value;
  if (!name || !ssh_username || !ssh_password) {
    toast("Enter a name, SSH username, and SSH password — or pick an existing credential set.");
    return;
  }
  if (!expert_password) {
    toast("An expert password is required for a Spark firewall credential set.");
    return;
  }
  const result = await saveSparkCredential({ name, ssh_username, ssh_password, expert_password, api_key });
  if (!result.ok) { toast("Save failed: " + result.reason); return; }
  closeSparkCredModal({ credentialSetName: result.name, scenario });
});
document.getElementById("fw-spark-cred-cancel").addEventListener("click", () => closeSparkCredModal(null));
document.getElementById("fw-spark-cred-close").addEventListener("click", () => closeSparkCredModal(null));
document.getElementById("fw-spark-cred-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "fw-spark-cred-modal") closeSparkCredModal(null); // backdrop click cancels
});

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
  // Rows of only one kind were enabled to begin with (see setFirewallRowLock)
  // unless nothing was locked yet, in which case this re-derives a lock from
  // whichever kind ends up first and corrects the rest.
  applyFirewallPackageFilter();
});

document.getElementById("fw-bulk-import-package").addEventListener("change", applyFirewallRowLockFromPackage);

document.getElementById("fw-bulk-import-btn").addEventListener("click", () => {
  const btn = document.getElementById("fw-bulk-import-btn");
  const pkg = document.getElementById("fw-bulk-import-package").value;
  if (!pkg) { toast("Choose a package first."); return; }
  if (packageKind(pkg) === "spark_image") {
    bulkImport(btn, selectedFirewallNames, async (name) => {
      const extra = await operationCredentials(name, "transfer and upgrade a Spark firmware image");
      if (extra === null) { toast(`Skipped ${name}: credentials not provided.`); return; }
      if (!confirm(
        `Upgrade ${name} to ${pkg}?\n\nThe firewall reboots on its own once the transfer ` +
        "completes — this cannot be undone or cancelled after the upgrade command is issued."
      )) return;
      const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/spark-transfer-upgrade`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: pkg, confirmed: true, ...extra }),
      });
      lastJobStatus.set(job.id, job.status);
    });
    return;
  }
  bulkImport(btn, selectedFirewallNames, async (name) => {
    const extra = await operationCredentials(name, "import a package");
    if (extra === null) { toast(`Skipped ${name}: credentials not provided.`); return; }
    const { proceed, force } = await checkDiskSpaceBeforeImport("firewalls", name, pkg, extra);
    if (!proceed) return;
    const job = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/import`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg, force_low_space: force, ...extra }),
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
    if (extra === null) { toast(`Skipped ${name}: credentials not provided.`); return; }
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

// `credential_set` (string, null, or omitted/undefined) rides in the same
// prov.add/prov.edit job — see addServer above. Returns the JobRecord too.
async function addFirewall({ name, address, role, ssh_user, ssh_port, credential_set }) {
  return await api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, address, role, ssh_user, ssh_port, credential_set }),
  });
}

// Set while the modal is in edit mode — read by the modal's own Remove button,
// which replaces the row-level Remove button (the row's only action now is
// the name link, which opens straight into this modal).
let editingFirewallName = null;

// Set when the operator picks "bootstrap a dedicated account" in the Spark
// credential-scenario modal (see fm-role change listener below) — the
// firewall submit handler opens the Spark bootstrap-commands modal right
// after a successful add. Reset on any role change away from Spark, and
// consumed (reset) once acted on.
let pendingSparkBootstrap = false;

// Only the add flow prompts automatically when Spark is picked — editing an
// existing firewall's role to Spark doesn't interrupt with this scenario
// modal; the operator can still assign/replace credentials via the normal
// #fm-cred-select dropdown in that case.
document.getElementById("fm-role").addEventListener("change", async (ev) => {
  if (ev.target.value !== "spark_firewall") { pendingSparkBootstrap = false; return; }
  if (editingFirewallName !== null || !storageEnabled()) return;
  const label = document.getElementById("fm-name").value.trim() || "this firewall";
  const result = await resolveSparkFirewallCredentials(label);
  if (result) {
    await populateFirewallCredSelect(result.credentialSetName);
    pendingSparkBootstrap = result.scenario === "bootstrap";
  } else {
    pendingSparkBootstrap = false; // cancelled — role stays Spark, credential unresolved ("assign later")
  }
});

async function openAddFirewallModal() {
  if (!currentEnv) { toast("Create an environment first (picker → New Environment…)."); return; }
  editingFirewallName = null;
  pendingSparkBootstrap = false;
  document.getElementById("firewall-form").reset();
  document.getElementById("fm-name").disabled = false;
  document.getElementById("firewall-modal-title").textContent = "Add firewall";
  document.getElementById("firewall-modal-submit").textContent = "Add firewall";
  document.getElementById("firewall-modal-remove").classList.add("hidden");
  // Nothing to check yet — the host doesn't exist in the store until this
  // form is submitted, and cluster-recheck/domain need an existing firewall.
  document.getElementById("fm-cluster-info").classList.add("hidden");
  document.getElementById("fm-domain-info").classList.add("hidden");
  await populateFirewallCredSelect();
  document.getElementById("firewall-modal").classList.remove("hidden");
  document.getElementById("fm-name").focus();
}
async function openEditFirewallModal(fw, assignedSetName, clusterName, mdsDomain) {
  editingFirewallName = fw.name;
  pendingSparkBootstrap = false;
  document.getElementById("fm-name").value = fw.name;
  document.getElementById("fm-name").disabled = true;
  document.getElementById("fm-address").value = fw.address;
  document.getElementById("fm-role").value = fw.role;
  document.getElementById("fm-user").value = fw.ssh_user;
  document.getElementById("fm-port").value = fw.ssh_port;
  document.getElementById("firewall-modal-title").textContent = `Edit ${fw.name}`;
  document.getElementById("firewall-modal-submit").textContent = "Save changes";
  document.getElementById("firewall-modal-remove").classList.remove("hidden");
  document.getElementById("fm-cluster-info").classList.remove("hidden");
  renderFirewallClusterInfo(clusterName);
  await populateFirewallCredSelect(assignedSetName);
  if (envIsMds[currentEnv]) {
    document.getElementById("fm-domain-info").classList.remove("hidden");
    await populateFirewallDomainSelect(mdsDomain);
  } else {
    document.getElementById("fm-domain-info").classList.add("hidden");
  }
  document.getElementById("firewall-modal").classList.remove("hidden");
  document.getElementById("fm-address").focus();
}

function renderFirewallClusterInfo(clusterName) {
  document.getElementById("fm-cluster-name").value = clusterName || "";
  document.getElementById("fm-cluster-status").textContent = "";
}

// MDS-only. Populates the Domain dropdown from the same /domains endpoint the
// discover-firewalls modal uses, so the operator picks from real Domain names
// rather than typing one by hand.
async function populateFirewallDomainSelect(currentDomain) {
  const select = document.getElementById("fm-domain-select");
  select.querySelectorAll("option:not(:first-child)").forEach((o) => o.remove());
  document.getElementById("fm-domain-status").textContent = "";
  try {
    const { domains, warnings } = await api(
      `/api/environments/${encodeURIComponent(currentEnv)}/domains`,
    );
    for (const d of domains) select.appendChild(new Option(d, d));
    for (const w of warnings || []) toast(w);
  } catch (e) {
    document.getElementById("fm-domain-status").textContent = "Could not load domains: " + e.message;
  }
  // The stored domain may not be in the current domains list (renamed/removed
  // on the MDS since it was set) — add it anyway so Save doesn't silently
  // change it just by opening the modal.
  if (currentDomain && !select.querySelector(`option[value="${CSS.escape(currentDomain)}"]`)) {
    select.appendChild(new Option(currentDomain, currentDomain));
  }
  select.value = currentDomain || "";
}

// Management API only, no SSH — Check Point doesn't expose the SmartConsole
// cluster object's own name over the CLI on the member itself, so no live
// command could ever answer this (see clusterxl.py). No credentials needed.
document.getElementById("fm-cluster-recheck").addEventListener("click", async () => {
  const name = editingFirewallName;
  if (!name) return;
  const btn = document.getElementById("fm-cluster-recheck");
  btn.disabled = true;
  document.getElementById("fm-cluster-status").textContent = "checking…";
  try {
    const result = await api(envUrl(`/firewalls/${encodeURIComponent(name)}/cluster-recheck`), {
      method: "POST",
    });
    document.getElementById("fm-cluster-name").value = result.cluster_name || "";
    document.getElementById("fm-cluster-status").textContent = result.resolved
      ? "resolved via Management API"
      : "Management API couldn't resolve this — enter it manually and click Save";
    await loadFirewalls(); // table's status line reflects the new name too
  } catch (e) {
    document.getElementById("fm-cluster-status").textContent = "check failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});

// Manual fallback for when the Management API can't resolve a name (no
// primary configured, older management version, or no Domain set on this
// firewall on an MDS) — operator types the real cluster object name in by hand.
document.getElementById("fm-cluster-save").addEventListener("click", async () => {
  const name = editingFirewallName;
  if (!name) return;
  const btn = document.getElementById("fm-cluster-save");
  const value = document.getElementById("fm-cluster-name").value.trim();
  btn.disabled = true;
  try {
    await api(envUrl(`/firewalls/${encodeURIComponent(name)}/cluster-name`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cluster_name: value || null }),
    });
    document.getElementById("fm-cluster-status").textContent = "saved";
    await loadFirewalls();
  } catch (e) {
    document.getElementById("fm-cluster-status").textContent = "save failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});

// MDS Domain/CMA membership — set automatically at discovery-import time, or
// adjustable here for manually-added firewalls or if it was ever guessed wrong.
document.getElementById("fm-domain-save").addEventListener("click", async () => {
  const name = editingFirewallName;
  if (!name) return;
  const btn = document.getElementById("fm-domain-save");
  const value = document.getElementById("fm-domain-select").value;
  btn.disabled = true;
  try {
    await api(envUrl(`/firewalls/${encodeURIComponent(name)}/mds-domain`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mds_domain: value || null }),
    });
    document.getElementById("fm-domain-status").textContent = "saved";
    await loadFirewalls();
  } catch (e) {
    document.getElementById("fm-domain-status").textContent = "save failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});
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
    // Executes immediately as a tracked prov.add/prov.edit job
    // (services/prov_ops.py) — the response is already the finished job, so
    // a validation failure (e.g. bad role, name collision) is known right
    // here, not just on a later Jobs-tab poll.
    const job = await addFirewall({
      name,
      address: document.getElementById("fm-address").value.trim(),
      role: document.getElementById("fm-role").value,
      ssh_user: sshUser,
      ssh_port: Number(document.getElementById("fm-port").value) || 22,
      // Storage-enabled: always explicit (clears to null if left at "none"),
      // matching this modal's previous always-fires-the-assignment behavior.
      credential_set: storageEnabled() ? (credSet || null) : undefined,
    });
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
    if (job.status !== "succeeded") {
      toast("Save failed: " + (job.error || "unknown error"));
      await loadJobs();
      return;
    }
    closeFirewallModal();
    await Promise.all([loadJobs(), loadFirewalls()]);
    if (pendingSparkBootstrap) {
      pendingSparkBootstrap = false;
      await openSparkBootstrapModal(name);
    }
  } catch (e) { toast("Save failed: " + e.message); }
});
document.getElementById("firewall-modal-remove").addEventListener("click", async () => {
  const name = editingFirewallName;
  if (!name || !currentEnv) return;
  if (!confirm(`Remove firewall ${name} from ${currentEnv}?`)) return;
  try {
    // Executes immediately as a tracked prov.delete job — see the firewall
    // form submit handler above.
    const job = await api(
      `/api/environments/${encodeURIComponent(currentEnv)}/firewalls/${encodeURIComponent(name)}`,
      { method: "DELETE" },
    );
    lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
    if (job.status !== "succeeded") toast("Remove failed: " + (job.error || "unknown error"));
    closeFirewallModal();
    await Promise.all([loadJobs(), loadFirewalls()]);
  } catch (e) { toast("Remove failed: " + e.message); }
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
    // Stashed for the Import-selected handler below — Management API-
    // resolved at scan time (see DiscoveryService.find_cluster_for_gateway),
    // so it rides straight into the add-firewall payload without a second
    // round trip.
    row.dataset.clusterName = s.cluster_name || "";
    // Same idea as clusterName above — the Domain/CMA this whole scan ran
    // against (None on SMS), so it rides straight into the import payload.
    row.dataset.mdsDomain = s.mds_domain || "";
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
    // Every other imported firewall silently inherits the primary's credential
    // set; Spark firewalls get their own scenario+credential prompt instead
    // (see #fw-spark-cred-modal) since Spark needs an expert password the
    // primary's set likely doesn't carry, and often ships with a distinct
    // per-device admin password anyway. Cancelling leaves the row unassigned
    // ("assign later") rather than blocking the rest of the batch.
    let credentialSet = (storageEnabled() && discoverFwPrimaryCredSet) || undefined;
    let bootstrapAfter = false;
    if (role === "spark_firewall" && storageEnabled()) {
      const result = await resolveSparkFirewallCredentials(name);
      credentialSet = result ? result.credentialSetName : undefined;
      bootstrapAfter = result ? result.scenario === "bootstrap" : false;
    }
    try {
      // Add executes immediately as a prov.add job (services/prov_ops.py), so
      // the response already carries the real outcome (e.g. a name collision
      // fails the job right here, not just on a later Jobs-tab poll).
      const job = await api(`/api/environments/${encodeURIComponent(currentEnv)}/firewalls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name, address, role, ssh_user: discoverFwPrimarySshUser,
          credential_set: credentialSet,
          cluster_name: r.dataset.clusterName || undefined,
          mds_domain: r.dataset.mdsDomain || undefined,
        }),
      });
      lastJobStatus.set(job.id, job.status); // so pollJobs() catches it even if another tab is watching
      if (job.status === "succeeded") {
        ok++;
        // Awaited so the operator can copy this row's commands before the
        // next Spark row's prompt/preview overwrites the same modal.
        if (bootstrapAfter) await openSparkBootstrapModal(name);
      } else {
        failed.push(`${name}: ${job.error || "unknown error"}`);
      }
    } catch (e) { failed.push(`${name}: ${e.message}`); }
  }
  await Promise.all([loadJobs(), loadFirewalls()]);
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

// filename -> display text ("queued" / "NN%") for an in-flight pkgs.push_to_repo
// job, kept live by refreshPushProgress() (called from pollJobs()) by reading
// the job's own log lines — see ProgressReporter in services/patching.py,
// which logs "upload progress: NN%" at ~10% steps during the SFTP transfer.
const pkgPushProgress = new Map();

// Reflects pkgPushProgress for one already-rendered row — called both right
// after a row is built (loadPackages()) and on every poll tick while a push
// is in flight (refreshPushProgress()), so it must be cheap and idempotent.
function applyPushProgress(row, filename) {
  const span = row.querySelector(".pkg-push-progress");
  const btn = row.querySelector(".btn-push-repo");
  const text = pkgPushProgress.get(filename);
  if (text) {
    span.textContent = text === "queued" ? "queued…" : `uploading… ${text}`;
    span.classList.remove("hidden");
    btn.disabled = true;
  } else {
    span.textContent = "";
    span.classList.add("hidden");
  }
}

// Polls the log of every currently-running pkgs.push_to_repo job for its
// latest "upload progress: NN%" line (see ProgressReporter, ~10% steps) and
// reflects it on the matching package row. Called from pollJobs() so it rides
// the same 2.5s cadence as everything else there — no separate timer.
async function refreshPushProgress(activeJobs) {
  const seen = new Set();
  for (const job of activeJobs) {
    const filename = job.params && job.params.package;
    if (!filename) continue; // shouldn't happen — submit_push_to_repo always sets it
    seen.add(filename);
    if (job.status !== "running") continue; // "pending" keeps its "queued" placeholder
    try {
      const events = await api(`/api/jobs/${job.id}/events`);
      let pct = null;
      for (let i = events.length - 1; i >= 0; i--) {
        const m = /upload progress: (\d+)%/.exec(events[i].message);
        if (m) { pct = m[1]; break; }
      }
      if (pct != null) pkgPushProgress.set(filename, `${pct}%`);
    } catch { /* transient — next tick retries */ }
  }
  for (const filename of pkgPushProgress.keys()) if (!seen.has(filename)) pkgPushProgress.delete(filename);
  for (const row of document.querySelectorAll("#packages-table tr.pkg-row")) {
    applyPushProgress(row, row.dataset.pkgFilename);
  }
}

async function loadPackages() {
  const tbody = document.querySelector("#packages-table tbody");
  const packages = await api("/api/packages");
  tbody.replaceChildren();
  for (const pkg of packages) {
    const row = el("tpl-package-row");
    row.dataset.pkgFilename = pkg.filename;
    row.querySelector(".pkg-filename").textContent = pkg.filename;
    row.querySelector(".pkg-size").textContent = fmtBytes(pkg.size);
    // Compatible major version / Take / category, extracted from the
    // package file itself at upload time (hfconfig.extract_package_metadata,
    // packages.py) — "—" for anything uploaded before this shipped, or
    // that wasn't a readable CPUSE archive (e.g. a non-CPUSE file).
    row.querySelector(".pkg-compat").textContent =
      [pkg.direct_base_version, pkg.take_number ? `Take ${pkg.take_number}` : null, pkg.category]
        .filter(Boolean)
        .join(" · ") || "—";

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
    // Retention executes immediately (services/pkgs_ops.py) — the response is
    // already the finished pkgs.keep/pkgs.notkeep job, tracked on the Jobs
    // tab for audit history only. Revert the optimistic toggle if the write
    // itself failed, not just on a request-level (network/HTTP) failure.
    pin.addEventListener("change", async () => {
      pin.disabled = true;
      try {
        const job = await api(`/api/packages/${encodeURIComponent(pkg.filename)}/retention`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pinned: pin.checked }),
        });
        lastJobStatus.set(job.id, job.status);
        if (job.status !== "succeeded") {
          pin.checked = !pin.checked; // revert — the write itself failed
          toast("Retention update failed: " + (job.error || "unknown error"));
        }
        await Promise.all([loadJobs(), loadPackages()]);
      } catch (e) {
        pin.checked = !pin.checked; // revert the optimistic toggle — the request itself failed
        toast("Could not update retention: " + e.message);
      } finally {
        pin.disabled = false;
      }
    });

    // Delete likewise executes immediately — see the comment above.
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete package ${pkg.filename}?`)) return;
      try {
        const job = await api(`/api/packages/${encodeURIComponent(pkg.filename)}`, { method: "DELETE" });
        lastJobStatus.set(job.id, job.status);
        await Promise.all([loadJobs(), loadPackages()]);
      } catch (e) { toast("Delete failed to start: " + e.message); }
    });

    // Unlike the rest of this table, this is genuinely slow (SFTP to the
    // primary + a server-side import — see services/pkg_repo_ops.py) so it
    // stays a real background job: submit and let the Jobs tab / the
    // PKGS_JOB_KINDS entry in pollJobs() reflect progress and completion,
    // rather than waiting here. Uses the environment name (not a host name —
    // the primary is resolved server-side, and the Packages tab has no
    // per-row host to key on) as the credential-prompt/cache key.
    row.querySelector(".btn-push-repo").addEventListener("click", async () => {
      if (!currentEnv) { toast("Pick an environment first."); return; }
      const btn = row.querySelector(".btn-push-repo");
      const extra = await operationCredentials(currentEnv, "upload to the repository");
      if (extra === null) return; // credential prompt cancelled
      btn.disabled = true;
      try {
        const job = await api(
          `/api/env/${encodeURIComponent(currentEnv)}/packages/${encodeURIComponent(pkg.filename)}/push-to-repo`,
          { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(extra) },
        );
        lastJobStatus.set(job.id, job.status);
        toast("Upload to repository started.");
        // Shown live on this row (not just the Jobs tab) — pollJobs() picks up
        // the running job and fills in a real percentage; "queued" is just the
        // placeholder for the gap until the first poll tick.
        pkgPushProgress.set(pkg.filename, "queued");
        applyPushProgress(row, pkg.filename);
        await loadJobs();
      } catch (e) {
        toast("Could not start upload: " + e.message);
      } finally {
        // Leave it disabled if the job is now tracked as in-flight — only the
        // failure path (job never got created) should re-enable immediately.
        if (!pkgPushProgress.has(pkg.filename)) btn.disabled = false;
      }
    });
    applyPushProgress(row, pkg.filename); // in case a push-to-repo job is already in flight
    tbody.appendChild(row);
    tbody.appendChild(sha1Row);
    const noteRow = buildPackageNoteRow(pkg);
    if (noteRow) tbody.appendChild(noteRow);
  }
  await populateCdtSelectors(); // keep the CDT dropdowns in sync with packages/servers
}

// Collapsed detail row for the package's compatibility/prerequisite note
// (hfconfig.extract_package_metadata's conditions_set.json read) — same
// presence-gated pattern as syncInstallLogRow on the Jobs tab, simplified
// since loadPackages() rebuilds the whole table every call (no existing row
// to find/update): just skip the row entirely when there's no note.
function buildPackageNoteRow(pkg) {
  if (!pkg.compatibility_note) return null;
  const row = el("tpl-package-note-row");
  row.querySelector(".pkg-note").textContent = pkg.compatibility_note;
  return row;
}

// Shared upload path for the form and drag & drop. The multipart body itself
// is still sent synchronously (inherent to HTTP — the browser is actively
// streaming it during this request); the server then stages it and does the
// rest (hash, dedupe, store) immediately too — see services/pkgs_ops.py — so
// the response here is already the finished pkgs.upload job, not a "queued"
// placeholder.
const UPLOAD_FIELD_HINT = "Click to choose a file, or drag and drop to begin upload";

async function uploadPackageFile(file) {
  const field = document.getElementById("upload-field");
  const text = document.getElementById("upload-field-text");
  const input = document.getElementById("upload-file");
  const form = new FormData();
  form.append("file", file);
  field.classList.add("uploading"); // blocks re-trigger — see the .uploading rule in app.css
  input.disabled = true;
  text.textContent = `uploading ${file.name}… (large packages take a while)`;
  try {
    const job = await api("/api/packages", { method: "POST", body: form });
    lastJobStatus.set(job.id, job.status);
    if (job.status === "succeeded") {
      text.textContent = `${file.name}: stored`;
      await Promise.all([loadJobs(), loadPackages()]);
    } else {
      text.textContent = UPLOAD_FIELD_HINT;
      toast(`Upload of ${file.name} failed: ` + (job.error || "unknown error"));
      await loadJobs();
    }
  } catch (e) {
    text.textContent = UPLOAD_FIELD_HINT;
    toast(`Upload of ${file.name} failed to start: ` + e.message);
  } finally {
    field.classList.remove("uploading");
    input.disabled = false;
  }
}

// The <label for="upload-file"> wrapping the (visually hidden but focusable)
// input already opens the native file dialog on click or keyboard activation —
// no click handler needed for that part. Selecting a file begins the upload
// immediately (no separate submit step), matching the field's own hint text
// and the drag & drop behavior below.
document.getElementById("upload-file").addEventListener("change", async (ev) => {
  const input = ev.target;
  if (!input.files.length) return;
  const file = input.files[0];
  input.value = ""; // reset so choosing the same file again still fires "change"
  await uploadPackageFile(file);
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
  if (!currentEnv || !enabled) {
    credentialSets = [];
    populateConnectPrimaryCredSelect();
    return;
  }
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
    // Executes immediately as a tracked cred.delete job (services/cred_ops.py).
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete credential set "${set.name}"? Servers using it lose access.`)) return;
      try {
        const job = await api(envUrl(`/credentials/${encodeURIComponent(set.name)}`), { method: "DELETE" });
        lastJobStatus.set(job.id, job.status);
        await Promise.all([loadJobs(), loadCredentialSets(), loadServers()]);
      } catch (e) { toast("Delete failed to start: " + e.message); }
    });
    tbody.appendChild(row);
  }
  populateConnectPrimaryCredSelect();
}

// Sets the Bootstrap/Connect-to-Primary panels' default open/closed state for
// the current environment: collapsed once hasProvisionedPrimary is true (see
// loadServers/updateServersInfoControls), left open otherwise since
// bootstrapping is likely still needed. Called once per environment load/
// switch — never on every credential-set refresh — so it doesn't yank the
// panels shut/open out from under an operator who's actively working in
// them; the explicit collapse right after a successful Connect to Primary
// run (see the confirm modal's Run handler) covers that moment instead.
function updateProvisionCollapse() {
  document.getElementById("provision-details").open = !hasProvisionedPrimary;
  document.getElementById("connect-primary-details").open = !hasProvisionedPrimary;
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
    // Executes immediately (services/cred_ops.py) — the response is already
    // the finished cred.add/cred.edit job, tracked on the Jobs tab for audit
    // history only (unlike packages, this never queues).
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
    lastJobStatus.set(job.id, job.status);
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
// pkgs.* (services/pkgs_ops.py) executes immediately, so its own call sites
// already reload the Packages table directly — this only exists as a
// fallback for another tab/session polling in the narrow window between a
// job's insert and its (near-instant) finish.
const PKGS_JOB_KINDS = [
  "pkgs.upload", "pkgs.keep", "pkgs.notkeep", "pkgs.delete", "pkgs.push_to_repo",
];
// cred.* (services/cred_ops.py) executes immediately, so its own call sites
// already reload the Credentials table directly — this only exists as a
// fallback for another tab/session polling in the narrow window between a
// job's insert and its (near-instant) finish.
const CRED_JOB_KINDS = ["cred.add", "cred.edit", "cred.delete"];
// Management-server AND firewall add/edit/delete (services/prov_ops.py) share
// one set of kinds — no server/firewall split in the Kind column (operator-
// directed, 2026-07-23) — so a finished prov.* job just reloads both tables;
// it's cheap and simpler than tracking which entity type each job touched.
const PROV_JOB_KINDS = ["prov.add", "prov.edit", "prov.delete"];
// Connect to Primary (services/connect_primary.py) touches both the servers
// table (adds/updates the primary) and a credential set (the captured API
// key) — its own call site (the confirm modal's Run handler) already reloads
// both directly; this is the same "other tab/session" fallback as
// CRED_JOB_KINDS above.
const CONNECT_PRIMARY_JOB_KIND = "prov.connect_primary";
const lastJobStatus = new Map();
const TERMINAL_JOB_STATUSES = ["succeeded", "failed", "cancelled", "interrupted", "timed_out"];

// Polls a single job until it's terminal (or timeoutMs elapses). Used only
// where the caller has a real, immediate correctness dependency on the job
// having actually landed — e.g. discovery reads the servers list straight
// from the DB right after adding the environment's first primary, and would
// wrongly report "no primary" if it ran before that add job finished. NOT
// used for the general add/edit/delete UI flow, which — like credentials/
// packages — reloads optimistically and lets pollJobs() (PROV_JOB_KINDS)
// catch the real outcome instead.
async function waitForJobDone(jobId, { timeoutMs = 5000, intervalMs = 150 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (TERMINAL_JOB_STATUSES.includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return null; // gave up — caller proceeds anyway rather than hanging forever
}

// Live count of not-yet-finished jobs, shown as a pill on the Jobs tab button.
function updateJobsBadge(jobs) {
  const pill = document.getElementById("jobs-badge");
  const n = jobs.filter((j) => j.status === "running" || j.status === "pending").length;
  pill.textContent = n;
  pill.title = `${n} job${n === 1 ? "" : "s"} running or queued`;
  pill.classList.toggle("hidden", n === 0);
}

function jobStatusClass(status) {
  if (status === "succeeded") return "ok";
  // "warn", not "err" — running/pending are still in progress, and a timed-out
  // import isn't a verdict (CPUSE may still be working); it may yet resolve to
  // succeeded via the Jobs tab's "Check status" recheck.
  return status === "running" || status === "pending" || status === "timed_out" ? "warn" : "err";
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
  // pkgs.push_to_repo is the one pkgs.* kind that IS scoped to a real host —
  // submit_push_to_repo() targets the environment's primary management
  // server (services/pkg_repo_ops.py), unlike upload/keep/notkeep/delete
  // whose target is a filename. Show that host rather than blanking it.
  const isPkgsWithHostTarget = job.kind === "pkgs.push_to_repo";
  // Every other kind — including cred.* and prov.* — DOES act on a real
  // environment (a credential set or server/firewall belonging to it), so
  // the Env column always shows the actual environment name for them
  // (previously cred.* showed a synthetic "Credentials" label here instead;
  // operator-directed, 2026-07-23 — the real environment is more useful).
  row.querySelector(".job-target").textContent =
    isPkgs && !isPkgsWithHostTarget ? "" : (job.target ?? "");
  row.querySelector(".job-env").textContent = isPkgs ? "Packages" : (job.environment ?? "");
  row.querySelector(".job-user").textContent = job.username ?? "";
  const badge = row.querySelector(".job-status .badge");
  badge.textContent = job.status;
  badge.className = "badge " + jobStatusClass(job.status); // reset, not add — status can change
  row.querySelector(".job-started").textContent = fmtTime(job.started_at ?? job.created_at);
  const errorCell = row.querySelector(".job-error");
  const errorText = errorCell.querySelector(".job-error-text");
  errorText.textContent =
    job.status === "succeeded" ? `Succeeded ${fmtTime(job.finished_at)}` : (job.error ?? "");
  errorCell.title = job.status === "succeeded" ? "" : (job.error ?? ""); // full text on hover even while truncated/collapsed
  row.querySelector(".btn-cancel").classList.toggle(
    "hidden", !(job.status === "pending" || job.status === "running"),
  );
  // Only a TIMED_OUT import job (see PatchingService.recheck_import) gets a
  // manual recheck link — every other kind/status has nothing to recheck.
  row.querySelector(".btn-recheck-import").classList.toggle(
    "hidden", !(job.status === "timed_out" && job.kind === "cpuse.import"),
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
  row.querySelector(".btn-recheck-import").addEventListener("click", async (ev) => {
    ev.stopPropagation(); // don't also toggle the log row
    const btn = ev.currentTarget;
    // Read straight from the row's own rendered cells rather than threading
    // the job object through — they're already the host/environment this
    // job ran against (renderJobRow fills them from the same job record).
    const host = row.querySelector(".job-target").textContent;
    const env = row.querySelector(".job-env").textContent;
    const extra = await operationCredentials(host, "check import status", env);
    if (extra === null) return; // credential prompt cancelled
    btn.disabled = true;
    try {
      const updated = await api(`/api/jobs/${jobId}/recheck-import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(extra),
      });
      renderJobRow(row, updated);
      toast(
        updated.status === "succeeded"
          ? "Confirmed — package is imported."
          : "Still not listed as imported yet."
      );
    } catch (e) {
      toast("Check status failed: " + e.message);
    } finally {
      btn.disabled = false;
    }
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
    let reloadProv = false;
    for (const job of jobs) {
      const prev = lastJobStatus.get(job.id);
      const justFinished =
        (prev === "pending" || prev === "running") && TERMINAL_JOB_STATUSES.includes(job.status);
      if (justFinished && IMPORT_JOB_KINDS.includes(job.kind)) reloadServers = true;
      if (justFinished && PKGS_JOB_KINDS.includes(job.kind)) reloadPackages = true;
      if (justFinished && CRED_JOB_KINDS.includes(job.kind)) reloadCredentials = true;
      if (justFinished && PROV_JOB_KINDS.includes(job.kind)) reloadProv = true;
      if (justFinished && job.kind === CONNECT_PRIMARY_JOB_KIND) {
        reloadProv = true;
        reloadCredentials = true;
      }
      lastJobStatus.set(job.id, job.status);
    }
    const currentIds = new Set(jobs.map((j) => j.id));
    for (const id of lastJobStatus.keys()) if (!currentIds.has(id)) lastJobStatus.delete(id);

    const activePush = jobs.filter(
      (j) => j.kind === "pkgs.push_to_repo" && (j.status === "pending" || j.status === "running"),
    );
    if (activePush.length || pkgPushProgress.size) await refreshPushProgress(activePush);

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
    // A prov.* job (add/edit/delete) could be either a server or a firewall —
    // the kind alone doesn't say which (see PROV_JOB_KINDS) — so just reload
    // both; cheap, and simpler than threading an entity hint through the poll.
    // loadServers() itself reloads firewalls at its end (see its last line) —
    // calling loadFirewalls() again here in parallel raced it: both cleared
    // the firewalls tbody and then both appended their own rows on top,
    // doubling every row (operator-reported, 2026-07-23).
    if (reloadProv) await loadServers();
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
