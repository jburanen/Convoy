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

/* ---------- 2. status chips ---------- */

async function refreshStatus() {
  const box = document.getElementById("status-chips");
  box.replaceChildren();
  try {
    const s = await api("/api/status");
    addChip(box, `v${s.version}`);
    addChip(box, `${s.management_servers} management server(s)`);
    addChip(box, `${s.packages} package(s)`);
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

/* ---------- 3. servers ---------- */

async function loadServers() {
  const tbody = document.querySelector("#servers-table tbody");
  const namelist = document.getElementById("server-names");
  const servers = await api("/api/servers");
  const packages = await api("/api/packages");

  tbody.replaceChildren();
  namelist.replaceChildren();

  for (const srv of servers) {
    const row = el("tpl-server-row");
    row.querySelector(".srv-name").textContent = srv.name;
    row.querySelector(".srv-address").textContent = srv.address;
    row.querySelector(".srv-creds").textContent =
      srv.credentials.length ? srv.credentials.join(", ") : "none";

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

    const opt = document.createElement("option");
    opt.value = srv.name;
    namelist.appendChild(opt);
  }

  if (!servers.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "muted";
    td.textContent = "No management servers in inventory. Mount an inventory.yaml (see examples/).";
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

async function refreshState(name, row) {
  const btn = row.querySelector(".btn-refresh");
  const agentDiv = row.querySelector(".srv-agent");
  const pkgsDiv = row.querySelector(".srv-packages");
  btn.disabled = true;
  agentDiv.textContent = "querying…";
  try {
    const state = await api(`/api/servers/${encodeURIComponent(name)}/state`);
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
    agentDiv.textContent = "detect failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function importPackage(name, row) {
  const select = row.querySelector(".pkg-select");
  if (!select.value) { toast("Choose an uploaded package first."); return; }
  try {
    await api(`/api/servers/${encodeURIComponent(name)}/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: select.value }),
    });
    await loadJobs();
  } catch (e) {
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
  try {
    await api(`/api/servers/${encodeURIComponent(name)}/install`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_id: packageId, confirmed: true }),
    });
    await loadJobs();
  } catch (e) {
    toast("Install failed to start: " + e.message);
  }
}

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
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete package ${pkg.filename}?`)) return;
      try {
        await api(`/api/packages/${encodeURIComponent(pkg.filename)}`, { method: "DELETE" });
        await Promise.all([loadPackages(), loadServers(), refreshStatus()]);
      } catch (e) { toast("Delete failed: " + e.message); }
    });
    tbody.appendChild(row);
  }
}

document.getElementById("upload-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("upload-file");
  const progress = document.getElementById("upload-progress");
  const btn = document.getElementById("upload-btn");
  if (!input.files.length) return;

  const form = new FormData();
  form.append("file", input.files[0]);
  btn.disabled = true;
  progress.textContent = "uploading… (large packages take a while)";
  try {
    await api("/api/packages", { method: "POST", body: form });
    progress.textContent = "done";
    input.value = "";
    await Promise.all([loadPackages(), loadServers(), refreshStatus()]);
  } catch (e) {
    progress.textContent = "";
    toast("Upload failed: " + e.message);
  } finally {
    btn.disabled = false;
  }
});

/* ---------- 5. credentials ---------- */

async function loadCredentials() {
  const tbody = document.querySelector("#credentials-table tbody");
  tbody.replaceChildren();
  let creds;
  try {
    creds = await api("/api/credentials");
  } catch (e) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "muted";
    td.textContent = e.message;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const cred of creds) {
    const row = el("tpl-credential-row");
    row.querySelector(".cred-host").textContent = cred.host;
    row.querySelector(".cred-kind").textContent = cred.kind;
    row.querySelector(".cred-username").textContent = cred.username ?? "";
    row.querySelector(".btn-delete").addEventListener("click", async () => {
      if (!confirm(`Delete ${cred.kind} credential for ${cred.host}?`)) return;
      try {
        await api(
          `/api/credentials/${encodeURIComponent(cred.host)}/${encodeURIComponent(cred.kind)}`,
          { method: "DELETE" },
        );
        await Promise.all([loadCredentials(), loadServers()]);
      } catch (e) { toast("Delete failed: " + e.message); }
    });
    tbody.appendChild(row);
  }
}

document.getElementById("credential-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const secretInput = document.getElementById("cred-secret");
  try {
    await api("/api/credentials", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host: document.getElementById("cred-host").value.trim(),
        kind: document.getElementById("cred-kind").value,
        username: document.getElementById("cred-username").value.trim() || null,
        secret: secretInput.value,
      }),
    });
    secretInput.value = ""; // never keep the secret around in the form
    await Promise.all([loadCredentials(), loadServers()]);
  } catch (e) {
    toast("Save failed: " + e.message);
  }
});

/* ---------- 6. jobs ---------- */

const openJobLogs = new Set(); // job ids whose progress log is expanded

async function loadJobs() {
  const tbody = document.querySelector("#jobs-table tbody");
  const jobs = await api("/api/jobs?limit=25");
  tbody.replaceChildren();
  for (const job of jobs) {
    const row = el("tpl-job-row");
    row.querySelector(".job-kind").textContent = job.kind;
    row.querySelector(".job-target").textContent = job.target ?? "";
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
    const active = jobs.some((j) => j.status === "pending" || j.status === "running");
    if (active || openJobLogs.size) await loadJobs();
  } catch { /* transient — next tick will retry */ }
  setTimeout(pollJobs, 2500);
}

/* ---------- boot ---------- */

(async function init() {
  await refreshStatus();
  await Promise.all([loadServers(), loadPackages(), loadCredentials(), loadJobs()]);
  pollJobs();
})();
