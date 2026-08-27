// Per-panel help text — the single place to edit any panel's descriptive
// copy. `brief` renders directly on the panel (kept to one short clause);
// `full` (a string, or an array of strings for multiple paragraphs) renders
// in that panel's help modal, opened via its (?) button. Both may contain
// simple inline HTML (<strong>, <em>, <a>). Nothing else needs to change to
// edit this copy — see app.js's renderPanelHelp()/openHelpModal().
//
// `{{archivePath}}` in jobs.full is substituted at render time with the live
// job-archive path reported by /api/status (see app.js's substituteHelp()).
const PANEL_HELP = {
  provision: {
    title: "Bootstrap initial management access",
    brief:
      "Generates clish commands to provision this tool's service account. " +
      "<strong class=\"prov-note-warn\">Apply them in clish on every management server</strong>, " +
      "then continue to Connect to Primary below.",
    full:
      "The generated commands create this tool's service account. Its credentials are " +
      "saved to the <strong>Credentials</strong> table below automatically.",
  },
  "connect-primary": {
    title: "Connect to Primary",
    brief:
      "Connect to the primary once the clish commands above have been applied, to " +
      "create its Management API access.",
    full:
      "Creates (or re-issues a key for) a Management API administrator over SSH — no " +
      "copy-paste required. You'll be shown the exact commands to confirm before anything runs.",
  },
  credentials: {
    title: "Credentials",
    brief: "Named login sets, encrypted at rest — assign one to each server below.",
    full:
      "Stored encrypted at rest using <strong>argon2id</strong>; secrets are never displayed " +
      "again after saving. Give one an SSH password <em>or</em> a private key (plus an " +
      "optional expert password for privileged CPUSE steps). One set can be assigned to " +
      "many servers.",
  },
  "servers-info": {
    title: "Management Servers",
    brief:
      "Once Connect to Primary above has succeeded, discover or manually add the rest " +
      "of your management servers.",
    full:
      "These are used to orchestrate bulk patching of firewalls owned by this environment, " +
      "and can also be patched directly with this tool on the <strong>CPUSE</strong> tab.",
  },
  smart1cloud: {
    title: "Smart-1 Cloud",
    brief:
      "Connect this environment to its Smart-1 Cloud tenant — the hosted management " +
      "server, reached only by Management API key.",
    full: [
      "Check Point hosts the management server for a Smart-1 Cloud environment, so there " +
      "is no SSH to it: no service account to bootstrap, no Connect to Primary, no CPUSE " +
      "patching of the management server, and no estate to discover. This one connection " +
      "replaces all of it.",
      "Everything comes off <strong>Settings → API &amp; SmartConsole</strong> in Smart-1 " +
      "Cloud: the maas URL prefix and tenant UUID from the login request it prints, plus " +
      "the Management API key. Connecting logs in to prove all three before storing " +
      "anything, then registers the tenant as this environment's management server with " +
      "the key held in a credential set.",
      "The environment's <strong>firewalls</strong> are unaffected — they are still " +
      "reached over SSH and patched exactly as anywhere else.",
    ],
  },
  packages: {
    title: "Packages",
    brief:
      "Upload a package once, then distribute it to any server — drag &amp; drop, or " +
      "pick a file below.",
    full: [
      "Compare the SHA-1 / SHA-256 with the values published on the Check Point download " +
        "page before importing anywhere. Uploads are <strong>auto-deleted after the " +
        "retention window</strong> (30 days by default) unless you tick <strong>Keep</strong> " +
        "to store them indefinitely.",
      "<strong>Upload to Mgmt</strong>, below, is a separate step: it pushes an already-stored " +
        "package into the current environment's primary management server's own package " +
        "repository via the Management API, so it's available there for policy installs and " +
        "hotfix imports from SmartConsole or CDT. It runs as a background job (large-file " +
        "transfer + server-side import) — track it on the <strong>Jobs</strong> tab.",
    ],
  },
  servers: {
    title: "Management Servers",
    brief:
      "Patched locally via CPUSE — click <strong>Refresh</strong> (or <strong>Refresh " +
      "all</strong> above) to query live state over SSH.",
    full:
      "CDT does not patch management servers. The detected state shown below (last row " +
      "per server) stays cached until refreshed. Assign or change a server's credential " +
      "set from the <strong>Edit</strong> button on the Provisioning tab.",
  },
  firewalls: {
    title: "Firewalls",
    brief:
      "Direct CPUSE patching, one host at a time over SSH — best for a small number of " +
      "standalone gateways or cluster members.",
    full:
      "Gateways can also be patched from SmartConsole or Web SmartConsole — see " +
      "<a class=\"sk-link\" href=\"https://support.checkpoint.com/results/sk/sk170314\" " +
      "target=\"_blank\" rel=\"noopener\">sk170314</a>. For large numbers of gateways, use the " +
      "<strong>Gateways</strong> tab (CDT bulk fleet push, planned for version 2). Add " +
      "firewalls manually or discover them from a Primary SMS/MDS. The detected state shown " +
      "below (last row per firewall) stays cached until refreshed.",
  },
  cdt: {
    title: "Gateway deployment (CDT)",
    brief: "CDT runs on a management server and bulk-pushes a package to many gateways.",
    full:
      "Flow: <strong>Stage</strong> (upload package + write CDT config) → " +
      "<strong>Generate</strong> candidates → <strong>Load</strong>, reorder and trim the " +
      "list (row order = deployment order = blast-radius control) → <strong>Save order</strong> " +
      "→ optional <strong>Prepare</strong> → <strong>Execute</strong>. Execute runs under " +
      "nohup on the server and is followed live on the Jobs tab.",
  },
  jobs: {
    title: "Jobs",
    brief:
      "Click a row to see its progress log or view installation logs for completed " +
      "installs. Running jobs can be cancelled at the next safe point.",
    full:
      "Jobs older than a year are removed from this list, archived to " +
      "<span class=\"mono\">{{archivePath}}</span>, and stored there for three additional years.",
  },
};
