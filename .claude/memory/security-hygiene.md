---
name: security-hygiene
description: What must never be committed once this repo goes public
metadata:
  type: project
---

This repo is **intended to become public**. It orchestrates real customer security
infrastructure, so leaking config is a genuine risk to the operators who use it.

**Why:** a public commit history is forever. A single leaked inventory exposes
management-server and firewall hostnames, IPs, and SIC/topology detail; a leaked key
or `.env` is a direct compromise path.

**How to apply:**
- Never commit: SSH keys, certs, `*.env`, credentials, vault passwords, real
  `inventory*.yaml`, CDT XML plans, target CSVs, package repos, logs, run reports, or
  captured state. All are covered by `.gitignore` / `.claudeignore` — keep both
  updated as new sensitive artifact types appear.
- Only **`*.example.yaml` / `*.sample.yaml`** templates with placeholder values are
  tracked. Real files use the same names *without* `.example` and are ignored.
- Secrets come from environment / a secrets store at runtime, never from tracked
  files. `config.py` reads them; they are not defaulted in code.
- Before any commit on a public-bound branch, sanity-check `git status` for stray
  inventories, keys, or logs. When adding a new artifact type that could carry
  infrastructure detail, add its pattern to **both** ignore files first.
- Keep this aligned with [[safety-constraints]] — same principle, different surface.
