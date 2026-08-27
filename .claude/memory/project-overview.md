---
name: project-overview
description: What Convoy is, who uses it, and what problem it solves
metadata:
  type: project
---

**Convoy** is an **internal orchestration tool** for organizations running
Check Point firewalls and security infrastructure. It wraps and coordinates Check
Point's **Central Deployment Tool (CDT)** to roll out patches and upgrades
(hotfixes, Jumbo Hotfix Accumulators, and major-version upgrades) across fleets of
**Security Management Servers and Security Gateways**.

**Why it exists:** CDT and CPUSE are powerful but operate one command / one plan at
a time and lack fleet-level guardrails. Real deployments need staged rollouts,
per-site batching, pre/post health checks, maintenance-window gating, and auditable
records. This tool is the orchestration layer that provides those.

**Users:** internal security/network operations engineers running authorized
maintenance on infrastructure they own. This is a defensive, operational tool — not
an exploitation tool.

**Scope boundary:** the tool *drives* CDT/CPUSE; it does not reimplement package
verification or installation. Check Point's agents remain the source of truth for
install state. See [[cdt-cpuse-domain]] and [[safety-constraints]].
