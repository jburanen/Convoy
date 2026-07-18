# Project Memory — chkp-cpuse-orch

Index of persistent project facts. One line per memory; details live in the linked file.
Load this at the start of each session; read a linked file when its hook looks relevant.

- [Project Overview](project-overview.md) — what this tool orchestrates and for whom
- [CDT & CPUSE Domain](cdt-cpuse-domain.md) — how Check Point's deployment tooling actually works
- [Tech Stack](tech-stack.md) — Python + Typer + Paramiko/Gaia API; why
- [Architecture](architecture.md) — module layout and data flow
- [Patching & Web Design](patching-web-design.md) — two subsystems, web-primary service core, credential/package/job infra
- [Operational Safety Constraints](safety-constraints.md) — HA/cluster rules, dry-run-first, maintenance windows
- [Security & Public-Repo Hygiene](security-hygiene.md) — what must never be committed once public
- [Use the documentation-tool MCP](use-documentation-tool-mcp.md) — always prefer it for docs lookups
