# CLAUDE.md — Convoy

Project instructions for Claude Code. Persistent project knowledge lives in
[.claude/memory/](.claude/memory/MEMORY.md) — read that index first.

## What this is
An **internal orchestration tool** for organizations running Check Point firewalls.
It coordinates Check Point's **Central Deployment Tool (CDT)** (and CPUSE on
individual Gaia hosts) to deploy patches and upgrades — hotfixes, Jumbo Hotfix
Accumulators, and major-version upgrades — across fleets of **Security Management
Servers and Security Gateways**. It is a **defensive, operational** tool for
authorized maintenance on infrastructure the operator owns.

See [.claude/memory/cdt-cpuse-domain.md](.claude/memory/cdt-cpuse-domain.md) for how
CDT/CPUSE actually work.

## Stack
Python 3.11+, `src/` layout. Typer (CLI), Pydantic v2 (config/inventory), Paramiko
(SSH to Gaia), httpx (Gaia REST + Management API), Rich, structlog, tenacity.
Tooling: pytest, ruff, mypy. Details:
[.claude/memory/tech-stack.md](.claude/memory/tech-stack.md).

## Layout
- `src/convoy/` — package (see
  [.claude/memory/architecture.md](.claude/memory/architecture.md))
- `tests/` — pytest suite
- `examples/` — `*.example.yaml` inventory/config templates (only these are tracked)
- `.claude/memory/` — project memory

## Working here — read before you code
- **This repo is public-bound.** Never commit secrets, real inventories, CDT plans,
  logs, or run reports. Only `*.example.*` templates are tracked. Keep `.gitignore`
  and `.claudeignore` updated when new sensitive artifact types appear. See
  [.claude/memory/security-hygiene.md](.claude/memory/security-hygiene.md).
- **This touches production firewalls.** Honor the operational safety rules —
  dry-run by default, cluster-aware ordering, health gating, bounded blast radius,
  rollback path, full audit logging. See
  [.claude/memory/safety-constraints.md](.claude/memory/safety-constraints.md).
- Keep CDT/CPUSE wrappers thin (execute + parse). Sequencing and safety decisions
  belong in `orchestrator.py` / `checks.py`, where they are unit-testable without
  live gear.

## Common commands
```bash
pip install -e ".[dev]"     # install with dev extras
pytest                      # run tests
ruff check . && ruff format .
mypy src
convoy --help      # CLI entrypoint (once installed)
```

## Maintaining memory
When you learn a durable project fact, add/update a file in `.claude/memory/` and
index it in `.claude/memory/MEMORY.md` — one fact per file, with frontmatter.
