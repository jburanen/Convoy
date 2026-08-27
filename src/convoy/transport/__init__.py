"""Transport layer: how the orchestrator reaches Gaia hosts.

Three transports, thin and swappable:
- ``ssh``       — Paramiko SSH to Gaia clish / expert (baseline).
- ``gaia_api``  — Gaia REST API.
- ``mgmt_api``  — Check Point Management API (mgmt_cli / web-api).

Wrappers (cpuse, cdt) depend on these interfaces, not on a specific client, so the
orchestration logic can be tested against fakes without live gear.
"""
