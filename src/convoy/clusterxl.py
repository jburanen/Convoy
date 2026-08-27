"""ClusterXL live state — parses `show cluster state` (Gaia clish) to answer
"is this host a cluster member, and is it active or standby right now."

Read-only and best-effort: it backs the Firewalls panel's live status line,
not deployment gating (that's checks.py's still-unimplemented `cluster_state`
health check, a different consumer with different requirements — it needs a
pass/fail verdict against an *expected* role, not a display string).

Check Point doesn't expose the SmartConsole cluster object's own name via CLI
on the member itself (confirmed against Check Point's own docs) — `show
cluster state` only lists each member's own hostname. So the "cluster name"
here is a stand-in: every member hostname the table lists, comma-joined —
not the configured cluster object name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Sample row shapes (see `show cluster state` in the field):
#   1 (local)  11.22.33.245    100%            ACTIVE(!)      Member1
#   2          11.22.33.246    0%              DOWN           Member2
_MEMBER_ROW_RE = re.compile(
    r"^(?P<id>\d+)\s*(?P<local>\(local\))?\s+"
    r"(?P<addr>\S+)\s+(?P<load>\S+)\s+(?P<state>\S+)\s+(?P<name>\S+)\s*$"
)


@dataclass(frozen=True)
class ClusterMemberState:
    """This host's live ClusterXL role, parsed from `show cluster state`."""

    role: str  # raw State text for the local member, e.g. "ACTIVE(!)", "STANDBY", "DOWN"
    cluster_name: str  # comma-joined member hostnames (see module docstring) — never empty

    @property
    def is_active(self) -> bool:
        return self.role.strip().upper().startswith("ACTIVE")

    @property
    def is_standby(self) -> bool:
        return self.role.strip().upper().startswith("STANDBY")


def parse_cluster_state(stdout: str) -> ClusterMemberState | None:
    """Parse `show cluster state` output. Returns None if it contains no
    recognizable member table — e.g. the host isn't a cluster member at all
    (a standalone gateway's exact non-member output isn't documented, so this
    treats anything unparseable the same way: not a cluster member, not an
    error). Tolerant by design, like cpuse.parse_packages: an unrecognized
    line is skipped rather than failing the whole parse."""
    local_role: str | None = None
    names: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _MEMBER_ROW_RE.match(line)
        if not m:
            continue
        names.append(m.group("name"))
        if m.group("local"):
            local_role = m.group("state")
    if local_role is None or not names:
        return None
    return ClusterMemberState(role=local_role, cluster_name=", ".join(names))


__all__ = ["ClusterMemberState", "parse_cluster_state"]
