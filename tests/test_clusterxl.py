from __future__ import annotations

from chkp_cpuse_orch.clusterxl import parse_cluster_state

# Real-shaped `show cluster state` output (see clusterxl.py docstring).
ACTIVE_MEMBER_OUTPUT = """\
Cluster Mode:   High Availability (Active Up) with IGMP Membership

ID         Unique Address  Assigned Load   State          Name

1 (local)  11.22.33.245    100%            ACTIVE(!)      Member1
2          11.22.33.246    0%              DOWN           Member2


Active PNOTEs: COREXL
"""

STANDBY_MEMBER_OUTPUT = """\
Cluster Mode:   High Availability (Active Up)

ID         Unique Address  Assigned Load   State          Name

1          11.22.33.245    100%            ACTIVE(!)      Member1
2 (local)  11.22.33.246    0%              STANDBY        Member2
"""


def test_parse_cluster_state_local_active() -> None:
    state = parse_cluster_state(ACTIVE_MEMBER_OUTPUT)
    assert state is not None
    assert state.role == "ACTIVE(!)"
    assert state.cluster_name == "Member1, Member2"
    assert state.is_active
    assert not state.is_standby


def test_parse_cluster_state_local_standby() -> None:
    state = parse_cluster_state(STANDBY_MEMBER_OUTPUT)
    assert state is not None
    assert state.role == "STANDBY"
    assert state.cluster_name == "Member1, Member2"
    assert state.is_standby
    assert not state.is_active


def test_parse_cluster_state_none_when_no_member_table() -> None:
    assert parse_cluster_state("") is None
    assert parse_cluster_state("This machine is not part of a cluster.\n") is None
