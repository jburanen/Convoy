from __future__ import annotations

import pytest

from chkp_cpuse_orch.config import Config
from chkp_cpuse_orch.inventory import Cluster, Host, Inventory, Role, Site
from chkp_cpuse_orch.web.auth import ALLOW_NO_AUTH_ENV, BASIC_AUTH_DISABLE_ENV


@pytest.fixture(autouse=True)
def _no_basic_auth_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Basic auth is on by default in production (see web/auth.py), but most tests
    predate it and assume `create_app(config)` with no authenticator runs open.
    Disable it here so that holds; tests exercising basic auth itself override with
    monkeypatch.delenv/setenv (same monkeypatch fixture, so it composes cleanly).

    Both vars are needed: running with no auth is a deliberate two-key action in
    production (see ALLOW_NO_AUTH_ENV), and the test suite opting into it is
    exactly the kind of deliberate choice that gate is meant to require."""
    monkeypatch.setenv(BASIC_AUTH_DISABLE_ENV, "true")
    monkeypatch.setenv(ALLOW_NO_AUTH_ENV, "1")


@pytest.fixture
def inventory() -> Inventory:
    """A small estate: one mgmt server, one standalone gateway, one 2-member cluster."""
    return Inventory(
        sites=[
            Site(
                name="dc1",
                hosts=[
                    Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT),
                    Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY),
                    Host(name="fw-a1", address="192.0.2.31", role=Role.CLUSTER_MEMBER),
                    Host(name="fw-a2", address="192.0.2.32", role=Role.CLUSTER_MEMBER),
                ],
                clusters=[Cluster(name="cluster-a", members=["fw-a2", "fw-a1"])],
            )
        ]
    )


@pytest.fixture
def config() -> Config:
    return Config()
