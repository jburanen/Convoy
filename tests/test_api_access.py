from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from chkp_cpuse_orch.credentials import CredentialStore
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.services.api_access import (
    JOB_REPAIR_API_ACCESS,
    ApiAccessService,
    parse_api_status,
    render_repair_commands,
)
from chkp_cpuse_orch.services.common import EnvironmentRegistry
from chkp_cpuse_orch.services.environments import EnvironmentManager
from chkp_cpuse_orch.store import Store

from .fakes import FakeTransport, make_factory

ENV = "default"

HEALTHY_UNRESTRICTED = """\
Processes:

Name      State     PID       More Information
-------------------------------------------------
API       Started   1234      Command Line Interface

--------------------------------------------
Overall API Status: Started
Accessibility: All IP addresses that can be used for GUI clients
--------------------------------------------

API readiness test SUCCESSFUL. The server is up and ready to receive connections
"""

RESTRICTED_TO_LOCAL = """\
Processes:

Name      State     PID       More Information
-------------------------------------------------
API       Started   1234      Command Line Interface

--------------------------------------------
Overall API Status: Started
Accessibility: require local
--------------------------------------------

API readiness test SUCCESSFUL. The server is up and ready to receive connections
"""

NOT_STARTED = """\
--------------------------------------------
Overall API Status: Stopped
--------------------------------------------
"""


# ---- pure parsing / rendering ----------------------------------------------------


def test_parse_api_status_healthy_and_unrestricted() -> None:
    started, restricted = parse_api_status(HEALTHY_UNRESTRICTED)
    assert started is True
    assert restricted is False


def test_parse_api_status_restricted_to_local() -> None:
    started, restricted = parse_api_status(RESTRICTED_TO_LOCAL)
    assert started is True
    assert restricted is True


def test_parse_api_status_not_started() -> None:
    started, restricted = parse_api_status(NOT_STARTED)
    assert started is False
    assert restricted is False


def test_render_repair_commands_sms() -> None:
    cmds = render_repair_commands(is_mds=False)
    joined = "\n".join(cmds)
    assert cmds[0].startswith('umask 077; mgmt_cli login -r true --domain "System Data" > ')
    assert (
        'set api-settings accepted-api-calls-from "All IP addresses that can be used '
        'for GUI clients" --domain "System Data"'
    ) in joined
    assert any(c.endswith("publish") for c in cmds)
    assert cmds[-1] == "api restart"


def test_render_repair_commands_mds_omits_domain() -> None:
    cmds = render_repair_commands(is_mds=True)
    assert "--domain" not in cmds[0]


# ---- service (diagnose + repair job) ----------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment(ENV, credential_storage_enabled=True)
    return store


@pytest.fixture
def credentials(store: Store) -> CredentialStore:
    cs = CredentialStore(store, master_key="unit test master key")
    cs.put_set(
        ENV,
        "primary",
        ssh_username="svc-patch",
        ssh_password="gaia-pw",
        expert_password="expert-pw",
    )
    return cs


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(responses={"api status": RESTRICTED_TO_LOCAL})


@pytest.fixture
def registry() -> EnvironmentRegistry:
    return EnvironmentRegistry()


@pytest.fixture
def env_manager(
    store: Store,
    credentials: CredentialStore,
    transport: FakeTransport,
    registry: EnvironmentRegistry,
) -> EnvironmentManager:
    manager = EnvironmentManager(store, registry, credentials, make_factory(transport))
    manager.add_server(
        ENV, name="mgmt-01", address="192.0.2.10", role="primary_sms", ssh_user="svc-patch"
    )
    manager.assign_credential(ENV, "mgmt-01", "primary")
    manager.rebuild()
    return manager


@pytest.fixture
def service(
    env_manager: EnvironmentManager, registry: EnvironmentRegistry, store: Store
) -> ApiAccessService:
    return ApiAccessService(registry=registry, runner=JobRunner(store))


def _run(service: ApiAccessService) -> None:
    asyncio.run(service.runner.run_until_idle())


def test_diagnose_reports_restricted_to_local(service: ApiAccessService) -> None:
    diag = service.diagnose(ENV)
    assert diag.error is None
    assert diag.overall_started is True
    assert diag.restricted_to_local is True


def test_diagnose_reports_unrestricted(service: ApiAccessService, transport: FakeTransport) -> None:
    transport.responses["api status"] = HEALTHY_UNRESTRICTED
    diag = service.diagnose(ENV)
    assert diag.restricted_to_local is False
    assert diag.overall_started is True


def test_diagnose_unknown_environment_becomes_error(service: ApiAccessService) -> None:
    """registry.get() itself can raise for an unknown environment — this must
    become ``.error``, not propagate and crash the endpoint (confirmed via a
    live smoke test: this used to 500)."""
    diag = service.diagnose("no-such-env")
    assert diag.error is not None
    assert "unknown environment" in diag.error


def test_diagnose_no_primary_configured(registry: EnvironmentRegistry, store: Store) -> None:
    # An environment that exists but has no primary yet.
    store.insert_environment("empty", credential_storage_enabled=True)
    manager = EnvironmentManager(store, registry, None, make_factory(FakeTransport()))
    manager.rebuild()
    service = ApiAccessService(registry=registry, runner=JobRunner(store))
    diag = service.diagnose("empty")
    assert diag.error is not None
    assert "no Primary" in diag.error


def test_diagnose_ssh_failure_becomes_error(
    service: ApiAccessService, transport: FakeTransport
) -> None:
    transport.fail_rc = 1
    diag = service.diagnose(ENV)
    assert diag.error is not None
    assert "exited 1" in diag.error


def test_preview_repair_commands_matches_render(service: ApiAccessService) -> None:
    """Modulo the per-run session path: each render mints a fresh unguessable
    one (see provisioning.new_api_session_file), which is the whole point."""

    def norm(commands: list[str]) -> list[str]:
        return [re.sub(r"cpuse_orch_mgmt_api\.[0-9a-f]+\.sid", "SESSION", c) for c in commands]

    assert norm(service.preview_repair_commands(ENV)) == norm(render_repair_commands(is_mds=False))


def test_repair_job_widens_restricted_access(
    service: ApiAccessService, store: Store, transport: FakeTransport
) -> None:
    job = service.submit_repair(ENV)
    assert job.kind == JOB_REPAIR_API_ACCESS
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "succeeded"
    joined = "\n".join(transport.commands)
    assert "set api-settings accepted-api-calls-from" in joined
    assert "api restart" in joined
    events = "\n".join(e.message for e in store.events(job.id))
    assert "restarted the API server" in events


def test_repair_job_is_noop_when_already_unrestricted(
    service: ApiAccessService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["api status"] = HEALTHY_UNRESTRICTED
    job = service.submit_repair(ENV)
    _run(service)
    assert store.get_job(job.id).status.value == "succeeded"
    assert not any("set api-settings" in c for c in transport.commands)
    events = "\n".join(e.message for e in store.events(job.id))
    assert "nothing to repair" in events


def test_repair_job_fails_on_transport_error(
    service: ApiAccessService, store: Store, transport: FakeTransport
) -> None:
    transport.fail_rc = 1
    job = service.submit_repair(ENV)
    _run(service)
    assert store.get_job(job.id).status.value == "failed"
