from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from chkp_cpuse_orch.errors import InventoryError
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.services.common import EnvironmentRegistry
from chkp_cpuse_orch.services.environments import EnvironmentManager
from chkp_cpuse_orch.services.firewalls import FirewallManager
from chkp_cpuse_orch.services.prov_ops import (
    JOB_ADD,
    JOB_DELETE,
    JOB_EDIT,
    ProvisioningJobService,
)
from chkp_cpuse_orch.store import CredentialSetRow, Store

ENV = "default"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment(ENV, credential_storage_enabled=True)
    return store


@pytest.fixture
def env_manager(store: Store) -> EnvironmentManager:
    return EnvironmentManager(store, EnvironmentRegistry(), credentials=None, client_factory=None)


@pytest.fixture
def firewall_manager(store: Store, env_manager: EnvironmentManager) -> FirewallManager:
    return FirewallManager(store, env_manager)


@pytest.fixture
def service(
    store: Store, env_manager: EnvironmentManager, firewall_manager: FirewallManager
) -> ProvisioningJobService:
    return ProvisioningJobService(
        store=store,
        env_manager=env_manager,
        firewall_manager=firewall_manager,
        runner=JobRunner(store),
    )


def _run(service: ProvisioningJobService) -> None:
    asyncio.run(service.runner.run_until_idle())


def _credset(store: Store, name: str = "primary", *, is_default: bool = False) -> None:
    store.upsert_credential_set(
        CredentialSetRow(environment=ENV, name=name, ssh_password_ct=b"ct", is_default=is_default)
    )


# -- servers: add / edit ---------------------------------------------------------


def test_new_server_submits_as_add(
    service: ProvisioningJobService, env_manager: EnvironmentManager
) -> None:
    job = service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_ADD
    assert job.target == "mgmt-01"
    _run(service)
    servers = env_manager.list_servers(ENV)
    assert [s.name for s in servers] == ["mgmt-01"]


def test_existing_server_submits_as_edit(
    service: ProvisioningJobService, env_manager: EnvironmentManager
) -> None:
    service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    job = service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.11",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_EDIT
    _run(service)
    servers = env_manager.list_servers(ENV)
    assert servers[0].address == "192.0.2.11"


def test_server_validation_error_surfaces_as_a_failed_job_not_a_raise(
    service: ProvisioningJobService, store: Store
) -> None:
    """A gateway role is invalid for a management server — EnvironmentManager.
    add_server raises inside the handler, so submission itself succeeds
    (matches cred.* — operator-directed, 2026-07-23)."""
    job = service.submit_put_server(
        ENV,
        name="fw-x",
        address="192.0.2.10",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert "not a management server role" in (finished.error or "")


def test_server_credential_set_assignment_folds_into_the_same_job(
    service: ProvisioningJobService, store: Store, env_manager: EnvironmentManager
) -> None:
    _credset(store, "primary")
    service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        credential_set="primary",
    )
    _run(service)
    assert env_manager.list_servers(ENV)[0].credential_set_id is not None


def test_server_credential_set_omitted_leaves_default_on_create_alone(
    service: ProvisioningJobService, store: Store, env_manager: EnvironmentManager
) -> None:
    """No credential_set kwarg at all → EnvironmentManager.add_server's own
    "inherit the environment default" logic decides, untouched."""
    _credset(store, "primary", is_default=True)
    service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    assert env_manager.list_servers(ENV)[0].credential_set_id is not None


def test_server_credential_set_explicit_none_clears_it(
    service: ProvisioningJobService, store: Store, env_manager: EnvironmentManager
) -> None:
    """Explicit null (vs. omitted) overrides even the default-on-create
    inheritance — same "always fires the assignment" behavior the Add Firewall/
    Server modal has always had."""
    _credset(store, "primary", is_default=True)
    service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        credential_set=None,
    )
    _run(service)
    assert env_manager.list_servers(ENV)[0].credential_set_id is None


# -- servers: delete --------------------------------------------------------------


def test_delete_server_removes_it(
    service: ProvisioningJobService, env_manager: EnvironmentManager
) -> None:
    service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    job = service.submit_delete_server(ENV, "mgmt-01")
    assert job.kind == JOB_DELETE
    assert job.target == "mgmt-01"
    _run(service)
    assert env_manager.list_servers(ENV) == []


def test_submit_delete_server_on_missing_server_raises_synchronously(
    service: ProvisioningJobService, store: Store
) -> None:
    """No job should even be created for an obviously-doomed request — same
    convention as CredentialJobService.submit_delete."""
    with pytest.raises(InventoryError, match="not found"):
        service.submit_delete_server(ENV, "ghost")
    assert store.list_jobs() == []


# -- firewalls: add / edit / delete -----------------------------------------------


def test_new_firewall_submits_as_add(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_ADD
    assert job.target == "fw-01"
    _run(service)
    assert [f.name for f in firewall_manager.list_firewalls(ENV)] == ["fw-01"]


def test_existing_firewall_submits_as_edit(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.21",
        role="cluster_member",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_EDIT
    _run(service)
    firewalls = firewall_manager.list_firewalls(ENV)
    assert firewalls[0].address == "192.0.2.21"
    assert firewalls[0].role == "cluster_member"


def test_cluster_name_is_applied_on_creation(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    """A discovery import passes cluster_name along with the initial create."""
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="cluster_member",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        cluster_name="prod-cluster",
    )
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].cluster_name == "prod-cluster"


def test_cluster_name_is_never_applied_on_a_later_edit(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    """Regression guard: an ordinary edit (e.g. the Edit-firewall modal's Save
    changes, which never sends cluster_name) must not wipe out a
    previously-detected name — only genuine creation (JOB_ADD) applies it."""
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="cluster_member",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        cluster_name="prod-cluster",
    )
    _run(service)

    # An edit that (correctly, per the frontend) omits cluster_name entirely.
    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.21",
        role="cluster_member",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_EDIT
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].cluster_name == "prod-cluster"

    # Even if a caller mistakenly passed a cluster_name on an edit, it's
    # still ignored — the JOB_ADD gate in ProvisioningJobService._do_put is
    # what protects this, not the caller remembering to omit the field.
    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.22",
        role="cluster_member",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        cluster_name="some-other-cluster",
    )
    assert job.kind == JOB_EDIT
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].cluster_name == "prod-cluster"


def test_mds_domain_is_applied_on_creation(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    """A discovery import passes mds_domain along with the initial create,
    same as cluster_name."""
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        mds_domain="CustomerA",
    )
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].mds_domain == "CustomerA"


def test_mds_domain_is_never_applied_on_a_later_edit(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    """Regression guard mirroring test_cluster_name_is_never_applied_on_a_later_edit:
    an ordinary edit must not wipe out a previously-tracked domain, and even a
    caller mistakenly passing mds_domain on an edit is ignored — the JOB_ADD
    gate protects this, not caller discipline."""
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        mds_domain="CustomerA",
    )
    _run(service)

    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.21",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert job.kind == JOB_EDIT
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].mds_domain == "CustomerA"

    job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.22",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
        mds_domain="CustomerB",
    )
    assert job.kind == JOB_EDIT
    _run(service)
    assert firewall_manager.list_firewalls(ENV)[0].mds_domain == "CustomerA"


def test_firewall_validation_error_surfaces_as_a_failed_job(
    service: ProvisioningJobService, store: Store
) -> None:
    job = service.submit_put_firewall(
        ENV,
        name="mgmt-x",
        address="192.0.2.20",
        role="management",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert "not a firewall role" in (finished.error or "")


def test_delete_firewall_removes_it(
    service: ProvisioningJobService, firewall_manager: FirewallManager
) -> None:
    service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    _run(service)
    job = service.submit_delete_firewall(ENV, "fw-01")
    assert job.kind == JOB_DELETE
    _run(service)
    assert firewall_manager.list_firewalls(ENV) == []


def test_submit_delete_firewall_on_missing_firewall_raises_synchronously(
    service: ProvisioningJobService, store: Store
) -> None:
    with pytest.raises(InventoryError, match="not found"):
        service.submit_delete_firewall(ENV, "ghost")
    assert store.list_jobs() == []


# -- shared job kinds across entity types -----------------------------------------


def test_server_and_firewall_add_share_the_same_job_kind(
    service: ProvisioningJobService,
) -> None:
    """Operator-directed, 2026-07-23: no server/firewall split in the Kind
    column — both entity types share prov.add/prov.edit/prov.delete, and an
    internal params["entity"] discriminator (invisible on the Jobs tab) tells
    the single handler pair which manager to call."""
    server_job = service.submit_put_server(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    firewall_job = service.submit_put_firewall(
        ENV,
        name="fw-01",
        address="192.0.2.20",
        role="gateway",
        ssh_user="admin",
        ssh_port=22,
        notes=None,
    )
    assert server_job.kind == firewall_job.kind == JOB_ADD
