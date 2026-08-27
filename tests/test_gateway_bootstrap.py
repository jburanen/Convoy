from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Any

import pytest

from convoy.credentials import CredentialStore
from convoy.errors import CredentialError, InventoryError
from convoy.inventory import Host, Inventory, Role, Site
from convoy.jobs import JobRunner
from convoy.services.common import EnvironmentRegistry, HostConnector
from convoy.services.gateway_bootstrap import GatewayBootstrapService
from convoy.services.provisioning import REDACTED_HASH
from convoy.store import JobStatus, Store


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment("default", credential_storage_enabled=True)
    return store


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    return CredentialStore(store, master_key="correct horse battery staple")


@pytest.fixture
def runner(store: Store) -> JobRunner:
    return JobRunner(store)


def _inventory(*hosts: Host) -> Inventory:
    return Inventory(sites=[Site(name="t", hosts=list(hosts))])


def _registry(inventory: Inventory, creds: CredentialStore | None) -> EnvironmentRegistry:
    registry = EnvironmentRegistry()
    registry.add("default", HostConnector(inventory, creds))
    return registry


def _assign(store: Store, inventory: Inventory, host_name: str, set_name: str) -> None:
    row = store.get_credential_set_by_name("default", set_name)
    assert row is not None
    for site in inventory.sites:
        for host in site.hosts:
            if host.name == host_name:
                host.credential_set_id = row.id


def _run(runner: JobRunner) -> None:
    asyncio.run(runner.run_until_idle())


def test_preview_renders_gaia_user_commands_from_assigned_set(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY))
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "fw-01", "primary")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    commands = service.preview_bootstrap_commands("default", "fw-01")

    assert commands[0] == "add user admin uid 0 homedir /home/admin"
    # The preview must NOT carry a real hash: it is a plain GET open to every
    # authenticated user, and a 5000-round sha512_crypt hash is offline-
    # crackable. The push computes the real value itself.
    assert commands[1] == f"set user admin password-hash {REDACTED_HASH}"
    assert not any("$6$" in c for c in commands)


def test_preview_rejects_private_key_only_credential_set(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY))
    creds.put_set(
        "default",
        "keyset",
        ssh_username="admin",
        ssh_private_key="KEYDATA",
        expert_password="expert-pw",
    )
    _assign(store, inv, "fw-01", "keyset")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(CredentialError, match="private key, not a"):
        service.preview_bootstrap_commands("default", "fw-01")


def test_preview_requires_an_assigned_credential_set(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY))
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(CredentialError, match="no credential assigned"):
        service.preview_bootstrap_commands("default", "fw-01")


def test_preview_rejects_unknown_firewall(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory()
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(InventoryError):
        service.preview_bootstrap_commands("default", "nope")


def test_preview_rejects_non_firewall_role(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT))
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(InventoryError, match="not a firewall"):
        service.preview_bootstrap_commands("default", "mgmt-01")


def test_preview_rejects_spark_firewall(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    # Spark uses a different clish command family entirely (add administrator,
    # not add user/set user password-hash) — see preview_spark_admin_commands.
    inv = _inventory(Host(name="spark-01", address="192.0.2.30", role=Role.SPARK_FIREWALL))
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "spark-01", "primary")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(InventoryError, match="Spark firewall"):
        service.preview_bootstrap_commands("default", "spark-01")


def test_submit_bootstrap_rejects_spark_firewall(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="spark-01", address="192.0.2.30", role=Role.SPARK_FIREWALL))
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "spark-01", "primary")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(InventoryError, match="Spark firewall"):
        service.submit_bootstrap("default", "spark-01")


def test_preview_spark_admin_commands_renders_add_administrator(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="spark-01", address="192.0.2.30", role=Role.SPARK_FIREWALL))
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "spark-01", "primary")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    commands = service.preview_spark_admin_commands("default", "spark-01")

    assert len(commands) == 1
    assert commands[0].startswith("add administrator username admin password-hash $6$")
    assert commands[0].endswith('permission "Super Admin"')


def test_preview_spark_admin_commands_rejects_non_spark_firewall(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY))
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "fw-01", "primary")
    service = GatewayBootstrapService(registry=_registry(inv, creds), store=store, runner=runner)

    with pytest.raises(InventoryError, match="not a Spark firewall"):
        service.preview_spark_admin_commands("default", "fw-01")


# -- _do_bootstrap job execution (fake Management API client) ---------------------
#
# Response shape below is the REAL show-task payload for a run-script task,
# verified against live gear 2026-08-18 (see the module docstring in
# services/gateway_bootstrap.py) — not a guess.


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class _FakeMgmtClient:
    def __init__(
        self,
        *,
        task_sequence: list[dict[str, Any]],
        objects: list[dict[str, Any]] | None = None,
        **kwargs: object,
    ) -> None:
        self._tasks = list(task_sequence)
        # What the management database reports for show-gateways-and-servers.
        # Defaults to fw-01 at the address the test inventories use, so the
        # target-identity check (see _confirm_target_identity) passes; tests
        # that exercise a mismatch pass their own list.
        self._objects = (
            objects if objects is not None else [{"name": "fw-01", "ipv4-address": "192.0.2.20"}]
        )
        self.kwargs = kwargs
        self.run_script_calls: list[tuple[str, list[str], str]] = []

    def __enter__(self) -> _FakeMgmtClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def show_gateways_and_servers(self, *, details_level: str = "full") -> list[dict[str, Any]]:
        return self._objects

    def run_script(
        self, script: str, targets: list[str], *, script_name: str = "convoy-run"
    ) -> str:
        self.run_script_calls.append((script, targets, script_name))
        return "6a99e21c-681a-4d6d-87f4-9a0cb0854332"

    def show_task(self, task_id: str) -> dict[str, Any]:
        if len(self._tasks) > 1:
            return self._tasks.pop(0)
        return self._tasks[0]


def _succeeded_task(
    gateway_name: str = "clutch", output: str = "hello-from-run-script\n"
) -> dict[str, Any]:
    """Mirrors the real show-task response pasted by the operator verbatim
    (trimmed to the fields this code actually reads)."""
    return {
        "task-id": "6a99e21c-681a-4d6d-87f4-9a0cb0854332",
        "status": "succeeded",
        "progress-percentage": 100,
        "task-details": [
            {
                "statusCode": "succeeded",
                "gatewayName": gateway_name,
                "responseMessage": _b64(output),
                "responseError": "",
            }
        ],
    }


def _failed_task(error: str = "clish: command not found") -> dict[str, Any]:
    return {
        "task-id": "6a99e21c-681a-4d6d-87f4-9a0cb0854332",
        "status": "failed",
        "progress-percentage": 100,
        "task-details": [
            {
                "statusCode": "failed",
                "gatewayName": "clutch",
                "responseMessage": _b64(""),
                "responseError": error,
            }
        ],
    }


def _service_for_job(
    store: Store,
    creds: CredentialStore,
    runner: JobRunner,
    *,
    task_sequence: list[dict[str, Any]],
    objects: list[dict[str, Any]] | None = None,
) -> GatewayBootstrapService:
    inv = _inventory(
        Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS),
        Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY),
    )
    creds.put_set(
        "default",
        "mgmt-creds",
        ssh_username="admin",
        ssh_password="mgmtpw123",
        expert_password="expert-pw",
    )
    _assign(store, inv, "mgmt-01", "mgmt-creds")
    creds.put_set(
        "default",
        "fw-creds",
        ssh_username="admin",
        ssh_password="s3cret-pw!",
        expert_password="expert-pw",
    )
    _assign(store, inv, "fw-01", "fw-creds")
    return GatewayBootstrapService(
        registry=_registry(inv, creds),
        store=store,
        runner=runner,
        mgmt_client_factory=lambda host, **kw: _FakeMgmtClient(
            task_sequence=task_sequence, objects=objects, **kw
        ),
        poll_interval=0,
    )


def test_submit_bootstrap_succeeds_and_logs_gateway_output(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    service = _service_for_job(store, creds, runner, task_sequence=[_succeeded_task()])

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.SUCCEEDED, finished.error
    events = [e.message for e in store.events(job.id)]
    assert any("hello-from-run-script" in e for e in events)
    # The plaintext password never appears in any logged event.
    assert not any("s3cret-pw!" in e for e in events)


def test_submit_bootstrap_records_failure_from_task_status(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    service = _service_for_job(store, creds, runner, task_sequence=[_failed_task()])

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "clish: command not found" in (finished.error or "")


def test_submit_bootstrap_polls_until_terminal_status(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    in_progress = {
        "task-id": "6a99e21c-681a-4d6d-87f4-9a0cb0854332",
        "status": "in progress",
        "progress-percentage": 50,
        "task-details": [],
    }
    service = _service_for_job(
        store, creds, runner, task_sequence=[in_progress, in_progress, _succeeded_task()]
    )

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED


def test_do_bootstrap_rejects_private_key_only_set_before_any_api_call(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    inv = _inventory(
        Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS),
        Host(name="fw-01", address="192.0.2.20", role=Role.GATEWAY),
    )
    creds.put_set(
        "default",
        "mgmt-creds",
        ssh_username="admin",
        ssh_password="mgmtpw123",
        expert_password="expert-pw",
    )
    _assign(store, inv, "mgmt-01", "mgmt-creds")
    creds.put_set(
        "default",
        "keyset",
        ssh_username="admin",
        ssh_private_key="KEYDATA",
        expert_password="expert-pw",
    )
    _assign(store, inv, "fw-01", "keyset")
    calls: list[_FakeMgmtClient] = []

    def factory(host: object, **kw: object) -> _FakeMgmtClient:
        client = _FakeMgmtClient(task_sequence=[_succeeded_task()], **kw)
        calls.append(client)
        return client

    service = GatewayBootstrapService(
        registry=_registry(inv, creds),
        store=store,
        runner=runner,
        mgmt_client_factory=factory,
        poll_interval=0,
    )

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "private key, not a" in (finished.error or "")
    assert calls == []  # never even opened a Management API session


def test_decode_task_output_refuses_to_confirm_without_task_details() -> None:
    """A task-level "succeeded" is not evidence the SCRIPT succeeded — that
    lives in task-details, and confirming without it would be the same
    confirmed-on-no-evidence bug the security review closed elsewhere."""
    from convoy.services.gateway_bootstrap import _decode_task_output

    ok, message = _decode_task_output(
        {"status": "succeeded", "progress-percentage": 100, "comments": "Completed"}
    )
    assert ok is False
    assert "task-details" in message
    # The raw response belongs in the job log, not inline in the UI's error.
    assert "progress-percentage" not in message


def test_decode_task_output_handles_unexpected_shape() -> None:
    from convoy.services.gateway_bootstrap import _decode_task_output

    ok, message = _decode_task_output({"status": "succeeded", "task-details": []})
    assert ok is False
    assert "task-details" in message


# -- target-identity confirmation (security: run-script resolves by NAME) ----------
#
# run-script hands a bare name to the management server, which resolves it
# against its own object database over SIC. The local row's address is the only
# thing binding that name to a real device, so _do_bootstrap must confirm the
# two agree before pushing a uid-0 adminRole account. See _confirm_target_identity.


def test_bootstrap_refuses_when_mgmt_resolves_name_to_a_different_address(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    """The attack this blocks: name a local row after a real SIC-trusted
    gateway, point its address anywhere, and the bootstrap lands on the real
    gateway instead of the configured one."""
    service = _service_for_job(
        store,
        creds,
        runner,
        task_sequence=[_succeeded_task()],
        objects=[{"name": "fw-01", "ipv4-address": "198.51.100.99"}],
    )

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    error = finished.error or ""
    assert "192.0.2.20" in error and "198.51.100.99" in error
    assert "different device" in error


def test_bootstrap_refuses_when_mgmt_does_not_know_the_name(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    service = _service_for_job(store, creds, runner, task_sequence=[_succeeded_task()], objects=[])

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "no gateway/server object named" in (finished.error or "")


def test_bootstrap_refuses_when_resolved_object_has_no_address(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    """Fail closed: an object we can't pin to an address is not a confirmation."""
    service = _service_for_job(
        store, creds, runner, task_sequence=[_succeeded_task()], objects=[{"name": "fw-01"}]
    )

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "reports no IP address" in (finished.error or "")


def test_bootstrap_refuses_an_ambiguous_name(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    service = _service_for_job(
        store,
        creds,
        runner,
        task_sequence=[_succeeded_task()],
        objects=[
            {"name": "fw-01", "ipv4-address": "192.0.2.20"},
            {"name": "fw-01", "ipv4-address": "192.0.2.21"},
        ],
    )

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    finished = store.get_job(job.id)
    assert finished.status is JobStatus.FAILED
    assert "ambiguous target" in (finished.error or "")


def test_bootstrap_logs_the_resolved_management_side_address(
    store: Store, creds: CredentialStore, runner: JobRunner
) -> None:
    """The audit trail has to record which device was actually touched, not
    just the caller-supplied name."""
    service = _service_for_job(store, creds, runner, task_sequence=[_succeeded_task()])

    job = service.submit_bootstrap("default", "fw-01")
    _run(runner)

    assert store.get_job(job.id).status is JobStatus.SUCCEEDED
    messages = [e.message for e in store.events(job.id)]
    assert any("resolves to 192.0.2.20" in m for m in messages)
