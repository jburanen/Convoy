from __future__ import annotations

import asyncio
import dataclasses
import shlex
from pathlib import Path

import pytest

from convoy.credentials import CredentialKind, CredentialStore, JobCredentialVault
from convoy.errors import InventoryError, JobError, ProvisioningError
from convoy.jobs import JobRunner
from convoy.services.common import EnvironmentRegistry
from convoy.services.environments import EnvironmentManager
from convoy.services.mgmt_bootstrap import JOB_BOOTSTRAP_MGMT, MgmtBootstrapService
from convoy.services.provisioning import REDACTED_HASH
from convoy.store import Store
from convoy.transport.ssh import GaiaShell

from .fakes import FakeTransport

ENV = "default"
LOGIN_USER = "existing-login"  # distinctive: "admin" would match adminRole
LOGIN_PW = "existing-admin-pw"
ACCOUNT = "svc-patch"
ACCOUNT_PW = "new-account-pw"


class _Recorder:
    """ClientFactory that records the host and credentials it was handed."""

    def __init__(self, transport: FakeTransport) -> None:
        self.transport = transport
        self.calls: list[tuple[object, dict]] = []

    def __call__(self, host: object, creds: dict) -> FakeTransport:
        self.calls.append((host, creds))
        return self.transport


@pytest.fixture
def store(tmp_path: Path) -> Store:
    store = Store(tmp_path / "orch.db")
    store.insert_environment(ENV, credential_storage_enabled=True)
    return store


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(shell=GaiaShell.CLISH)


@pytest.fixture
def recorder(transport: FakeTransport) -> _Recorder:
    return _Recorder(transport)


@pytest.fixture
def credentials(store: Store) -> CredentialStore:
    cs = CredentialStore(store, master_key="unit test master key")
    # A stored set the job must NOT use, even though storage is enabled.
    cs.put_set(
        ENV, "stored", ssh_username="stored-user", ssh_password="stored-pw", expert_password="x"
    )
    return cs


@pytest.fixture
def registry(
    store: Store, credentials: CredentialStore, recorder: _Recorder
) -> EnvironmentRegistry:
    registry = EnvironmentRegistry()
    EnvironmentManager(store, registry, credentials, recorder).rebuild()
    return registry


@pytest.fixture
def vault() -> JobCredentialVault:
    return JobCredentialVault()


@pytest.fixture
def service(
    store: Store, registry: EnvironmentRegistry, vault: JobCredentialVault
) -> MgmtBootstrapService:
    holder: list[MgmtBootstrapService] = []

    def finished(job_id: str) -> None:  # mirrors web/app.py's job_finished
        vault.discard(job_id)
        holder[0].discard(job_id)

    svc = MgmtBootstrapService(
        registry=registry,
        vault=vault,
        runner=JobRunner(store, on_job_finished=finished),
        store=store,
    )
    holder.append(svc)
    return svc


def _submit(service: MgmtBootstrapService, **overrides: object):
    kwargs: dict[str, object] = {
        "address": "192.0.2.10",
        "ssh_port": 2222,
        "login_username": LOGIN_USER,
        "login_password": LOGIN_PW,
        "account_username": ACCOUNT,
        "account_password": ACCOUNT_PW,
    }
    kwargs.update(overrides)
    return service.submit_bootstrap(ENV, **kwargs)  # type: ignore[arg-type]


def _run(service: MgmtBootstrapService) -> None:
    asyncio.run(service.runner.run_until_idle())


def _everything_persisted(store: Store, job_id: str) -> str:
    job = store.get_job(job_id)
    events = " ".join(e.message for e in store.events(job_id))
    return f"{job.model_dump_json()} {events}"


def test_clish_login_runs_commands_bare_with_the_temporary_login(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport, recorder: _Recorder
) -> None:
    job = _submit(service)
    assert job.kind == JOB_BOOTSTRAP_MGMT
    _run(service)

    assert store.get_job(job.id).status.value == "succeeded"
    host, creds = recorder.calls[0]
    assert (host.address, host.ssh_port) == ("192.0.2.10", 2222)  # type: ignore[attr-defined]
    login = creds[CredentialKind.SSH_PASSWORD]
    assert (login.username, login.reveal()) == (LOGIN_USER, LOGIN_PW)  # not the stored set
    assert [c.split()[0:2] for c in transport.commands] == [
        ["add", "user"],
        ["set", "user"],
        ["add", "rba"],
        ["set", "user"],
        ["save", "config"],
    ]
    assert transport.commands[0] == f"add user {ACCOUNT} uid 0 homedir /home/{ACCOUNT}"
    assert transport.closed


def test_bash_login_wraps_each_command_in_clish_c(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport
) -> None:
    transport.shell = GaiaShell.EXPERT
    _submit(service)
    _run(service)
    assert all(c.startswith("clish -c ") for c in transport.commands)
    assert shlex.split(transport.commands[-1]) == ["clish", "-c", "save config"]


def test_nothing_secret_is_persisted_and_memory_is_purged(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport, vault: JobCredentialVault
) -> None:
    job = _submit(service)
    _run(service)
    password_hash = transport.commands[1].split()[-1]
    assert password_hash.startswith("$6$")
    persisted = _everything_persisted(store, job.id)
    for secret in (LOGIN_PW, LOGIN_USER, ACCOUNT_PW, password_hash):
        assert secret not in persisted, secret
    assert REDACTED_HASH in persisted  # the log shows the command shape, redacted
    assert store.get_job(job.id).params == {"ssh_port": 2222, "account_username": ACCOUNT}
    assert vault.get(job.id) is None
    assert service._pending.get(job.id) is None


def test_failure_reports_the_device_error_with_the_hash_redacted(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport
) -> None:
    # A device that echoes the offending command back must not leak the hash.
    transport.responses = {"password-hash": (1, "CLINFR0409 Invalid hash: {echo}")}

    def echo_run(command: str, *, timeout: float | None = None):
        result = FakeTransport.run(transport, command, timeout=timeout)
        return dataclasses.replace(result, stdout=result.stdout.replace("{echo}", command))

    transport.run = echo_run  # type: ignore[method-assign]
    job = _submit(service)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert "CLINFR0409" in (finished.error or "")
    assert REDACTED_HASH in (finished.error or "")
    assert "$6$" not in _everything_persisted(store, job.id)
    assert not any(c.startswith("save config") for c in transport.commands)  # stopped early


LOCKED = (
    1,
    "CLINFR0771 Config lock is owned by webui-admin. "
    "Use the command 'lock database override' to acquire the lock.",
)


def test_config_lock_on_first_command_is_overridden_and_the_command_retried(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport
) -> None:
    transport.responses = {"add user": [LOCKED, (0, "")]}
    job = _submit(service)
    _run(service)

    assert store.get_job(job.id).status.value == "succeeded"
    assert transport.commands[:3] == [
        f"add user {ACCOUNT} uid 0 homedir /home/{ACCOUNT}",
        "lock database override",
        f"add user {ACCOUNT} uid 0 homedir /home/{ACCOUNT}",
    ]
    assert transport.commands[-1] == "save config"  # carried on to the end
    events = [e for e in store.events(job.id) if e.level == "warning"]
    assert any("lock database override" in e.message for e in events)


def test_config_lock_override_is_wrapped_for_a_bash_login(
    service: MgmtBootstrapService, transport: FakeTransport
) -> None:
    transport.shell = GaiaShell.EXPERT
    transport.responses = {"add user": [LOCKED, (0, "")]}
    _submit(service)
    _run(service)
    assert transport.commands[1] == "clish -c 'lock database override'"


def test_config_lock_on_the_hash_command_never_logs_the_hash(
    service: MgmtBootstrapService,
    store: Store,
    transport: FakeTransport,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transport.responses = {"password-hash": [LOCKED, (0, "")]}
    job = _submit(service)
    _run(service)
    assert store.get_job(job.id).status.value == "succeeded"
    assert "lock database override" in transport.commands
    assert "$6$" not in _everything_persisted(store, job.id)
    assert "$6$" not in capsys.readouterr().out  # the structlog warning too


def test_a_lock_that_survives_the_override_fails_after_one_retry(
    service: MgmtBootstrapService, store: Store, transport: FakeTransport
) -> None:
    transport.responses = {"add user": LOCKED}
    job = _submit(service)
    _run(service)

    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert "CLINFR0771" in (finished.error or "")
    assert transport.commands.count("lock database override") == 1
    assert not any(c.startswith("set user") for c in transport.commands)


def test_cancelled_before_running_still_purges_memory(
    service: MgmtBootstrapService, store: Store, vault: JobCredentialVault
) -> None:
    job = _submit(service)
    service.runner.request_cancel(job.id)
    _run(service)
    assert vault.get(job.id) is None
    assert service._pending.get(job.id) is None


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"address": "  "}, JobError),
        ({"login_username": ""}, JobError),
        ({"login_password": ""}, JobError),
        ({"account_username": "Bad User"}, ProvisioningError),
        ({"account_password": "short"}, ProvisioningError),
    ],
)
def test_rejects_bad_input_without_queueing_a_job(
    service: MgmtBootstrapService,
    store: Store,
    vault: JobCredentialVault,
    overrides: dict,
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        _submit(service, **overrides)
    assert store.list_jobs() == []


def test_refuses_an_api_only_environment(service: MgmtBootstrapService, store: Store) -> None:
    store.set_environment_access(ENV, True)
    EnvironmentManager(store, service._registry, None).rebuild()
    with pytest.raises(JobError, match="API-only"):
        _submit(service)


def test_refuses_an_unknown_environment(service: MgmtBootstrapService) -> None:
    with pytest.raises(InventoryError):
        service.submit_bootstrap(
            "ghost",
            address="192.0.2.10",
            ssh_port=22,
            login_username=LOGIN_USER,
            login_password=LOGIN_PW,
            account_username=ACCOUNT,
            account_password=ACCOUNT_PW,
        )


def test_refuses_a_second_job_on_a_busy_address(
    service: MgmtBootstrapService, store: Store, vault: JobCredentialVault
) -> None:
    first = _submit(service)
    with pytest.raises(JobError, match="already"):
        _submit(service)
    assert vault.get(first.id) is not None  # the queued one keeps its login
