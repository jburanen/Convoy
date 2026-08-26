from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.credentials import (
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
from chkp_cpuse_orch.errors import JobError
from chkp_cpuse_orch.jobs import JobRunner
from chkp_cpuse_orch.services.common import EnvironmentRegistry
from chkp_cpuse_orch.services.connect_primary import JOB_CONNECT_PRIMARY, PrimaryConnectService
from chkp_cpuse_orch.services.environments import EnvironmentManager
from chkp_cpuse_orch.store import Store

from .fakes import FakeTransport, make_factory

ENV = "default"
SECRET_MARKER = "s3cr3t-key-value"


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
    return FakeTransport(
        responses={
            # Not found by default (rc != 0) — the common case: no admin yet.
            "show administrator name": (1, ""),
            "add api-key": f'{{"api-key": "{SECRET_MARKER}"}}',
        }
    )


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
    manager.rebuild()
    return manager


@pytest.fixture
def vault() -> JobCredentialVault:
    return JobCredentialVault()


@pytest.fixture
def service(
    store: Store,
    credentials: CredentialStore,
    env_manager: EnvironmentManager,
    registry: EnvironmentRegistry,
    vault: JobCredentialVault,
) -> PrimaryConnectService:
    return PrimaryConnectService(
        registry=registry,
        env_manager=env_manager,
        credentials=credentials,
        vault=vault,
        runner=JobRunner(store),
        store=store,
    )


def _run(service: PrimaryConnectService) -> None:
    asyncio.run(service.runner.run_until_idle())


def _submit(
    service: PrimaryConnectService,
    *,
    credential_set: str | None = "primary",
    address: str = "192.0.2.10",
    confirm_address_change: bool = False,
):
    return service.submit_connect_primary(
        ENV,
        name="mgmt-01",
        address=address,
        role="primary_sms",
        ssh_user="svc-patch",
        ssh_port=22,
        credential_set=credential_set,
        is_mds=False,
        confirm_address_change=confirm_address_change,
    )


def test_upserts_server_row_synchronously(
    service: PrimaryConnectService, env_manager: EnvironmentManager
) -> None:
    """The inventory add happens in submit_connect_primary itself, before the
    job even runs — so a bad role/name collision would surface immediately."""
    _submit(service)
    servers = env_manager.list_servers(ENV)
    assert [s.name for s in servers] == ["mgmt-01"]


def test_creates_administrator_when_missing_and_captures_key(
    service: PrimaryConnectService, store: Store, transport: FakeTransport
) -> None:
    job = _submit(service)
    assert job.kind == JOB_CONNECT_PRIMARY
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "succeeded"
    joined = "\n".join(transport.commands)
    assert "add administrator name svc-patch" in joined
    assert "add api-key admin-name svc-patch" in joined


def test_skips_add_administrator_when_already_exists(
    service: PrimaryConnectService, store: Store, transport: FakeTransport
) -> None:
    transport.responses["show administrator name"] = (0, '{"name": "svc-patch"}')
    job = _submit(service)
    _run(service)
    assert store.get_job(job.id).status.value == "succeeded"
    assert not any("add administrator" in c for c in transport.commands)
    # Re-running to "regenerate" a key must still issue a fresh add-api-key call.
    assert any("add api-key" in c for c in transport.commands)


def test_reveal_api_key_is_pop_once(service: PrimaryConnectService, store: Store) -> None:
    job = _submit(service)
    _run(service)
    assert store.get_job(job.id).status.value == "succeeded"
    assert service.reveal_api_key(job.id) == SECRET_MARKER
    assert service.reveal_api_key(job.id) is None


def test_reveal_api_key_unknown_job_returns_none(service: PrimaryConnectService) -> None:
    assert service.reveal_api_key("no-such-job") is None


def test_key_persisted_to_credential_set_when_storage_enabled(
    service: PrimaryConnectService, store: Store, credentials: CredentialStore
) -> None:
    job = _submit(service)
    _run(service)
    assert store.get_job(job.id).status.value == "succeeded"
    info = credentials.get_info(ENV, "primary")
    assert info is not None
    assert info.has_api is True


def test_key_never_appears_in_job_log(service: PrimaryConnectService, store: Store) -> None:
    job = _submit(service)
    _run(service)
    events = store.events(job.id)
    for event in events:
        assert SECRET_MARKER not in event.message


def test_parse_failure_fails_job_without_leaking_raw_output(
    service: PrimaryConnectService, store: Store, transport: FakeTransport
) -> None:
    """A garbled `add api-key` response must fail the job with a generic
    message — never the raw stdout, which could itself contain a secret."""
    transport.responses["add api-key"] = f"not json at all, {SECRET_MARKER}"
    job = _submit(service)
    _run(service)
    finished = store.get_job(job.id)
    assert finished.status.value == "failed"
    assert SECRET_MARKER not in (finished.error or "")
    for event in store.events(job.id):
        assert SECRET_MARKER not in event.message
    # Nothing was ever captured to reveal.
    assert service.reveal_api_key(job.id) is None


def test_transport_failure_fails_job(
    service: PrimaryConnectService, store: Store, transport: FakeTransport
) -> None:
    transport.fail_rc = 1
    job = _submit(service)
    _run(service)
    assert store.get_job(job.id).status.value == "failed"


def test_storage_disabled_environment_still_reveals_key(
    tmp_path: Path,
    transport: FakeTransport,
    vault: JobCredentialVault,
) -> None:
    """No credential store to persist into — the key is still recoverable via
    the one-time reveal, per the storage-disabled design. Storage-disabled
    means an operator-supplied CredentialBundle rides along on submit,
    exactly like PatchingService's own storage-disabled path."""
    disabled_store = Store(tmp_path / "disabled.db")
    disabled_store.insert_environment(ENV, credential_storage_enabled=False)
    registry = EnvironmentRegistry()
    env_manager = EnvironmentManager(disabled_store, registry, None, make_factory(transport))
    env_manager.rebuild()
    service = PrimaryConnectService(
        registry=registry,
        env_manager=env_manager,
        credentials=None,
        vault=vault,
        runner=JobRunner(disabled_store),
        store=disabled_store,
    )
    inline_creds = {
        CredentialKind.SSH_PASSWORD: Credential(
            host="mgmt-01", kind=CredentialKind.SSH_PASSWORD, secret=SecretStr("inline-pw")
        ),
        # mgmt_cli is bash-native — the bootstrap job needs it too, same as a
        # storage-enabled environment's stored set (see require_expert=True
        # on submit_connect_primary's submit_host_job call).
        CredentialKind.EXPERT_PASSWORD: Credential(
            host="mgmt-01", kind=CredentialKind.EXPERT_PASSWORD, secret=SecretStr("expert-pw")
        ),
    }
    job = service.submit_connect_primary(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="svc-patch",
        ssh_port=22,
        credential_set=None,
        is_mds=False,
        credentials=inline_creds,
    )
    _run(service)
    assert disabled_store.get_job(job.id).status.value == "succeeded"
    assert service.reveal_api_key(job.id) == SECRET_MARKER


# -- address repointing (security) ------------------------------------------------
#
# add_server is an upsert, so posting an existing server's name with a new
# address silently repoints that row — handing its stored SSH/expert
# credentials to whatever answers at the new address, and redirecting every
# later job for the environment. That takes an explicit acknowledgement.


def test_repointing_an_existing_server_requires_confirmation(
    service: PrimaryConnectService, env_manager: EnvironmentManager
) -> None:
    _submit(service)
    _run(service)

    with pytest.raises(JobError, match="would repoint that server"):
        _submit(service, address="198.51.100.99")

    # the original row is untouched
    assert [s.address for s in env_manager.list_servers(ENV)] == ["192.0.2.10"]


def test_repointing_succeeds_when_confirmed(
    service: PrimaryConnectService, env_manager: EnvironmentManager
) -> None:
    _submit(service)
    _run(service)

    _submit(service, address="198.51.100.99", confirm_address_change=True)

    assert [s.address for s in env_manager.list_servers(ENV)] == ["198.51.100.99"]


def test_reconnecting_to_the_same_address_needs_no_confirmation(
    service: PrimaryConnectService, env_manager: EnvironmentManager
) -> None:
    """Only a *change* is gated — an ordinary reconnect must stay friction-free."""
    _submit(service)
    _run(service)

    _submit(service)  # same address, no confirmation flag

    assert [s.address for s in env_manager.list_servers(ENV)] == ["192.0.2.10"]


def test_adding_a_brand_new_server_needs_no_confirmation(
    service: PrimaryConnectService, env_manager: EnvironmentManager
) -> None:
    _submit(service)
    assert [s.name for s in env_manager.list_servers(ENV)] == ["mgmt-01"]


# -- api-key reveal is scoped to the operator who ran the job (H6) -----------------
#
# Pop-once limits HOW MANY times the key can be read, not by whom. Job ids are
# listed to every authenticated user by /api/jobs, so without an ownership check
# anyone logged in could poll for a fresh connect-primary job and win the race
# for someone else's freshly minted Management API key.


def test_reveal_api_key_refuses_another_operators_job(
    service: PrimaryConnectService, store: Store
) -> None:
    job = service.submit_connect_primary(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="svc-patch",
        ssh_port=22,
        credential_set="primary",
        is_mds=False,
        triggered_by="alice",
    )
    _run(service)

    assert service.reveal_api_key(job.id, requested_by="mallory") is None
    # ...and it was not consumed by the refusal, so the owner can still read it
    assert service.reveal_api_key(job.id, requested_by="alice") is not None


def test_reveal_api_key_allows_the_owner_and_is_still_pop_once(
    service: PrimaryConnectService,
) -> None:
    job = service.submit_connect_primary(
        ENV,
        name="mgmt-01",
        address="192.0.2.10",
        role="primary_sms",
        ssh_user="svc-patch",
        ssh_port=22,
        credential_set="primary",
        is_mds=False,
        triggered_by="alice",
    )
    _run(service)

    assert service.reveal_api_key(job.id, requested_by="alice") is not None
    assert service.reveal_api_key(job.id, requested_by="alice") is None
