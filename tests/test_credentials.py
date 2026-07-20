from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from chkp_cpuse_orch.credentials import (
    MASTER_KEY_ENV,
    MASTER_KEY_FILE_ENV,
    Credential,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
    ensure_ssh_credential,
    load_master_key,
)
from chkp_cpuse_orch.errors import CredentialError
from chkp_cpuse_orch.store import Store


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "orch.db")


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    return CredentialStore(store, master_key="correct horse battery staple")


def _cred(
    secret: str = "s3cret!", kind: CredentialKind = CredentialKind.SSH_PASSWORD
) -> Credential:
    return Credential(host="mgmt-01", kind=kind, username="admin", secret=SecretStr(secret))


def test_put_get_roundtrip(creds: CredentialStore) -> None:
    creds.put(_cred("hunter22"))
    loaded = creds.get("mgmt-01", CredentialKind.SSH_PASSWORD)
    assert loaded.reveal() == "hunter22"
    assert loaded.username == "admin"


def test_ciphertext_on_disk_is_not_plaintext(creds: CredentialStore, store: Store) -> None:
    creds.put(_cred("supersecretvalue"))
    rec = store.get_credential("mgmt-01", "ssh_password")
    assert rec is not None
    assert b"supersecretvalue" not in rec.ciphertext


def test_secret_never_in_repr(creds: CredentialStore) -> None:
    creds.put(_cred("topsecret"))
    loaded = creds.get("mgmt-01", CredentialKind.SSH_PASSWORD)
    assert "topsecret" not in repr(loaded)
    assert "topsecret" not in str(loaded)


def test_wrong_master_key_fails_fast(store: Store) -> None:
    CredentialStore(store, master_key="the right key").put(_cred())
    with pytest.raises(CredentialError, match="master key does not match"):
        CredentialStore(store, master_key="not the right key")


def test_same_key_reopens_fine(store: Store) -> None:
    CredentialStore(store, master_key="the right key").put(_cred("abc"))
    reopened = CredentialStore(store, master_key="the right key")
    assert reopened.get("mgmt-01", CredentialKind.SSH_PASSWORD).reveal() == "abc"


def test_missing_credential_raises_but_try_get_returns_none(creds: CredentialStore) -> None:
    with pytest.raises(CredentialError, match="no ssh_password credential"):
        creds.get("nowhere", CredentialKind.SSH_PASSWORD)
    assert creds.try_get("nowhere", CredentialKind.SSH_PASSWORD) is None


def test_for_host_returns_mixed_auth_bundle(creds: CredentialStore) -> None:
    creds.put(_cred("pw", CredentialKind.SSH_PASSWORD))
    creds.put(_cred("-----BEGIN OPENSSH PRIVATE KEY-----", CredentialKind.SSH_PRIVATE_KEY))
    bundle = creds.for_host("mgmt-01")
    assert set(bundle) == {CredentialKind.SSH_PASSWORD, CredentialKind.SSH_PRIVATE_KEY}
    assert bundle[CredentialKind.SSH_PASSWORD].reveal() == "pw"


def test_list_is_secret_free(creds: CredentialStore) -> None:
    creds.put(_cred("classified"))
    infos = creds.list()
    assert len(infos) == 1
    assert infos[0].host == "mgmt-01"
    assert infos[0].kind is CredentialKind.SSH_PASSWORD
    assert "classified" not in repr(infos)


def test_delete(creds: CredentialStore) -> None:
    creds.put(_cred())
    assert creds.delete("mgmt-01", CredentialKind.SSH_PASSWORD) is True
    assert creds.delete("mgmt-01", CredentialKind.SSH_PASSWORD) is False


def test_empty_secret_refused(creds: CredentialStore) -> None:
    with pytest.raises(CredentialError, match="empty secret"):
        creds.put(_cred(""))


def test_load_master_key_from_env() -> None:
    assert load_master_key({MASTER_KEY_ENV: "long enough key"}) == "long enough key"


def test_load_master_key_from_file(tmp_path: Path) -> None:
    key_file = tmp_path / "master.key"
    key_file.write_text("file-based-key\n", encoding="utf-8")
    assert load_master_key({MASTER_KEY_FILE_ENV: str(key_file)}) == "file-based-key"


def test_load_master_key_missing_or_short() -> None:
    with pytest.raises(CredentialError, match="no master key"):
        load_master_key({})
    with pytest.raises(CredentialError, match="at least"):
        load_master_key({MASTER_KEY_ENV: "short"})


# -- ephemeral (in-memory) credentials for storage-disabled environments -----------


def _bundle(kind: CredentialKind = CredentialKind.SSH_PASSWORD) -> dict:
    return {kind: Credential(host="h", kind=kind, secret=SecretStr("pw"))}


def test_ensure_ssh_credential_requires_ssh() -> None:
    with pytest.raises(CredentialError, match="provide an SSH"):
        ensure_ssh_credential({}, "mgmt-01", "dmz")
    # An expert password alone is not enough to open a session.
    with pytest.raises(CredentialError, match="provide an SSH"):
        ensure_ssh_credential(_bundle(CredentialKind.EXPERT_PASSWORD), "mgmt-01", "dmz")
    # A password or a private key each satisfy it (no raise).
    ensure_ssh_credential(_bundle(CredentialKind.SSH_PASSWORD), "mgmt-01", "dmz")
    ensure_ssh_credential(_bundle(CredentialKind.SSH_PRIVATE_KEY), "mgmt-01", "dmz")


def test_job_credential_vault_lifecycle() -> None:
    vault = JobCredentialVault()
    bundle = _bundle()
    assert vault.get("j1") is None
    with pytest.raises(CredentialError, match="no in-memory credentials"):
        vault.require("j1")

    vault.put("j1", bundle)
    assert vault.get("j1") is bundle
    assert vault.require("j1") is bundle

    vault.discard("j1")
    assert vault.get("j1") is None
    vault.discard("j1")  # discarding an absent job is a no-op
