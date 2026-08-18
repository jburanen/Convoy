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
    store = Store(tmp_path / "orch.db")
    # credential_sets.environment FKs to environments — the "default" row must exist.
    store.insert_environment("default", credential_storage_enabled=True)
    return store


@pytest.fixture
def creds(store: Store) -> CredentialStore:
    return CredentialStore(store, master_key="correct horse battery staple")


def _put(creds: CredentialStore, name: str = "primary", **kw: str) -> None:
    """Create a set; defaults to an SSH-password set unless overridden."""
    kw.setdefault("ssh_username", "admin")
    kw.setdefault("ssh_password", "s3cret!")
    creds.put_set("default", name, **kw)


def _set_id(store: Store, name: str = "primary") -> str:
    row = store.get_credential_set_by_name("default", name)
    assert row is not None
    return row.id


def test_put_set_and_bundle_roundtrip(creds: CredentialStore, store: Store) -> None:
    creds.put_set(
        "default",
        "primary",
        ssh_username="admin",
        ssh_password="hunter22",
        expert_password="rootpw",
    )
    bundle = creds.get_set_bundle(_set_id(store), "mgmt-01")
    assert bundle[CredentialKind.SSH_PASSWORD].reveal() == "hunter22"
    assert bundle[CredentialKind.SSH_PASSWORD].username == "admin"
    assert bundle[CredentialKind.EXPERT_PASSWORD].reveal() == "rootpw"
    # Expert secret carries no username.
    assert bundle[CredentialKind.EXPERT_PASSWORD].username is None


def test_ciphertext_on_disk_is_not_plaintext(creds: CredentialStore, store: Store) -> None:
    _put(creds, ssh_password="supersecretvalue")
    row = store.get_credential_set_by_name("default", "primary")
    assert row is not None and row.ssh_password_ct is not None
    assert b"supersecretvalue" not in row.ssh_password_ct


def test_secret_never_in_repr(creds: CredentialStore, store: Store) -> None:
    _put(creds, ssh_password="topsecret")
    bundle = creds.get_set_bundle(_set_id(store), "mgmt-01")
    cred = bundle[CredentialKind.SSH_PASSWORD]
    assert "topsecret" not in repr(cred)
    assert "topsecret" not in str(cred)


def test_wrong_master_key_fails_fast(store: Store) -> None:
    CredentialStore(store, master_key="the right key").put_set(
        "default", "primary", ssh_password="pw"
    )
    with pytest.raises(CredentialError, match="master key does not match"):
        CredentialStore(store, master_key="not the right key")


def test_same_key_reopens_fine(store: Store) -> None:
    CredentialStore(store, master_key="the right key").put_set(
        "default", "primary", ssh_password="abc"
    )
    reopened = CredentialStore(store, master_key="the right key")
    bundle = reopened.get_set_bundle(_set_id(store), "mgmt-01")
    assert bundle[CredentialKind.SSH_PASSWORD].reveal() == "abc"


def test_ssh_secret_required(creds: CredentialStore) -> None:
    with pytest.raises(CredentialError, match="SSH password or private key"):
        creds.put_set("default", "noauth", expert_password="only-expert")


def test_update_merges_and_preserves_id(creds: CredentialStore, store: Store) -> None:
    # Bootstrap entry: SSH password only.
    creds.put_set("default", "primary", ssh_username="admin", ssh_password="hunter22")
    original_id = _set_id(store)

    # "Edit" it to add just the API key — no SSH secret re-entered.
    info = creds.put_set("default", "primary", api_key="APIKEY123")

    assert info.has_api is True
    assert _set_id(store) == original_id  # id preserved → server assignments survive
    bundle = creds.get_set_bundle(original_id, "mgmt-01")
    # The SSH password is kept (merge), and the API key was added.
    assert bundle[CredentialKind.SSH_PASSWORD].reveal() == "hunter22"
    assert bundle[CredentialKind.SSH_PASSWORD].username == "admin"
    assert bundle[CredentialKind.API_KEY].reveal() == "APIKEY123"


def test_update_can_replace_a_secret(creds: CredentialStore, store: Store) -> None:
    creds.put_set("default", "primary", ssh_username="admin", ssh_password="old-pw")
    creds.put_set("default", "primary", ssh_password="new-pw")  # username kept
    bundle = creds.get_set_bundle(_set_id(store), "mgmt-01")
    assert bundle[CredentialKind.SSH_PASSWORD].reveal() == "new-pw"
    assert bundle[CredentialKind.SSH_PASSWORD].username == "admin"


def test_set_default_is_exclusive_per_environment(creds: CredentialStore) -> None:
    _put(creds, "a")
    _put(creds, "b")
    assert creds.default_set_name("default") is None

    assert creds.set_default("default", "a") is True
    assert creds.default_set_name("default") == "a"
    assert [i.name for i in creds.list_sets("default") if i.is_default] == ["a"]

    # Switching the default clears the previous one (at most one per environment).
    assert creds.set_default("default", "b") is True
    assert creds.default_set_name("default") == "b"
    assert [i.name for i in creds.list_sets("default") if i.is_default] == ["b"]

    assert creds.set_default("default", "ghost") is False  # unknown set


def test_editing_a_set_preserves_its_default_flag(creds: CredentialStore) -> None:
    _put(creds, "primary")
    creds.set_default("default", "primary")
    creds.put_set("default", "primary", api_key="APIKEY")  # edit to add an API key
    assert creds.default_set_name("default") == "primary"  # still the default


def test_password_xor_private_key(creds: CredentialStore) -> None:
    with pytest.raises(CredentialError, match="not both"):
        creds.put_set("default", "both", ssh_password="pw", ssh_private_key="key")


def test_private_key_set_bundle(creds: CredentialStore, store: Store) -> None:
    creds.put_set("default", "keyset", ssh_username="admin", ssh_private_key="KEYDATA")
    bundle = creds.get_set_bundle(_set_id(store, "keyset"), "mgmt-01")
    assert set(bundle) == {CredentialKind.SSH_PRIVATE_KEY}
    assert bundle[CredentialKind.SSH_PRIVATE_KEY].reveal() == "KEYDATA"


def test_list_sets_is_secret_free(creds: CredentialStore) -> None:
    creds.put_set(
        "default", "primary", ssh_username="admin", ssh_password="classified", api_key="k"
    )
    infos = creds.list_sets("default")
    assert len(infos) == 1
    info = infos[0]
    assert info.name == "primary"
    assert info.ssh_username == "admin"
    assert info.ssh_auth == "password"
    assert info.has_api is True
    assert info.has_expert is False
    assert "classified" not in repr(infos)


def test_delete_set(creds: CredentialStore) -> None:
    _put(creds)
    assert creds.delete_set("default", "primary") is True
    assert creds.delete_set("default", "primary") is False


def test_get_bundle_missing_set_raises(creds: CredentialStore) -> None:
    with pytest.raises(CredentialError, match="not found"):
        creds.get_set_bundle("no-such-id", "mgmt-01")


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
