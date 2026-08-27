"""Tests for services/common.py's default_client_factory — specifically the
SSH username resolution fix: the assigned credential's own username (from a
stored credential set's ssh_username, or an inline per-job credential) must
win over the Host's own (possibly stale/diverged) ssh_user field. See
.claude/memory/ssh-username-source-of-truth.md for the bug this closes.
"""

from __future__ import annotations

import paramiko
import pytest
from pydantic import SecretStr

from convoy.credentials import Credential, CredentialKind
from convoy.inventory import Host, Role
from convoy.services.common import default_client_factory


def _patch_paramiko_connect(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Same interception pattern as test_transport_ssh.py — no real network
    activity, just captures what SSHClient.connect() would send to paramiko."""
    captured: dict[str, object] = {}

    def fake_connect(self: paramiko.SSHClient, hostname: str, **kwargs: object) -> None:
        captured["hostname"] = hostname
        captured.update(kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", fake_connect)
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self: None)
    monkeypatch.setattr(
        paramiko.SSHClient, "set_missing_host_key_policy", lambda self, policy: None
    )
    return captured


def _host(ssh_user: str = "admin") -> Host:
    return Host(
        name="lab02-1550", address="192.0.2.21", role=Role.SPARK_FIREWALL, ssh_user=ssh_user
    )


def _password_cred(username: str | None) -> Credential:
    return Credential(
        host="lab02-1550",
        kind=CredentialKind.SSH_PASSWORD,
        username=username,
        secret=SecretStr("s3cret"),
    )


def test_credential_username_wins_over_diverged_host_ssh_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The exact bug: Host.ssh_user says "svc-patchmgr", the assigned
    # credential set says "admin" — the credential set must win.
    captured = _patch_paramiko_connect(monkeypatch)
    host = _host(ssh_user="svc-patchmgr")
    creds = {CredentialKind.SSH_PASSWORD: _password_cred("admin")}
    default_client_factory(host, creds)
    assert captured["username"] == "admin"


def test_falls_back_to_host_ssh_user_when_credential_has_no_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Inline per-job credentials (storage-disabled environments) carry no
    # username today — must still fall back to host.ssh_user, unchanged
    # behavior from before this fix.
    captured = _patch_paramiko_connect(monkeypatch)
    host = _host(ssh_user="admin")
    creds = {CredentialKind.SSH_PASSWORD: _password_cred(None)}
    default_client_factory(host, creds)
    assert captured["username"] == "admin"


def test_falls_back_to_host_ssh_user_with_no_credentials_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _patch_paramiko_connect(monkeypatch)
    host = _host(ssh_user="admin")
    default_client_factory(host, {})
    assert captured["username"] == "admin"


def test_private_key_credential_username_also_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    captured = _patch_paramiko_connect(monkeypatch)
    key = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    key.write_private_key(buf)
    host = _host(ssh_user="stale-admin")
    creds = {
        CredentialKind.SSH_PRIVATE_KEY: Credential(
            host="lab02-1550",
            kind=CredentialKind.SSH_PRIVATE_KEY,
            username="svc-patchmgr",
            secret=SecretStr(buf.getvalue()),
        )
    }
    default_client_factory(host, creds)
    assert captured["username"] == "svc-patchmgr"
