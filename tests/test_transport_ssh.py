from __future__ import annotations

import io

import paramiko
import pytest

from chkp_cpuse_orch.errors import TransportError
from chkp_cpuse_orch.inventory import Host, Role
from chkp_cpuse_orch.transport.ssh import (
    CommandResult,
    SSHClient,
    load_private_key,
    require_ok,
)


def _host() -> Host:
    return Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)


def test_load_private_key_roundtrip() -> None:
    # Generate a key, serialize it to text (as the credential store would hold
    # it), and load it back through the material loader.
    generated = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    generated.write_private_key(buf)
    loaded = load_private_key(buf.getvalue())
    assert loaded.get_fingerprint() == generated.get_fingerprint()


def test_load_private_key_rejects_garbage() -> None:
    with pytest.raises(TransportError, match="unsupported or corrupt"):
        load_private_key("not a key at all")


def test_run_before_connect_fails_closed() -> None:
    client = SSHClient(_host(), password="pw")
    with pytest.raises(TransportError, match="not connected"):
        client.run("show version all")
    with pytest.raises(TransportError, match="not connected"):
        client.put("local.tgz", "/var/log/upload/local.tgz")


def test_connect_failure_wrapped_as_transport_error() -> None:
    # RFC 5737 TEST-NET address with a tiny timeout — must fail fast and typed.
    host = Host(name="unreachable", address="192.0.2.1", role=Role.MANAGEMENT)
    client = SSHClient(host, password="pw", connect_timeout=0.05)
    with pytest.raises(TransportError, match="SSH connect to unreachable"):
        client.connect()


def _patch_paramiko_connect(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Intercepts the underlying paramiko connect() call (no real network
    activity) and returns the dict its kwargs land in — used to verify which
    username SSHClient actually sends, without needing a live host."""
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


def test_connect_uses_username_override_when_given(monkeypatch: pytest.MonkeyPatch) -> None:
    # The override must win even when it differs from host.ssh_user — this is
    # the primitive the credential-set-username fix (services/common.py's
    # default_client_factory) relies on. See
    # .claude/memory/ssh-username-source-of-truth.md.
    captured = _patch_paramiko_connect(monkeypatch)
    host = Host(name="fw", address="192.0.2.20", role=Role.GATEWAY, ssh_user="stale-admin")
    SSHClient(host, username="svc-patchmgr", password="pw").connect()
    assert captured["username"] == "svc-patchmgr"


def test_connect_falls_back_to_host_ssh_user_without_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _patch_paramiko_connect(monkeypatch)
    host = Host(name="fw", address="192.0.2.20", role=Role.GATEWAY, ssh_user="admin")
    SSHClient(host, password="pw").connect()
    assert captured["username"] == "admin"


def test_require_ok_passes_and_fails() -> None:
    good = CommandResult(command="x", exit_status=0, stdout="", stderr="")
    assert require_ok(good) is good
    bad = CommandResult(command="x", exit_status=2, stdout="", stderr="denied")
    with pytest.raises(TransportError, match="rc=2"):
        require_ok(bad)
