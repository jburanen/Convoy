from __future__ import annotations

import io
from pathlib import Path

import paramiko
import pytest

from chkp_cpuse_orch.errors import TransportError
from chkp_cpuse_orch.inventory import Host, Role
from chkp_cpuse_orch.transport.ssh import (
    CommandResult,
    SSHClient,
    _fingerprint,
    _host_key_id,
    _PinningPolicy,
    forget_host_key,
    known_hosts_path,
    load_private_key,
    require_ok,
    scrub_transcript,
    set_known_hosts_path,
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


# -- put_scp — classic-SCP upload (Spark's SSH server doesn't speak SFTP) --------


class _FakeScpChannel:
    """Stands in for the (stdin, stdout) pair exec_command("scp -t ...")
    returns: acks is the sequence of single-byte acks put_scp() reads (one
    per control line/data phase), exit_status what the channel reports once
    stdin is closed. Records everything written to stdin for assertions."""

    def __init__(self, acks: list[bytes], exit_status: int = 0) -> None:
        self._acks = list(acks)
        self.exit_status = exit_status
        self.written = bytearray()
        self.closed = False

        class _Channel:
            def recv_exit_status(_self) -> int:
                return self.exit_status

        self.channel = _Channel()

    # -- stdin side --
    def write(self, data: bytes) -> None:
        self.written.extend(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    # -- stdout side --
    def read(self, _n: int) -> bytes:
        return self._acks.pop(0) if self._acks else b""

    def readline(self) -> bytes:
        return b"permission denied\n"


def _fake_exec_command(channel: _FakeScpChannel):
    def exec_command(self: paramiko.SSHClient, command: str):
        return channel, channel, io.BytesIO(b"")

    return exec_command


def test_put_scp_happy_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_paramiko_connect(monkeypatch)
    channel = _FakeScpChannel(acks=[b"\x00", b"\x00", b"\x00"])
    monkeypatch.setattr(paramiko.SSHClient, "exec_command", _fake_exec_command(channel))
    local = tmp_path / "spark_firmware.img"
    local.write_bytes(b"fake firmware bytes")

    client = SSHClient(_host(), password="pw")
    client.connect()
    progressed: list[tuple[int, int]] = []
    size = client.put_scp(
        str(local),
        "/storage/spark_firmware.img",
        progress=lambda done, total: progressed.append((done, total)),
    )

    assert size == local.stat().st_size
    assert channel.written.startswith(b"C0644 19 spark_firmware.img\n")
    assert channel.written.endswith(b"fake firmware bytes\x00")
    assert channel.closed is True
    assert progressed == [(19, 19)]


def test_put_scp_raises_on_rejection_ack(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_paramiko_connect(monkeypatch)
    channel = _FakeScpChannel(acks=[b"\x01"])  # rejected before the control line is even sent
    monkeypatch.setattr(paramiko.SSHClient, "exec_command", _fake_exec_command(channel))
    local = tmp_path / "spark_firmware.img"
    local.write_bytes(b"x")

    client = SSHClient(_host(), password="pw")
    client.connect()
    with pytest.raises(TransportError, match="permission denied"):
        client.put_scp(str(local), "/storage/spark_firmware.img")


def test_put_scp_raises_when_channel_closes_before_ack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_paramiko_connect(monkeypatch)
    channel = _FakeScpChannel(acks=[])  # read(1) immediately returns b""
    monkeypatch.setattr(paramiko.SSHClient, "exec_command", _fake_exec_command(channel))
    local = tmp_path / "spark_firmware.img"
    local.write_bytes(b"x")

    client = SSHClient(_host(), password="pw")
    client.connect()
    with pytest.raises(TransportError, match="connection closed"):
        client.put_scp(str(local), "/storage/spark_firmware.img")


def test_put_scp_raises_on_nonzero_exit_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_paramiko_connect(monkeypatch)
    channel = _FakeScpChannel(acks=[b"\x00", b"\x00", b"\x00"], exit_status=1)
    monkeypatch.setattr(paramiko.SSHClient, "exec_command", _fake_exec_command(channel))
    local = tmp_path / "spark_firmware.img"
    local.write_bytes(b"x")

    client = SSHClient(_host(), password="pw")
    client.connect()
    with pytest.raises(TransportError, match="scp exited 1"):
        client.put_scp(str(local), "/storage/spark_firmware.img")


# -- SSH host-key pinning (H1) -----------------------------------------------------
#
# Every connection carries a root-equivalent Gaia password (and, for patch work,
# the expert password) to the far end. Before this, keys were auto-accepted on
# EVERY connection with nothing persisted, so an on-path attacker presenting any
# key collected both. See transport/ssh.py.


@pytest.fixture
def known_hosts(tmp_path: Path):
    """Point pinning at a temp file for the duration of one test."""
    path = tmp_path / "state" / "known_hosts"
    set_known_hosts_path(path)
    yield path
    set_known_hosts_path(None)


def _load(path: Path) -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    if path.is_file():
        keys.load(str(path))
    return keys


def _pin(path: Path, hostname: str, key: paramiko.PKey) -> None:
    client = paramiko.SSHClient()
    if path.is_file():
        client.load_host_keys(str(path))
    _PinningPolicy().missing_host_key(client, hostname, key)


def test_pinning_can_be_disabled(known_hosts: Path) -> None:
    """None disables pinning entirely — the CLI and unit tests, which never
    talk to real gear. (Deliberately not asserting the *initial* global value:
    create_app sets it process-wide, so any test that built an app first would
    make that order-dependent.)"""
    assert known_hosts_path() == known_hosts
    set_known_hosts_path(None)
    assert known_hosts_path() is None
    # and with pinning off, the policy is a no-op rather than an error
    _PinningPolicy().missing_host_key(
        paramiko.SSHClient(), "192.0.2.10", paramiko.RSAKey.generate(2048)
    )


def test_first_contact_pins_and_persists(known_hosts: Path) -> None:
    key = paramiko.RSAKey.generate(2048)
    _pin(known_hosts, "192.0.2.10", key)

    assert known_hosts.is_file()  # parent dirs created too
    assert "192.0.2.10" in _load(known_hosts)


def test_concurrent_first_contacts_do_not_lose_a_pin(known_hosts: Path) -> None:
    """paramiko's own AutoAddPolicy rewrites the whole file from its in-memory
    copy, so two hosts pinning at once can drop one — and a dropped pin silently
    re-TOFUs, which is the exact guarantee being made here."""
    a, b = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)

    stale = paramiko.SSHClient()  # loaded BEFORE the other pin lands
    _pin(known_hosts, "192.0.2.10", a)
    _PinningPolicy().missing_host_key(stale, "192.0.2.11", b)

    keys = _load(known_hosts)
    assert "192.0.2.10" in keys and "192.0.2.11" in keys


def test_forget_host_key_drops_exactly_one_host(known_hosts: Path) -> None:
    a, b = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    _pin(known_hosts, "192.0.2.10", a)
    _pin(known_hosts, "192.0.2.11", b)

    host = Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)
    assert forget_host_key(host) is True

    keys = _load(known_hosts)
    assert "192.0.2.10" not in keys
    assert "192.0.2.11" in keys  # never clears the whole file


def test_forget_host_key_is_idempotent(known_hosts: Path) -> None:
    host = Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)
    assert forget_host_key(host) is False  # nothing pinned yet
    _pin(known_hosts, "192.0.2.10", paramiko.RSAKey.generate(2048))
    assert forget_host_key(host) is True
    assert forget_host_key(host) is False


def test_forget_host_key_is_a_no_op_when_pinning_is_disabled() -> None:
    host = Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)
    assert forget_host_key(host) is False


def test_non_default_port_uses_bracketed_known_hosts_entry() -> None:
    """OpenSSH/paramiko name non-22 entries [address]:port — getting this wrong
    would silently pin under a key nothing ever looks up again."""
    host = Host(name="fw", address="192.0.2.12", role=Role.GATEWAY, ssh_port=2222)
    assert _host_key_id(host) == "[192.0.2.12]:2222"
    assert _host_key_id(Host(name="fw", address="192.0.2.12", role=Role.GATEWAY)) == "192.0.2.12"


def test_fingerprint_is_openssh_shaped() -> None:
    fp = _fingerprint(paramiko.RSAKey.generate(2048))
    assert fp.startswith("ssh-rsa SHA256:")
    assert not fp.endswith("=")  # unpadded, like ssh-keygen prints it
    assert _fingerprint(None) == "unknown"


# -- pty transcripts must never carry secrets into an error (H6) -------------------
#
# A transcript embedded in an exception reaches job.error, job_events, the
# flat-file archive AND the browser (via _map_error's str(exc) passthrough).
# These sessions type the expert password into that pty and read `add api-key`
# responses back out of it.


def test_scrub_transcript_redacts_what_follows_a_password_prompt() -> None:
    raw = "expert" + chr(13) + chr(10) + "Enter expert password:hunter2" + chr(13) + chr(10)
    out = scrub_transcript(raw)
    assert "hunter2" not in out
    assert "Enter expert password:" in out  # shape kept, so the log is still readable


def test_scrub_transcript_redacts_inline_secret_values() -> None:
    for raw, secret in (
        ("api-key: aBc123XYZ", "aBc123XYZ"),
        ("password-hash $6$salt$hash", "$6$salt$hash"),
        ("sid=deadbeefcafe", "deadbeefcafe"),
    ):
        assert secret not in scrub_transcript(raw), raw


def test_scrub_transcript_caps_length() -> None:
    out = scrub_transcript("x" * 20000)
    assert len(out) < 5000
    assert "more]" in out


def test_scrub_transcript_leaves_ordinary_output_alone() -> None:
    raw = "Filesystem 1024-blocks Used Available" + chr(10) + "/dev/sda1 100 20 80"
    assert scrub_transcript(raw) == raw
