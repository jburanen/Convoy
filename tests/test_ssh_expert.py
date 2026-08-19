"""Unit tests for the expert-mode SSH primitives (transport/ssh.py):
InteractiveShell's read/expect polling loop, and GaiaExpertSession's
Gaia-specific escalation logic layered on top of it. Both are exercised
against a minimal duck-typed fake channel (recv_ready/recv/send/close) —
not a real pty — so these confirm the *logic* (polling, pattern matching,
error paths) is correct; they cannot confirm the actual prompt text matches
real Spark hardware, which is unvalidated (see
.claude/memory/spark-firmware-patching.md)."""

from __future__ import annotations

import pytest

from chkp_cpuse_orch.errors import ExpertModeError, TransportError
from chkp_cpuse_orch.transport.ssh import GaiaExpertSession, InteractiveShell


class FakeChannel:
    """A scripted queue of byte chunks, delivered one recv_ready()/recv()
    pair at a time, so InteractiveShell.expect()'s polling loop actually
    loops (rather than being satisfied by a single recv call) when a test
    wants that. Ignores whatever is sent — the response script is fixed in
    advance, independent of what InteractiveShell.send_line/send_secret write."""

    def __init__(self, chunks: list[bytes], *, close_when_empty: bool = False) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self._close_when_empty = close_when_empty

    def recv_ready(self) -> bool:
        return bool(self._chunks)

    def recv(self, n: int) -> bytes:
        chunk = self._chunks.pop(0)
        if not self._chunks and self._close_when_empty:
            self.closed = True
        return chunk

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        return len(data)

    def close(self) -> None:
        self.closed = True


# -- InteractiveShell.expect() ------------------------------------------------------


def test_expect_matches_immediately() -> None:
    shell = InteractiveShell(FakeChannel([b"login as: admin\nPassword: "]))
    out = shell.expect(r"[Pp]assword\s*:\s*$", timeout=1.0)
    assert "Password: " in out


def test_expect_matches_after_multiple_reads() -> None:
    shell = InteractiveShell(FakeChannel([b"host", b"name", b"> "]))
    out = shell.expect(r">\s*$", timeout=1.0)
    assert out == "hostname> "


def test_expect_times_out_with_captured_output() -> None:
    shell = InteractiveShell(FakeChannel([b"still working...\n"]), read_timeout=0.2)
    with pytest.raises(TransportError, match="timed out"):
        shell.expect(r"NEVER MATCHES", timeout=0.2)


def test_expect_raises_when_channel_closes_before_match() -> None:
    shell = InteractiveShell(FakeChannel([b"partial output"], close_when_empty=True))
    with pytest.raises(TransportError, match="closed"):
        shell.expect(r"NEVER MATCHES", timeout=1.0)


def test_send_line_and_send_secret_write_to_channel() -> None:
    channel = FakeChannel([b"ignored"])
    shell = InteractiveShell(channel)
    shell.send_line("expert")
    shell.send_secret("hunter2")
    assert channel.sent == [b"expert\n", b"hunter2\n"]


# -- GaiaExpertSession ----------------------------------------------------------------


def test_enter_expert_succeeds_with_correct_password() -> None:
    channel = FakeChannel([b"Password: ", b"[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    session.enter_expert("hunter2", timeout=1.0)  # must not raise


def test_enter_expert_fails_with_wrong_password() -> None:
    channel = FakeChannel([b"Password: ", b"wrong password\nPassword: "])
    session = GaiaExpertSession(InteractiveShell(channel))
    with pytest.raises(ExpertModeError, match="wrong password"):
        session.enter_expert("hunter2", timeout=1.0)


def test_run_expert_strips_echo_and_prompt() -> None:
    channel = FakeChannel([b"bashUser on\nDone.\n[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    output = session.run_expert("bashUser on", timeout=1.0)
    assert output == "Done."


def test_exit_expert_returns_to_login_prompt() -> None:
    channel = FakeChannel([b"gw01> "])
    session = GaiaExpertSession(InteractiveShell(channel))
    session.exit_expert(timeout=1.0)  # must not raise
    assert channel.sent == [b"exit\n"]


def test_full_expert_conversation() -> None:
    channel = FakeChannel(
        [
            b"Password: ",
            b"[Expert@gw01]# ",
            b"bashUser on\nDone.\n[Expert@gw01]# ",
            b"gw01> ",
        ]
    )
    session = GaiaExpertSession(InteractiveShell(channel))
    session.enter_expert("hunter2", timeout=1.0)
    output = session.run_expert("bashUser on", timeout=1.0)
    session.exit_expert(timeout=1.0)
    assert output == "Done."
    assert channel.sent[0] == b"expert\n"
    assert channel.sent[1] == b"hunter2\n"
    assert channel.sent[-1] == b"exit\n"
