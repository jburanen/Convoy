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

from convoy.errors import ExpertModeError, TransportError, TransportTimeoutError
from convoy.transport.ssh import GaiaExpertSession, InteractiveShell

from .fakes import FakeInteractiveShell


class FakeChannel:
    """A scripted queue of byte chunks, delivered one recv_ready()/recv()
    pair at a time, so InteractiveShell.expect()'s polling loop actually
    loops (rather than being satisfied by a single recv call) when a test
    wants that. Ignores whatever is sent — the response script is fixed in
    advance, independent of what InteractiveShell.send_line/send_secret write."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        close_when_empty: bool = False,
        greet_silently: bool = False,
    ) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self._close_when_empty = close_when_empty
        # Withholds every chunk until something is sent, modelling a device
        # that prints no prompt of its own at login.
        self._greet_silently = greet_silently

    def recv_ready(self) -> bool:
        if self._greet_silently and not self.sent:
            return False
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
    channel = FakeChannel([b"gw01> ", b"Password: ", b"[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    assert session.enter_expert("hunter2", timeout=1.0) is True


def test_enter_expert_fails_with_wrong_password() -> None:
    channel = FakeChannel([b"gw01> ", b"Password: ", b"wrong password\nPassword: "])
    session = GaiaExpertSession(InteractiveShell(channel))
    with pytest.raises(ExpertModeError, match="wrong password"):
        session.enter_expert("hunter2", timeout=1.0)


def test_enter_expert_skips_escalation_when_login_lands_in_expert() -> None:
    """A Spark firewall whose user is configured `bashUser on` drops you
    straight into expert at login. Sending `expert` there asks for a password
    the session does not need, so the greeting decides it (operator-specified
    2026-08-27)."""
    channel = FakeChannel([b"[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    assert session.enter_expert("hunter2", timeout=1.0) is False
    assert channel.sent == []  # nothing sent at all -- not even `expert`


def test_enter_expert_still_escalates_when_the_device_greets_with_silence() -> None:
    """No greeting is not evidence of being elevated: fall back to sending
    `expert`, which is what this did before the greeting read existed."""
    channel = FakeChannel([b"Password: ", b"[Expert@gw01]# "], greet_silently=True)
    session = GaiaExpertSession(InteractiveShell(channel))
    assert session.enter_expert("hunter2", timeout=0.3) is True
    assert channel.sent[0] == b"expert\n"


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


def test_exit_expert_treats_the_device_hanging_up_as_a_clean_exit() -> None:
    """Real SG1800 behaviour (2026-08-27): `exit` from expert ends the whole
    session rather than dropping back to clish -- the device echoes
    `exit\\r\\nlogout\\r\\n` and closes the channel. That was failing
    spark.testcred jobs on teardown, after the login and escalation they set
    out to prove had already succeeded."""
    channel = FakeChannel([b"exit\r\nlogout\r\n"], close_when_empty=True)
    session = GaiaExpertSession(InteractiveShell(channel))
    session.exit_expert(timeout=1.0)  # must not raise
    assert channel.sent == [b"exit\n"]


def test_exit_expert_still_raises_when_the_session_hangs_open() -> None:
    """The narrower failure stays a failure: a channel that never closes and
    never returns a prompt is a stuck session, not a finished one, and must
    not be swallowed along with the hang-up above."""
    channel = FakeChannel([b"...\n"])  # never closes, never prompts
    session = GaiaExpertSession(InteractiveShell(channel))
    with pytest.raises(TransportTimeoutError):
        session.exit_expert(timeout=0.2)


# -- run_expert_command (bash-native commands, real exit status) -----------------


def test_run_expert_command_recovers_exit_status_and_strips_marker() -> None:
    # The device echoes back the exact combined line run_expert_command sent
    # (command + the appended `; echo <marker>:$?`) before its real output.
    channel = FakeChannel(
        [b"df -Pk /; echo __CHKP_ORCH_RC__:$?\nsome output\n__CHKP_ORCH_RC__:0\n[Expert@gw01]# "]
    )
    session = GaiaExpertSession(InteractiveShell(channel))
    result = session.run_expert_command("df -Pk /", timeout=1.0)
    assert result.exit_status == 0
    assert result.stdout == "some output"
    assert result.stderr == ""


def test_run_expert_command_recovers_nonzero_exit_status() -> None:
    channel = FakeChannel([b"false; echo __CHKP_ORCH_RC__:$?\n__CHKP_ORCH_RC__:1\n[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    result = session.run_expert_command("false", timeout=1.0)
    assert result.exit_status == 1


def test_run_expert_command_raises_when_marker_missing() -> None:
    # Simulates output that doesn't carry the sentinel for some reason (e.g.
    # an unexpected prompt) — must fail closed rather than guess a status.
    channel = FakeChannel([b"echo hi; echo __CHKP_ORCH_RC__:$?\nhi\n[Expert@gw01]# "])
    session = GaiaExpertSession(InteractiveShell(channel))
    with pytest.raises(TransportError, match="could not recover an exit status"):
        session.run_expert_command("echo hi", timeout=1.0)


def test_full_expert_conversation() -> None:
    channel = FakeChannel(
        [
            b"gw01> ",
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


# -- the silent expert-password reader (live bug, 2026-08-26) ----------------------
#
# Confirmed against a real R81.x Gaia firewall: its `expert` password reader does
# not act on the newline send_secret() already sent. The password sits unread and
# the escalation hangs to its full timeout with ZERO bytes received -- which is
# what "Disk space check ... timed out ... output so far: ''" was. A further
# newline, as its own write, submits the buffered password normally.
#
# Combining them into one write is NOT an alternative fix: the reader then takes
# the first newline as an empty password and the password itself is echoed in
# CLEARTEXT at the clish prompt, where Gaia logs it as an invalid command.


def test_enter_expert_nudges_a_reader_that_ignores_the_first_newline() -> None:
    shell = FakeInteractiveShell(expert_password="expert-pw", password_needs_nudge=True)
    GaiaExpertSession(shell).enter_expert("expert-pw")

    # the password went out on its own, and the nudge is a SEPARATE empty write
    assert shell.sent == ["expert", "***", ""]


def test_enter_expert_does_not_nudge_when_the_reader_answers_normally() -> None:
    """Spark/Gaia Embedded answers the first newline — it must not receive a
    stray extra line, which would land as a blank command in expert mode."""
    shell = FakeInteractiveShell(expert_password="expert-pw")
    GaiaExpertSession(shell).enter_expert("expert-pw")

    assert shell.sent == ["expert", "***"]


def test_enter_expert_still_reports_a_wrong_password_after_a_nudge() -> None:
    """The nudge must not paper over a genuinely wrong password."""
    shell = FakeInteractiveShell(
        expert_password="expert-pw", wrong_password=True, password_needs_nudge=True
    )
    with pytest.raises(ExpertModeError, match="wrong password"):
        GaiaExpertSession(shell).enter_expert("not-the-password")


def test_enter_expert_never_sends_the_password_and_nudge_in_one_write() -> None:
    """Regression guard for the cleartext-leak shape: the password must be its
    own write, never concatenated with extra terminators."""
    shell = FakeInteractiveShell(expert_password="expert-pw", password_needs_nudge=True)
    GaiaExpertSession(shell).enter_expert("expert-pw")

    secret_writes = [w for w in shell.sent if w == "***"]
    assert len(secret_writes) == 1
    assert "expert-pw" not in shell.sent  # never echoed as a plain command
