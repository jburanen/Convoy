"""Unit tests for GaiaSession (transport/ssh.py): the clish-login-plus-on-
demand-expert posture's central piece. Real SSHClient/paramiko are swapped
out for a scripted fake (FakeSSHClient) via monkeypatching the module-level
name GaiaSession._new_client() constructs — these confirm the *logic* (shell
detection, lazy elevation, the file-transfer shell-toggle maneuver) is
correct; they cannot confirm the shell-detection probe or the `set user`
commands work against real Gaia, which is unvalidated — see
.claude/memory/gaia-shell-posture.md."""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

import pytest

from chkp_cpuse_orch.errors import CredentialError, GaiaShellRestoreError, TransportError
from chkp_cpuse_orch.inventory import Host, Role
from chkp_cpuse_orch.transport import ssh as ssh_module
from chkp_cpuse_orch.transport.ssh import (
    CommandResult,
    GaiaSession,
    GaiaShell,
    require_ok,
)


def _host() -> Host:
    return Host(name="mgmt-01", address="192.0.2.10", role=Role.MANAGEMENT)


class FakeInteractiveShell:
    """Enough of InteractiveShell for GaiaExpertSession to drive a scripted
    expert-mode conversation, without a real pty."""

    def __init__(self) -> None:
        self.closed = False
        self._last = ""

    @property
    def host_name(self) -> str:
        return "mgmt-01"

    def send_line(self, text: str) -> None:
        self._last = text

    def send_secret(self, text: str) -> None:
        self._last = "***"

    def expect(self, pattern: str, *, timeout: float | None = None) -> str:
        if self._last == "expert":
            return "Password: "
        if self._last == "***":
            return "[Expert@gw01]# "
        if "echo __CHKP_ORCH_RC__:$?" in self._last:
            # run_expert_command's exit-status sentinel — echo the combined
            # line back (as a real terminal would) then the marker at rc 0.
            return f"{self._last}\nDone.\n__CHKP_ORCH_RC__:0\n[Expert@gw01]# "
        return f"{self._last}\nDone.\n[Expert@gw01]# "

    def close(self) -> None:
        self.closed = True


class FakeSSHClient:
    """Stands in for SSHClient — GaiaSession._new_client() constructs one of
    these per (re)connect. Class-level ``instances`` records every one
    created, so a test can inspect the sequence of connects the transfer
    maneuver performs."""

    instances: ClassVar[list[FakeSSHClient]] = []

    def __init__(
        self,
        host: Host,
        *,
        username: str | None = None,
        password: str | None = None,
        private_key: str | None = None,
        key_passphrase: str | None = None,
        connect_timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.connected = False
        self.closed = False
        self.commands: list[str] = []
        self.puts: list[tuple[str, str]] = []
        # Class attribute default; per-instance so tests can script per-fake.
        self.responses: dict[str, CommandResult | Exception] = {}
        self.put_result: int | Exception = 0
        FakeSSHClient.instances.append(self)

    def connect(self) -> None:
        self.connected = True

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        for key, scripted in self.responses.items():
            if key in command:
                # A list is a sequence consumed one call at a time, holding on
                # the last entry — lets a test script "fails, then succeeds"
                # (e.g. a config-lock conflict cleared by an override). Same
                # shape as test_gateway_bootstrap.py's task_sequence.
                if isinstance(scripted, list):
                    scripted = scripted.pop(0) if len(scripted) > 1 else scripted[0]
                if isinstance(scripted, Exception):
                    raise scripted
                return scripted
        return CommandResult(command=command, exit_status=0, stdout="", stderr="")

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        self.puts.append((local_path, remote_path))
        if isinstance(self.put_result, Exception):
            raise self.put_result
        return self.put_result

    def open_interactive_shell(self, *, width: int = 200, height: int = 50) -> FakeInteractiveShell:
        return FakeInteractiveShell()

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _patch_ssh_client(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSSHClient.instances = []
    monkeypatch.setattr(ssh_module, "SSHClient", FakeSSHClient)


def _session(**kw: object) -> GaiaSession:
    return GaiaSession(
        _host(),
        username="admin",
        password="pw",
        private_key=None,
        expert_password=kw.pop("expert_password", "expert-pw"),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )


# -- shell detection ---------------------------------------------------------------


def test_detects_clish_when_echo_probe_fails() -> None:
    # A clish-default account rejects `echo` as an unrecognized clish verb —
    # simulated here as a non-zero exit with no echoed sentinel.
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")
    assert session.shell is GaiaShell.CLISH


def test_detects_expert_when_echo_probe_succeeds() -> None:
    # An already-bash account runs `echo` directly and gets the sentinel back.
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(
        command="echo CHKP_ORCH_SHELL_PROBE_OK",
        exit_status=0,
        stdout="CHKP_ORCH_SHELL_PROBE_OK\n",
        stderr="",
    )
    assert session.shell is GaiaShell.EXPERT


def test_shell_detection_is_cached_not_reprobed() -> None:
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(
        command="echo", exit_status=0, stdout="CHKP_ORCH_SHELL_PROBE_OK", stderr=""
    )
    assert session.shell is GaiaShell.EXPERT
    assert session.shell is GaiaShell.EXPERT
    assert sum(1 for c in client.commands if c.startswith("echo")) == 1


# -- run() / run_bash() dispatch ----------------------------------------------------


def test_run_is_a_bare_passthrough_regardless_of_shell() -> None:
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")
    session.run("show installer packages all")
    assert "show installer packages all" in client.commands


def test_run_bash_passthrough_when_already_expert() -> None:
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(
        command="echo", exit_status=0, stdout="CHKP_ORCH_SHELL_PROBE_OK", stderr=""
    )
    result = session.run_bash("df -Pk /")
    assert result.ok
    assert "df -Pk /" in client.commands


def test_run_bash_elevates_once_then_reuses_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")

    calls: list[str] = []
    real_enter_expert = ssh_module.GaiaExpertSession.enter_expert

    def _tracking_enter_expert(self: object, password: str, **kw: object) -> None:
        calls.append(password)
        real_enter_expert(self, password, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(ssh_module.GaiaExpertSession, "enter_expert", _tracking_enter_expert)

    session.run_bash("df -Pk /")
    session.run_bash("sha1sum /var/log/upload/x")
    assert calls == ["expert-pw"]  # elevated exactly once, reused for the second call


def test_run_bash_requires_an_expert_password_when_clish() -> None:
    session = _session(expert_password=None)
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")
    with pytest.raises(CredentialError, match="expert-mode password is required"):
        session.run_bash("df -Pk /")


# -- put(): the transfer shell-toggle maneuver --------------------------------------


def test_put_passthrough_when_already_expert() -> None:
    session = _session()
    client = FakeSSHClient.instances[0]
    client.responses["echo"] = CommandResult(
        command="echo", exit_status=0, stdout="CHKP_ORCH_SHELL_PROBE_OK", stderr=""
    )
    client.put_result = 123
    size = session.put("local.tgz", "/var/log/upload/local.tgz")
    assert size == 123
    assert client.puts == [("local.tgz", "/var/log/upload/local.tgz")]
    # No shell toggle for an already-bash account.
    assert not any("shell /bin/bash" in c for c in client.commands)


def test_put_toggles_shell_transfers_then_restores_when_clish() -> None:
    session = _session()
    first = FakeSSHClient.instances[0]
    first.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")

    size = session.put("local.tgz", "/var/log/upload/local.tgz")

    # Three connections: the original (clish, toggles shell) + a fresh one for
    # the transfer (now bash, restores the shell too) + the session's own
    # resumed primary connection afterward.
    assert len(FakeSSHClient.instances) == 3
    first, transfer, resumed = FakeSSHClient.instances
    assert any("shell /bin/bash" in c for c in first.commands)
    assert first.closed is True
    assert transfer.puts == [("local.tgz", "/var/log/upload/local.tgz")]
    assert any("clish -c" in c and "shell /etc/cli.sh" in c for c in transfer.commands)
    assert any("clish -c" in c and "save config" in c for c in transfer.commands)
    assert transfer.closed is True
    assert resumed.closed is False  # left open as the session's live connection
    assert size == 0  # FakeSSHClient's default put_result


def test_put_restores_shell_even_when_transfer_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    first = FakeSSHClient.instances[0]
    first.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")

    def _failing_put(
        self: FakeSSHClient,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        raise TransportError("disk full")

    monkeypatch.setattr(FakeSSHClient, "put", _failing_put)

    with pytest.raises(TransportError, match="disk full"):
        session.put("local.tgz", "/var/log/upload/local.tgz")

    # The restore commands must still have run on the transfer connection
    # despite the transfer itself failing.
    _first, transfer, _resumed = FakeSSHClient.instances
    assert any("shell /etc/cli.sh" in c for c in transfer.commands)


def test_put_raises_gaia_shell_restore_error_if_restore_itself_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session()
    first = FakeSSHClient.instances[0]
    first.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")

    # Patch FakeSSHClient.run globally (via the class) so the *second*
    # connection (the transfer one) fails specifically on the restore command.
    original_run = FakeSSHClient.run

    def _run_failing_restore(
        self: FakeSSHClient, command: str, *, timeout: float | None = None
    ) -> CommandResult:
        if "shell /etc/cli.sh" in command:
            return CommandResult(command=command, exit_status=1, stdout="", stderr="denied")
        return original_run(self, command, timeout=timeout)

    monkeypatch.setattr(FakeSSHClient, "run", _run_failing_restore)

    with pytest.raises(GaiaShellRestoreError, match="left on a standing bash shell"):
        session.put("local.tgz", "/var/log/upload/local.tgz")


# -- clish config lock (live bug, 2026-08-26) --------------------------------------
#
# Elevating to expert takes Gaia's config-database lock, so the very next clish
# `set` in the same session is refused -- which is what broke the transfer
# shell-toggle on a real gateway. Gaia reports it on STDOUT (CLINFR0771 /
# CLINFR0519) with rc=1 and an EMPTY stderr, which is why the job error was a
# bare "command failed (rc=1)" with no reason attached.

_LOCK_STDOUT = (
    "CLINFR0771  Config lock is owned by admin. Use the command "
    "'lock database override' to acquire the lock."
    + chr(10)
    + "CLINFR0519  Configuration lock present. Can not execute this command."
)


def _lock_then_ok(command: str) -> list[CommandResult]:
    return [
        CommandResult(command=command, exit_status=1, stdout=_LOCK_STDOUT, stderr=""),
        CommandResult(command=command, exit_status=0, stdout="", stderr=""),
    ]


def test_put_breaks_the_config_lock_when_the_shell_toggle_is_refused() -> None:
    session = _session()
    first = FakeSSHClient.instances[0]
    first.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")
    first.responses["shell /bin/bash"] = _lock_then_ok("set user svc shell /bin/bash")

    session.put("local.tgz", "/var/log/upload/local.tgz")

    # Positions, not values: both toggle commands are the same string, so
    # .index() would just find the first one twice.
    at = [i for i, c in enumerate(first.commands) if "shell /bin/bash" in c]
    assert len(at) == 2  # refused, then retried
    override_at = first.commands.index("lock database override")
    assert at[0] < override_at < at[1]  # override sits between the two attempts


def test_no_lock_override_when_nothing_is_blocking() -> None:
    """The override forcibly evicts whoever holds the lock — an admin mid-change
    in SmartConsole or clish — so it must never fire pre-emptively."""
    session = _session()
    first = FakeSSHClient.instances[0]
    first.responses["echo"] = CommandResult(command="echo", exit_status=1, stdout="", stderr="")

    session.put("local.tgz", "/var/log/upload/local.tgz")

    every = [c for inst in FakeSSHClient.instances for c in inst.commands]
    assert not any("lock database override" in c for c in every)


def test_require_ok_reports_clish_errors_from_stdout() -> None:
    """clish writes errors to stdout; reporting stderr alone turned every clish
    failure into a bare rc with no reason."""
    with pytest.raises(TransportError, match="CLINFR0771"):
        require_ok(
            CommandResult(
                command="set user x shell /bin/bash", exit_status=1, stdout=_LOCK_STDOUT, stderr=""
            )
        )
