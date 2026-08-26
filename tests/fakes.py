"""Shared test doubles for SSH-touching code paths."""

from __future__ import annotations

import os
from collections.abc import Callable

from chkp_cpuse_orch.errors import TransportError, TransportTimeoutError
from chkp_cpuse_orch.transport.ssh import CommandResult, GaiaShell

# Canned CPUSE output used across tests: one imported, one installed package.
SHOW_PACKAGES_ALL = """\
Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz      Imported
Check_Point_R81_10_JHF_T45.tgz                            Installed
"""

DA_BUILD = "Build 2417"

# A response can be scripted as:
#   "text"            → rc 0, that stdout
#   (rc, "text")      → explicit rc + stdout
#   [resp, resp, ...] → consumed in order; the last one repeats
Resp = str | tuple[int, str]


class FakeTransport:
    """Satisfies services.common.Transport (and, via open_interactive_shell,
    services.spark_patching.ExpertCapableTransport). Replies come from
    ``responses``: the first key found as a substring of the command wins."""

    def __init__(
        self,
        responses: dict[str, Resp | list[Resp]] | None = None,
        fail_rc: int = 0,
        *,
        shell: GaiaShell = GaiaShell.EXPERT,
        expert_password: str = "expert-pw",
        expert_wrong_password: bool = False,
        expert_command_outputs: dict[str, str] | None = None,
        expert_drop_on: str | None = None,
        expert_timeout_on: str | None = None,
        expert_reboot_closes: bool = True,
    ) -> None:
        self.responses = responses or {}
        self.fail_rc = fail_rc  # set non-zero to make every command fail
        # Detected shell — defaults to EXPERT (today's confirmed-working
        # behavior, unchanged) so existing fixtures don't need updating just
        # to keep passing; tests exercising GaiaSession's own detection/
        # elevation logic live against the real class, not this fake.
        self.shell = shell
        self.commands: list[str] = []
        self.bash_commands: list[str] = []
        self.puts: list[tuple[str, str]] = []
        self.closed = False
        # Override to fake a bad upload (e.g. lambda local: 0 for a size mismatch).
        self.put_size: Callable[[str], int] = lambda local: os.path.getsize(local)
        # -- expert-mode (Spark) scripting — see FakeInteractiveShell below --
        self.expert_password = expert_password
        self.expert_wrong_password = expert_wrong_password
        self.expert_command_outputs = expert_command_outputs or {}
        # Substring of a run_expert() command that should raise TransportError
        # from expect() instead of returning — simulates the device dropping
        # the connection mid-reboot.
        self.expert_drop_on = expert_drop_on
        # Substring of a run_expert() command that should raise
        # TransportTimeoutError instead of returning — simulates the
        # deadline elapsing with the channel still open (e.g. a long-running
        # remote command that just hasn't finished yet), distinct from
        # expert_drop_on's channel-closed simulation above.
        self.expert_timeout_on = expert_timeout_on
        # Controls FakeInteractiveShell.wait_for_close() — True (default)
        # simulates the scheduled reboot closing the session promptly; False
        # simulates it never closing (script failed without scheduling one).
        self.expert_reboot_closes = expert_reboot_closes
        self.interactive_shells: list[FakeInteractiveShell] = []

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        rc, stdout = self._lookup(command)
        if self.fail_rc:
            rc = self.fail_rc
        return CommandResult(command=command, exit_status=rc, stdout=stdout, stderr="")

    def run_bash(self, command: str, *, timeout: float | None = None) -> CommandResult:
        # Same scripted responses as run() — this fake doesn't model the
        # real elevate-if-clish distinction (GaiaSession's own tests cover
        # that against the real class); it just records separately so a test
        # can assert a given command went through the bash-native path.
        self.bash_commands.append(command)
        return self.run(command, timeout=timeout)

    def _lookup(self, command: str) -> tuple[int, str]:
        for key, scripted in self.responses.items():
            if key in command:
                if isinstance(scripted, list):
                    resp = scripted.pop(0) if len(scripted) > 1 else scripted[0]
                else:
                    resp = scripted
                return (0, resp) if isinstance(resp, str) else resp
        if command.startswith("df -Pk"):
            # Plenty of free space by default, so the pre-import disk check
            # doesn't need scripting in every test that imports a package.
            # Tests exercising that check script their own "df -Pk <path>".
            return (
                0,
                "Filesystem     1024-blocks     Used  Available Capacity Mounted on\n"
                "/dev/sda1        999999999     1000  999999999        1% /",
            )
        return (0, "")

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        self.puts.append((local_path, remote_path))
        size = self.put_size(local_path)
        if progress is not None:
            progress(size, size)  # single 100% callback
        return size

    def put_scp(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        # Recorded into the same `puts` list as put() — callers only care
        # that a transfer happened, not which protocol carried it.
        return self.put(local_path, remote_path, progress=progress)

    def close(self) -> None:
        self.closed = True

    def open_interactive_shell(self) -> FakeInteractiveShell:
        shell = FakeInteractiveShell(
            expert_password=self.expert_password,
            wrong_password=self.expert_wrong_password,
            command_outputs=self.expert_command_outputs,
            drop_on=self.expert_drop_on,
            timeout_on=self.expert_timeout_on,
            reboot_closes=self.expert_reboot_closes,
        )
        self.interactive_shells.append(shell)
        return shell


class FakeInteractiveShell:
    """Fakes transport.ssh.InteractiveShell for GaiaExpertSession tests,
    without a real pty — same three methods (expect/send_line/send_secret),
    scripted against a tiny state machine that mimics Gaia's actual
    expert-mode conversation closely enough to drive the real
    GaiaExpertSession unchanged: `expert` -> password prompt -> correct/wrong
    password -> expert prompt (or another password prompt) -> commands echo
    their scripted output -> `exit` -> login prompt."""

    def __init__(
        self,
        *,
        expert_password: str = "expert-pw",
        wrong_password: bool = False,
        command_outputs: dict[str, str] | None = None,
        drop_on: str | None = None,
        timeout_on: str | None = None,
        reboot_closes: bool = True,
        password_needs_nudge: bool = False,
    ) -> None:
        self._expert_password = expert_password
        self._wrong_password = wrong_password
        self._command_outputs = command_outputs or {}
        self._drop_on = drop_on
        self._timeout_on = timeout_on
        self._reboot_closes = reboot_closes
        # Models the Gaia `expert` password reader that ignores the newline
        # send_secret() already sent and only acts once a FURTHER newline
        # arrives as its own write (see GaiaExpertSession.enter_expert).
        self._password_needs_nudge = password_needs_nudge
        self._awaiting_nudge = False
        self._last = ""
        self._last_secret: str | None = None
        self.sent: list[str] = []
        self.closed = False

    def send_line(self, text: str) -> None:
        self.sent.append(text)
        self._last = text

    def send_secret(self, text: str) -> None:
        self.sent.append("***")
        self._last_secret = text

    def expect(self, pattern: str, *, timeout: float | None = None) -> str:
        if self._drop_on is not None and self._drop_on in self._last:
            raise TransportError(f"fake: connection dropped while waiting for {pattern!r}")
        if self._timeout_on is not None and self._timeout_on in self._last:
            raise TransportTimeoutError(f"fake: timed out waiting for {pattern!r}")
        if self._last_secret is not None:
            if self._password_needs_nudge and not self._awaiting_nudge:
                # Password buffered but not acted on: stay silent until a bare
                # newline arrives, exactly as the real Gaia reader does.
                self._awaiting_nudge = True
                raise TransportTimeoutError(f"fake: timed out waiting for {pattern!r}")
            password, self._last_secret = self._last_secret, None
            self._awaiting_nudge = False
            if password == self._expert_password and not self._wrong_password:
                return "[Expert@host]# "
            return "wrong password\nPassword: "
        if self._last == "expert":
            return "Password: "
        if self._last == "exit":
            return "host> "
        output = self._command_outputs.get(self._last, "")
        return f"{self._last}\n{output}\n[Expert@host]# "

    def wait_for_close(self, *, timeout: float, poll_interval: float = 1.0) -> str:
        if self._reboot_closes:
            self.closed = True
            return ""
        raise TransportTimeoutError(f"fake: channel still open after {timeout:.0f}s")

    def close(self) -> None:
        self.closed = True


def make_factory(transport: FakeTransport) -> Callable[..., FakeTransport]:
    """A ClientFactory returning the given transport (and recording calls)."""

    def factory(host: object, creds: object) -> FakeTransport:
        return transport

    return factory


class FakeAuthenticator:
    """An ``Authenticator`` for web tests — no live directory. Accepts a mapping of
    username → password; anything else (or an empty password) is rejected, standing
    in for both bad credentials and missing group membership."""

    def __init__(self, users: dict[str, str]) -> None:
        self.users = users

    def authenticate(self, username: str, password: str):  # type: ignore[no-untyped-def]
        from chkp_cpuse_orch.errors import AuthError
        from chkp_cpuse_orch.web.auth import AuthenticatedUser

        if password and self.users.get(username) == password:
            return AuthenticatedUser(
                username=username, display_name=username.title(), dn=f"cn={username}"
            )
        raise AuthError("invalid credentials or not in required group")
