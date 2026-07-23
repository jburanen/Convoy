"""Shared test doubles for SSH-touching code paths."""

from __future__ import annotations

import os
from collections.abc import Callable

from chkp_cpuse_orch.transport.ssh import CommandResult

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
    """Satisfies services.common.Transport. Replies come from ``responses``:
    the first key found as a substring of the command wins."""

    def __init__(
        self, responses: dict[str, Resp | list[Resp]] | None = None, fail_rc: int = 0
    ) -> None:
        self.responses = responses or {}
        self.fail_rc = fail_rc  # set non-zero to make every command fail
        self.commands: list[str] = []
        self.puts: list[tuple[str, str]] = []
        self.closed = False
        # Override to fake a bad upload (e.g. lambda local: 0 for a size mismatch).
        self.put_size: Callable[[str], int] = lambda local: os.path.getsize(local)

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        rc, stdout = self._lookup(command)
        if self.fail_rc:
            rc = self.fail_rc
        return CommandResult(command=command, exit_status=rc, stdout=stdout, stderr="")

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
