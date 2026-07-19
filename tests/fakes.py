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


class FakeTransport:
    """Satisfies services.patching.Transport. Replies come from ``responses``:
    the first key found as a substring of the command wins."""

    def __init__(self, responses: dict[str, str] | None = None, fail_rc: int = 0) -> None:
        self.responses = responses or {}
        self.fail_rc = fail_rc  # set non-zero to make every command fail
        self.commands: list[str] = []
        self.puts: list[tuple[str, str]] = []
        self.closed = False
        # Override to fake a bad upload (e.g. lambda local: 0 for a size mismatch).
        self.put_size: Callable[[str], int] = lambda local: os.path.getsize(local)

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        stdout = next((out for key, out in self.responses.items() if key in command), "")
        return CommandResult(command=command, exit_status=self.fail_rc, stdout=stdout, stderr="")

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
