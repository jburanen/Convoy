"""SSH transport to Gaia (clish + expert).

Baseline transport for every operation. Kept deliberately small: connect, run a
command, return (rc, stdout, stderr), upload a file. No orchestration logic lives
here.

Auth is mixed (see .claude/memory/patching-web-design.md): an SSH private key
where installed, admin password otherwise — both may be supplied and Paramiko
tries the key first. Key material comes from the encrypted credential store as a
*string*, never from a file inside the repo.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

import paramiko

from ..errors import TransportError
from ..inventory import Host


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a single remote command."""

    command: str
    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


class CommandRunner(Protocol):
    """Interface the wrappers depend on. Real SSH and fakes both satisfy it."""

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult: ...


class FileTransfer(Protocol):
    """Interface for staging files onto a host. Real SFTP and fakes satisfy it."""

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int: ...


# Key types to try when loading key *material* (a string from the credential
# store). Order matters: modern first.
_KEY_CLASSES: tuple[type[paramiko.PKey], ...] = (
    paramiko.Ed25519Key,
    paramiko.ECDSAKey,
    paramiko.RSAKey,
)


def load_private_key(material: str, passphrase: str | None = None) -> paramiko.PKey:
    """Parse private-key material (PEM/OpenSSH text) into a Paramiko key object."""
    last_error: Exception | None = None
    for key_cls in _KEY_CLASSES:
        try:
            return key_cls.from_private_key(io.StringIO(material), password=passphrase)
        except paramiko.SSHException as exc:
            last_error = exc
    raise TransportError(f"unsupported or corrupt private key material: {last_error}")


class SSHClient:
    """Paramiko-backed Gaia SSH client.

    Usage::

        with SSHClient(host, password="...", private_key=key_material) as ssh:
            result = ssh.run("clish -c \\"show installer packages imported\\"")
            ssh.put("/local/jhf.tgz", "/var/log/upload/jhf.tgz")
    """

    def __init__(
        self,
        host: Host,
        *,
        password: str | None = None,
        private_key: str | None = None,  # key MATERIAL (from the credential store)
        key_passphrase: str | None = None,
        connect_timeout: float = 30.0,
        auto_add_host_key: bool = True,
    ) -> None:
        self.host = host
        self._password = password
        self._private_key = private_key
        self._key_passphrase = key_passphrase
        self._connect_timeout = connect_timeout
        # TOFU by default: Gaia boxes rarely have distributable host keys. Set
        # False to require the host key to already be in known_hosts.
        self._auto_add_host_key = auto_add_host_key
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        pkey = None
        if self._private_key is not None:
            pkey = load_private_key(self._private_key, self._key_passphrase)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        policy = paramiko.AutoAddPolicy if self._auto_add_host_key else paramiko.RejectPolicy
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                self.host.address,
                port=self.host.ssh_port,
                username=self.host.ssh_user,
                password=self._password,
                pkey=pkey,
                timeout=self._connect_timeout,
                # Only the credentials we were handed — no agent, no ~/.ssh scan.
                allow_agent=False,
                look_for_keys=False,
            )
        except (OSError, paramiko.SSHException) as exc:
            client.close()
            raise TransportError(
                f"SSH connect to {self.host.name} ({self.host.address}) failed: {exc}"
            ) from exc
        self._client = client

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        client = self._require_connected()
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
        except (OSError, paramiko.SSHException) as exc:
            raise TransportError(f"command failed on {self.host.name}: {command}: {exc}") from exc
        return CommandResult(command=command, exit_status=rc, stdout=out, stderr=err)

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        """SFTP upload. Returns the remote size after a stat round-trip; the
        caller compares it against the local size (fail closed on mismatch)."""
        client = self._require_connected()
        try:
            sftp = client.open_sftp()
            try:
                # confirm=True stats the remote file after transfer.
                attrs = sftp.put(local_path, remote_path, callback=progress, confirm=True)
            finally:
                sftp.close()
        except (paramiko.SSHException, OSError) as exc:
            raise TransportError(
                f"SFTP upload to {self.host.name}:{remote_path} failed: {exc}"
            ) from exc
        if attrs.st_size is None:
            raise TransportError(f"SFTP upload to {self.host.name}:{remote_path}: no remote size")
        return attrs.st_size

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _require_connected(self) -> paramiko.SSHClient:
        if self._client is None:
            raise TransportError(f"not connected to {self.host.name} — call connect() first")
        return self._client

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def require_ok(result: CommandResult) -> CommandResult:
    """Raise TransportError unless the command succeeded. Fail closed."""
    if not result.ok:
        raise TransportError(
            f"command failed (rc={result.exit_status}): {result.command}\n{result.stderr.strip()}"
        )
    return result
