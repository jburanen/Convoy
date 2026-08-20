"""SSH transport to Gaia (clish + expert).

Baseline transport for every operation. Kept deliberately small: connect, run a
command, return (rc, stdout, stderr), upload a file. No orchestration logic lives
here.

Auth is mixed (see .claude/memory/patching-web-design.md): an SSH private key
where installed, admin password otherwise — both may be supplied and Paramiko
tries the key first. Key material comes from the encrypted credential store as a
*string*, never from a file inside the repo.

Also home to InteractiveShell/GaiaExpertSession: a pty-backed session for
scripted `expert`-mode escalation, which exec_command() can't do (see
.claude/memory/spark-firmware-patching.md). Still transport, not orchestration
— they send bytes and wait for prompts, nothing more.
"""

from __future__ import annotations

import io
import os
import posixpath
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

import paramiko

from ..errors import ExpertModeError, TransportError, TransportTimeoutError
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


def _read_scp_ack(stdout: object, host_name: str) -> None:
    """Read one byte of the classic-SCP sink protocol's ack: 0x00 = ok, 0x01
    = warning, 0x02 = fatal — both non-zero cases are followed by a
    human-readable message up to the next newline. Raises on anything but a
    clean ok, including the channel closing mid-handshake."""
    ack = stdout.read(1)  # type: ignore[attr-defined]
    if not ack:
        raise TransportError(f"SCP upload to {host_name}: connection closed before an ack")
    if ack in (b"\x01", b"\x02"):
        detail = stdout.readline().decode("utf-8", errors="replace").strip()  # type: ignore[attr-defined]
        raise TransportError(f"SCP upload to {host_name} rejected: {detail or 'no detail given'}")
    if ack != b"\x00":
        raise TransportError(f"SCP upload to {host_name}: unexpected ack byte {ack!r}")


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
        username: str | None = None,  # override; falls back to host.ssh_user
        password: str | None = None,
        private_key: str | None = None,  # key MATERIAL (from the credential store)
        key_passphrase: str | None = None,
        connect_timeout: float = 30.0,
        auto_add_host_key: bool = True,
    ) -> None:
        self.host = host
        self._username = username
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
                username=self._username or self.host.ssh_user,
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

    def put_scp(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        """Classic-SCP upload, spoken directly over ``exec_command("scp -t
        ...")`` rather than Paramiko's SFTP subsystem — Spark (Gaia
        Embedded)'s ``bashUser on`` only advertises SCP ("SCP access
        enabled" in its own banner, no mention of SFTP), and a real-hardware
        transfer confirmed SFTP does not work there (`put()` failed with
        "Channel closed"). Gaia (Force) and the CPUSE-local management-server
        path keep using ``put()`` — SFTP is confirmed working there. See
        .claude/memory/spark-firmware-patching.md."""
        client = self._require_connected()
        local_size = os.path.getsize(local_path)
        filename = posixpath.basename(remote_path) or os.path.basename(local_path)
        try:
            stdin, stdout, _stderr = client.exec_command(f"scp -t {shlex.quote(remote_path)}")
            _read_scp_ack(stdout, self.host.name)
            stdin.write(f"C0644 {local_size} {filename}\n".encode())
            stdin.flush()
            _read_scp_ack(stdout, self.host.name)
            sent = 0
            with open(local_path, "rb") as fh:
                while chunk := fh.read(1 << 20):
                    stdin.write(chunk)
                    sent += len(chunk)
                    if progress is not None:
                        progress(sent, local_size)
            stdin.write(b"\x00")
            stdin.flush()
            _read_scp_ack(stdout, self.host.name)
            stdin.close()
            rc = stdout.channel.recv_exit_status()
        except (OSError, paramiko.SSHException) as exc:
            raise TransportError(
                f"SCP upload to {self.host.name}:{remote_path} failed: {exc}"
            ) from exc
        if rc != 0:
            raise TransportError(
                f"SCP upload to {self.host.name}:{remote_path} failed: scp exited {rc}"
            )
        return local_size

    def open_interactive_shell(self, *, width: int = 200, height: int = 50) -> InteractiveShell:
        """Open a pty-backed interactive session on the same connection, for
        scripted escalation (Gaia `expert` mode) that exec_command can't do —
        see InteractiveShell / GaiaExpertSession below."""
        client = self._require_connected()
        try:
            channel = client.invoke_shell(term="vt100", width=width, height=height)
        except (paramiko.SSHException, OSError) as exc:
            raise TransportError(
                f"failed to open an interactive shell on {self.host.name}: {exc}"
            ) from exc
        return InteractiveShell(channel, host_name=self.host.name)

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


class InteractiveShell:
    """A pty-backed, stateful SSH session (``invoke_shell``) for scripted
    interactive escalation — Gaia's ``expert`` command included.

    ``SSHClient.run()`` uses ``exec_command()``, which spawns a fresh,
    non-interactive shell per call and has no way to see or answer a prompt
    (e.g. the ``expert`` command's password prompt). This class instead sends
    bytes to one long-lived channel and waits for a pattern to appear in the
    output, one conversation turn at a time. It has no Gaia-specific
    vocabulary of its own — that lives in GaiaExpertSession below — so a
    wrong assumption about prompt text/timing is a contained fix in one
    place, not a rewrite of any job logic built on top of it.
    """

    def __init__(
        self, channel: paramiko.Channel, *, host_name: str = "", read_timeout: float = 15.0
    ) -> None:
        self._channel = channel
        self._host_name = host_name
        self._read_timeout = read_timeout

    def expect(self, pattern: str, *, timeout: float | None = None) -> str:
        """Read until ``pattern`` (a regex) matches the tail of accumulated
        output, or ``timeout`` elapses. Returns everything read. Raises
        TransportError if the channel closes first, or the narrower
        TransportTimeoutError if the deadline elapses with the channel still
        open — these are NOT interchangeable: a closed channel means the
        remote end actually hung up (e.g. a device rebooting), while a
        timeout with the channel still open means only that the pattern
        hasn't shown up *yet*, and whatever command is running remotely may
        still be legitimately in progress. Deliberately no fuzzy retry, a
        clear failure with the actual bytes seen is more debuggable than one
        that silently guesses again."""
        regex = re.compile(pattern)
        deadline = time.monotonic() + (self._read_timeout if timeout is None else timeout)
        collected = ""
        while not regex.search(collected):
            if self._channel.recv_ready():
                collected += self._channel.recv(4096).decode("utf-8", errors="replace")
                continue
            if self._channel.closed:
                raise TransportError(
                    f"SSH channel to {self._host_name} closed while waiting for "
                    f"{pattern!r}; output so far: {collected!r}"
                )
            if time.monotonic() >= deadline:
                raise TransportTimeoutError(
                    f"timed out waiting for {pattern!r} on {self._host_name}; "
                    f"output so far: {collected!r}"
                )
            time.sleep(0.1)
        return collected

    def send_line(self, text: str) -> None:
        self._channel.send((text + "\n").encode("utf-8"))

    def send_secret(self, text: str) -> None:
        """Same as send_line — named separately so a reader (and any future
        change to this method) knows the argument must never be logged."""
        self._channel.send((text + "\n").encode("utf-8"))

    def close(self) -> None:
        self._channel.close()


class GaiaExpertSession:
    """Drives a Gaia ``expert``-mode escalation over an InteractiveShell:
    send ``expert``, answer the password prompt, land at the expert prompt
    (or fail if rejected), run commands, ``exit`` back to the login shell.

    This is the ONLY place that encodes Gaia's actual prompt text. The
    regexes below are a first guess — **unvalidated against real Spark
    (Gaia Embedded) hardware**, see .claude/memory/spark-firmware-patching.md.
    Isolating them here means a wrong guess is a contained fix, not a change
    to any job's sequencing or logging.
    """

    _PASSWORD_PROMPT = r"[Pp]assword\s*:\s*$"
    _EXPERT_PROMPT = r"\[Expert@[^\]]+\]#\s*$"
    _LOGIN_PROMPT = r"[>#]\s*$"
    _WRONG_PASSWORD_RE = re.compile(
        r"wrong password|incorrect password|access denied", re.IGNORECASE
    )

    def __init__(self, shell: InteractiveShell) -> None:
        self._shell = shell

    def enter_expert(self, expert_password: str, *, timeout: float = 20.0) -> None:
        self._shell.send_line("expert")
        first = self._shell.expect(
            f"(?:{self._PASSWORD_PROMPT})|(?:{self._EXPERT_PROMPT})", timeout=timeout
        )
        if re.search(self._EXPERT_PROMPT, first):
            return  # already in expert mode
        self._shell.send_secret(expert_password)
        result = self._shell.expect(
            f"(?:{self._EXPERT_PROMPT})|(?:{self._PASSWORD_PROMPT})", timeout=timeout
        )
        if re.search(self._EXPERT_PROMPT, result):
            return
        detail = "wrong password" if self._WRONG_PASSWORD_RE.search(result) else "unexpected prompt"
        raise ExpertModeError(
            f"expert-mode escalation failed ({detail}) — check the credential set's "
            "expert password; prompt matching is unvalidated against real Spark "
            "hardware, see .claude/memory/spark-firmware-patching.md"
        )

    def run_expert(self, command: str, *, timeout: float = 60.0) -> str:
        """Run one command while already in expert mode; returns its output
        with the echoed command line and trailing prompt stripped."""
        self._shell.send_line(command)
        output = self._shell.expect(self._EXPERT_PROMPT, timeout=timeout)
        lines = output.splitlines()
        if lines and command.strip() in lines[0]:
            lines = lines[1:]
        if lines and re.search(self._EXPERT_PROMPT, lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def exit_expert(self, *, timeout: float = 15.0) -> None:
        self._shell.send_line("exit")
        self._shell.expect(self._LOGIN_PROMPT, timeout=timeout)
