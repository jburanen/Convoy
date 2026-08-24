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
from enum import StrEnum
from types import TracebackType
from typing import Protocol

import paramiko

from ..errors import (
    CredentialError,
    ExpertModeError,
    GaiaShellRestoreError,
    TransportError,
    TransportTimeoutError,
)
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


class GaiaShell(StrEnum):
    """What a Gaia account's SSH login shell is, which decides how a clish
    command must be sent. Historically a static per-host setting this tool
    chose at provisioning time; now detected live per connection (see
    ``GaiaSession`` below) since the tool no longer assumes every account is
    bash-default — see .claude/memory/gaia-shell-posture.md."""

    EXPERT = "expert"  # login shell is bash -> wrap as: clish -c "<cmd>"
    CLISH = "clish"  # login shell is clish -> send the command bare


class CommandRunner(Protocol):
    """Interface the wrappers depend on. Real SSH and fakes both satisfy it.

    ``run`` is for clish-native commands (the caller already formats the wire
    string for whichever shell it's talking to — see ``cpuse.py``); ``run_bash``
    is for bash-native ones, escalating to expert mode first if needed (see
    ``GaiaSession`` below). CPUSE only ever calls ``run``; CDT only ever calls
    ``run_bash`` — both are declared here so either wrapper can depend on this
    one protocol."""

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult: ...

    def run_bash(self, command: str, *, timeout: float | None = None) -> CommandResult: ...


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

    @property
    def host_name(self) -> str:
        return self._host_name

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

    def wait_for_close(self, *, timeout: float, poll_interval: float = 1.0) -> str:
        """Block until the channel actually closes (the remote end hung up —
        e.g. a device rebooting), or ``timeout`` elapses first. Unlike
        ``expect()``, there's no pattern to match against — this is for the
        specific case of already knowing a remote command has finished and
        deliberately waiting to observe the *disconnect* itself as a signal,
        rather than racing a timeout against it. Drains and returns whatever
        incidental output arrives while waiting (there shouldn't be much, at
        an idle prompt). Raises TransportTimeoutError — not TransportError —
        if the deadline elapses first: the channel is still open, so this is
        not evidence the remote end is gone, only that it hasn't gone *yet*."""
        deadline = time.monotonic() + timeout
        collected = ""
        while True:
            if self._channel.recv_ready():
                collected += self._channel.recv(4096).decode("utf-8", errors="replace")
                continue
            if self._channel.closed:
                return collected
            if time.monotonic() >= deadline:
                raise TransportTimeoutError(
                    f"channel to {self._host_name} still open after {timeout:.0f}s waiting "
                    f"for it to close; output so far: {collected!r}"
                )
            time.sleep(poll_interval)

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

    # A marker distinctive enough it will never collide with real command
    # output, used to recover a numeric exit status below.
    _RC_MARKER = "__CHKP_ORCH_RC__"
    _RC_RE = re.compile(rf"{_RC_MARKER}:(-?\d+)\s*$")

    def run_expert_command(self, command: str, *, timeout: float = 60.0) -> CommandResult:
        """Like ``run_expert``, but for bash-native commands that need a real
        exit status (``df``, ``sha1sum``, ``cat``, ``rm``, the CDT binary,
        ``mgmt_cli`` — anything checking ``.ok``/``exit_status`` the way any
        other ``CommandResult`` is), not just text to scan. ``run_expert``
        itself only returns output text — enough for Spark's own
        text-scanning callers, not for these. Appends a marker+``$?`` echo
        and strips it back off. Stderr is always empty: a pty intermixes
        stdout/stderr with no way to separate them, same limitation as every
        other interactive-shell command in this module."""
        output = self.run_expert(f"{command}; echo {self._RC_MARKER}:$?", timeout=timeout)
        lines = output.splitlines()
        match = self._RC_RE.search(lines[-1]) if lines else None
        if match is None:
            raise TransportError(
                f"could not recover an exit status for {command!r} on "
                f"{self._shell.host_name}: no {self._RC_MARKER} marker in output: {output!r}"
            )
        stdout = "\n".join(lines[:-1])
        return CommandResult(
            command=command, exit_status=int(match.group(1)), stdout=stdout, stderr=""
        )

    def exit_expert(self, *, timeout: float = 15.0) -> None:
        self._shell.send_line("exit")
        self._shell.expect(self._LOGIN_PROMPT, timeout=timeout)


def _restore_clish_shell(client: SSHClient, username: str) -> None:
    """Flip an account's shell back to clish from a session that is
    currently bash — used only by ``GaiaSession``'s transfer maneuver below,
    after a login-shell toggle to bash has already happened. Wrapped as
    ``clish -c`` since the connection this runs on is bash right now."""
    require_ok(client.run(f"clish -c {shlex.quote(f'set user {username} shell /etc/cli.sh')}"))
    require_ok(client.run(f"clish -c {shlex.quote('save config')}"))


class GaiaSession:
    """``CommandRunner``/``Transport`` for a full Gaia (Force) host under the
    clish-login-plus-on-demand-expert posture: SSH lands in clish (Gaia's own
    default) for accounts provisioned this way, or directly in bash/expert
    for accounts an operator supplies that already have that shell (older
    provisioning, or a pre-existing admin account) — detected live per
    connection, not configured per host. See
    .claude/memory/gaia-shell-posture.md.

    - ``run()`` is for **clish-native** commands. The caller (``cpuse.py``)
      already formats the wire string for ``self.shell`` (bare, or wrapped
      as ``clish -c "..."``), so this is a bare passthrough either way —
      exactly today's confirmed-working behavior for both shells, unchanged.
    - ``run_bash()`` is for **bash-native** commands (``df``, ``sha1sum``,
      ``cat``, ``rm``, the CDT binary, ``mgmt_cli``, ...). A clish-default
      account escalates via ``expert`` exactly once per session, lazily, the
      first time one is actually needed, and stays elevated for the rest of
      the session; an already-bash account just runs it directly, same as
      today.
    - ``put()`` needs a genuinely bash-shell session — Gaia's SFTP/SCP does
      not work from a clish login. For a clish-default account this
      temporarily flips the account's own shell to ``/bin/bash``,
      reconnects (the change only takes effect on a fresh session),
      transfers, then always flips it back — even on failure, since leaving
      a production account on a standing bash shell defeats the whole point
      of this posture.

    Unvalidated against real full-Gaia hardware this session (no gear
    available) — the shell-detection probe, ``run_expert_command``'s ``$?``
    marker, and the transfer shell-toggle maneuver are all new, first-guess
    assumptions. See .claude/memory/gaia-shell-posture.md for what to check
    first if this misbehaves.
    """

    _PROBE_TOKEN = "CHKP_ORCH_SHELL_PROBE_OK"

    def __init__(
        self,
        host: Host,
        *,
        username: str | None,
        password: str | None,
        private_key: str | None,
        key_passphrase: str | None = None,
        expert_password: str | None,
        connect_timeout: float = 30.0,
    ) -> None:
        self.host = host
        self._username = username
        self._password = password
        self._private_key = private_key
        self._key_passphrase = key_passphrase
        self._expert_password = expert_password
        self._connect_timeout = connect_timeout
        self._ssh = self._new_client()
        self._ssh.connect()
        self._shell: GaiaShell | None = None
        self._interactive: InteractiveShell | None = None
        self._expert: GaiaExpertSession | None = None
        self._elevated = False

    def _new_client(self) -> SSHClient:
        return SSHClient(
            self.host,
            username=self._username,
            password=self._password,
            private_key=self._private_key,
            key_passphrase=self._key_passphrase,
            connect_timeout=self._connect_timeout,
        )

    @property
    def shell(self) -> GaiaShell:
        if self._shell is None:
            probe = self._ssh.run(f"echo {self._PROBE_TOKEN}")
            self._shell = (
                GaiaShell.EXPERT
                if probe.ok and self._PROBE_TOKEN in probe.stdout
                else GaiaShell.CLISH
            )
        return self._shell

    # -- CommandRunner / Transport --------------------------------------------

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        _ = self.shell  # ensure detection has happened before the caller formats anything
        return self._ssh.run(command, timeout=timeout)

    def run_bash(self, command: str, *, timeout: float | None = None) -> CommandResult:
        if self.shell is GaiaShell.EXPERT:
            return self._ssh.run(command, timeout=timeout)
        self._ensure_elevated(timeout=timeout)
        assert self._expert is not None
        return self._expert.run_expert_command(command, timeout=timeout or 60.0)

    def _ensure_elevated(self, *, timeout: float | None) -> None:
        if self._elevated:
            return
        if not self._expert_password:
            raise CredentialError(
                f"an expert-mode password is required to patch {self.host.name!r} — the "
                "assigned credential set has none (or none was supplied for this job)"
            )
        if self._interactive is None:
            self._interactive = self._ssh.open_interactive_shell()
            self._expert = GaiaExpertSession(self._interactive)
        assert self._expert is not None
        self._expert.enter_expert(self._expert_password, timeout=timeout or 20.0)
        self._elevated = True

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        if self.shell is GaiaShell.EXPERT:
            return self._ssh.put(local_path, remote_path, progress=progress)
        return self._transfer_via_temporary_bash_shell(local_path, remote_path, progress)

    def _transfer_via_temporary_bash_shell(
        self,
        local_path: str,
        remote_path: str,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        if not self._username:
            raise TransportError(
                f"cannot transfer to {self.host.name!r}: no SSH username resolved to "
                "toggle the account's own shell for the transfer"
            )
        username = self._username
        require_ok(self.run(f"set user {shlex.quote(username)} shell /bin/bash"))
        require_ok(self.run("save config"))
        # A previously-elevated interactive pty lives on the transport we're
        # about to close — drop it so a later run_bash() re-elevates fresh on
        # the reconnected session below, instead of using a dead channel.
        if self._interactive is not None:
            self._interactive.close()
            self._interactive = None
            self._expert = None
            self._elevated = False
        self._ssh.close()

        transfer_client = self._new_client()
        transfer_client.connect()
        try:
            size = transfer_client.put(local_path, remote_path, progress=progress)
        finally:
            # Restore-to-clish always runs, transfer success or failure — a
            # restore failure raises regardless (chains onto whatever
            # exception, if any, is already propagating via __context__),
            # since leaving the account on a standing bash shell is never
            # acceptable to silently swallow.
            try:
                self._restore_clish_or_raise(transfer_client, username)
            finally:
                transfer_client.close()
                # Resume the session's primary connection, back in clish —
                # unconditionally, even if the transfer or restore above
                # failed, so this GaiaSession stays usable for whatever the
                # caller does next (e.g. closing it, or logging the failure)
                # instead of being left pointing at an already-closed client.
                self._ssh = self._new_client()
                self._ssh.connect()
        return size

    def _restore_clish_or_raise(self, transfer_client: SSHClient, username: str) -> None:
        try:
            _restore_clish_shell(transfer_client, username)
        except TransportError as exc:
            raise GaiaShellRestoreError(
                f"could not restore {username!r}'s login shell back to clish on "
                f"{self.host.name!r} after a transfer — the account is left on a standing "
                f"bash shell; fix this by hand (`set user {username} shell /etc/cli.sh`, "
                f"`save config`): {exc}"
            ) from exc

    def close(self) -> None:
        if self._interactive is not None:
            self._interactive.close()
        self._ssh.close()

    # -- passthroughs for Spark's own expert-mode plumbing --------------------

    def open_interactive_shell(self, *, width: int = 200, height: int = 50) -> InteractiveShell:
        """Spark (services/spark_patching.py) drives its own bashUser/expert
        conversation directly over an interactive shell, independent of this
        session's own lazy elevation for ``run_bash`` — a separate channel on
        the same underlying connection, same as any two interactive shells
        would be. See ExpertCapableTransport in spark_patching.py."""
        return self._ssh.open_interactive_shell(width=width, height=height)

    def put_scp(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int:
        """Spark transfers over classic SCP, not SFTP — its own job sequence
        (bashUser on/off) already brackets this call, so unlike ``put()``
        above, no shell-toggle maneuver is needed or wanted here."""
        return self._ssh.put_scp(local_path, remote_path, progress=progress)
