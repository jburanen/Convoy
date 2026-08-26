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

import base64
import hashlib
import io
import os
import posixpath
import re
import shlex
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Protocol

import paramiko

from ..errors import (
    CredentialError,
    ExpertModeError,
    GaiaShellRestoreError,
    HostKeyChangedError,
    TransportError,
    TransportTimeoutError,
)
from ..inventory import Host
from ..reporting import get_logger

logger = get_logger(__name__)


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


# -- host-key pinning -------------------------------------------------------------
#
# Every connection this tool makes carries a root-equivalent Gaia password (and,
# for patch work, the expert password) to the far end, so "trust whatever key is
# presented, every time" hands those straight to anything on-path. The known_hosts
# file lives beside the DB on the bind-mounted data volume, so pins survive
# container restarts; the path is set once at startup (web/app.py) rather than
# threaded through every service that builds a client.
#
# Policy: TOFU on first contact (pin and persist), hard failure on any later
# mismatch. Re-accepting a legitimately rebuilt host is an explicit operator
# action — see forget_host_key() and the accept-host-key route.

_known_hosts_lock = threading.Lock()
_known_hosts_path: Path | None = None


def set_known_hosts_path(path: str | os.PathLike[str] | None) -> None:
    """Point host-key pinning at ``path``. Called once at startup. ``None``
    disables pinning entirely (the CLI and unit tests, which never talk to
    real gear)."""
    global _known_hosts_path
    with _known_hosts_lock:
        _known_hosts_path = Path(path) if path is not None else None


def known_hosts_path() -> Path | None:
    with _known_hosts_lock:
        return _known_hosts_path


def _host_key_id(host: Host) -> str:
    """Paramiko's known_hosts entry name: the bare address on port 22, the
    ``[address]:port`` form otherwise."""
    if host.ssh_port == 22:
        return host.address
    return f"[{host.address}]:{host.ssh_port}"


def forget_host_key(host: Host) -> bool:
    """Drop ``host``'s pinned key so the next connection re-pins by TOFU.

    This is the operator's "yes, I rebuilt that box" action. Returns True if an
    entry was actually removed. Deliberately narrow: it forgets one host, never
    clears the file."""
    path = known_hosts_path()
    if path is None or not path.is_file():
        return False
    entry = _host_key_id(host)
    with _known_hosts_lock:
        keys = paramiko.HostKeys()
        try:
            keys.load(str(path))
        except OSError as exc:
            raise TransportError(f"could not read known_hosts at {path}: {exc}") from exc
        if entry not in keys:
            return False
        del keys[entry]
        try:
            keys.save(str(path))
        except OSError as exc:
            raise TransportError(f"could not write known_hosts at {path}: {exc}") from exc
    return True


def _fingerprint(key: paramiko.PKey | None) -> str:
    """OpenSSH-style ``SHA256:...`` fingerprint, for operator-facing messages."""
    if key is None:
        return "unknown"
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"{key.get_name()} SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


class _PinningPolicy(paramiko.MissingHostKeyPolicy):
    """TOFU that actually persists.

    paramiko's own AutoAddPolicy writes the whole in-memory HostKeys back to
    disk, so two connections pinning different hosts at the same time can lose
    one of the two pins — and a lost pin silently re-TOFUs on the next connect,
    which is the exact guarantee we're trying to make. Re-read, add, and write
    under the module lock instead, so concurrent first-contacts merge rather
    than overwrite."""

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        path = known_hosts_path()
        if path is None:
            return
        with _known_hosts_lock:
            keys = paramiko.HostKeys()
            try:
                # Don't assume _load_known_hosts already made the directory —
                # a pin that silently fails to persist re-TOFUs on the next
                # connect, which is exactly what this is meant to prevent.
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.is_file():
                    keys.load(str(path))
                keys.add(hostname, key.get_name(), key)
                keys.save(str(path))
            except OSError as exc:
                logger.warning(
                    "could not persist host key; it will be re-trusted on next connect",
                    host=hostname,
                    path=str(path),
                    error=str(exc),
                )
                return
        logger.info(
            "pinned new SSH host key on first contact",
            host=hostname,
            fingerprint=_fingerprint(key),
        )


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
        # TOFU: unknown hosts are pinned on first contact and persisted to the
        # configured known_hosts file (see set_known_hosts_path); a host whose
        # key later CHANGES is refused outright, whatever this flag says. Set
        # False to also refuse hosts that aren't pinned yet.
        self._auto_add_host_key = auto_add_host_key
        self._client: paramiko.SSHClient | None = None

    def _load_known_hosts(self, client: paramiko.SSHClient) -> None:
        """Register the pin file with ``client`` so known keys are checked and
        newly-seen ones are written back by AutoAddPolicy."""
        path = known_hosts_path()
        if path is None:
            return
        try:
            with _known_hosts_lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=True)
                client.load_host_keys(str(path))
        except OSError as exc:
            # Refusing to connect is the wrong trade here — an unwritable data
            # volume shouldn't take patching offline — but silently dropping to
            # trust-everything must be loud.
            logger.warning(
                "host-key pinning unavailable; connecting without it",
                path=str(path),
                error=str(exc),
            )

    def connect(self) -> None:
        pkey = None
        if self._private_key is not None:
            pkey = load_private_key(self._private_key, self._key_passphrase)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        self._load_known_hosts(client)
        client.set_missing_host_key_policy(
            _PinningPolicy() if self._auto_add_host_key else paramiko.RejectPolicy()
        )
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
        except paramiko.BadHostKeyException as exc:
            # Paramiko raises this before authenticating, so no credential has
            # been sent to the far end yet. Keep it that way.
            client.close()
            raise HostKeyChangedError(
                f"the SSH host key for {self.host.name} ({self.host.address}) has "
                f"changed since it was first trusted. Expected "
                f"{_fingerprint(exc.expected_key)}, got {_fingerprint(exc.key)}. "
                "No credentials were sent. If this host was genuinely rebuilt or "
                "upgraded, re-accept its key to pin the new one; otherwise treat "
                "this as a possible interception and investigate before retrying."
            ) from exc
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
    """Raise TransportError unless the command succeeded. Fail closed.

    Reports stdout when stderr is empty: **clish writes its errors to stdout**,
    so reporting stderr alone reduced every clish failure to a bare "rc=1" with
    no reason attached. That cost real debugging time on a config-lock failure
    whose cause (CLINFR0771) was sitting in the discarded stdout all along."""
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TransportError(
            f"command failed (rc={result.exit_status}): {result.command}" + chr(10) + detail
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

    # How long to wait for the expert password to be acted on before nudging
    # it with a further newline (see enter_expert). Short, because the healthy
    # case answers in well under a second and the unhealthy case never answers
    # at all -- this is dead time on every affected escalation.
    _SUBMIT_NUDGE_AFTER = 10.0

    def enter_expert(self, expert_password: str, *, timeout: float = 20.0) -> None:
        self._shell.send_line("expert")
        first = self._shell.expect(
            f"(?:{self._PASSWORD_PROMPT})|(?:{self._EXPERT_PROMPT})", timeout=timeout
        )
        if re.search(self._EXPERT_PROMPT, first):
            return  # already in expert mode
        self._shell.send_secret(expert_password)
        want = f"(?:{self._EXPERT_PROMPT})|(?:{self._PASSWORD_PROMPT})"
        try:
            result = self._shell.expect(want, timeout=self._SUBMIT_NUDGE_AFTER)
        except TransportTimeoutError:
            # Some Gaia builds' `expert` password reader does not act on the
            # newline send_secret() already sent: the password sits unread and
            # the session hangs until the escalation times out. Confirmed on an
            # R81.x gateway (clish login) 2026-08-26 -- a further newline, sent
            # as its OWN write, submits the already-buffered password and lands
            # in expert mode normally. Gaia Embedded (Spark) answers the first
            # newline immediately and never reaches this branch.
            #
            # It MUST be a separate write, and only after silence. Sending the
            # password and both newlines in one write is not a shortcut: the
            # reader then takes the first newline as an empty password, fails,
            # and the password itself is echoed IN CLEARTEXT at the clish prompt
            # where Gaia logs it as an invalid command. Never combine them.
            self._shell.send_line("")
            result = self._shell.expect(want, timeout=timeout)
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


# Gaia refuses a clish config change while the config database is locked, and
# reports it on STDOUT as CLINFR0771 / CLINFR0519. Elevating to expert (which
# every run_bash() on a clish-login host does) takes that lock, so the very
# next clish `set` in the same session is refused -- which is what broke the
# transfer shell-toggle on a real gateway, 2026-08-26.
_CONFIG_LOCK_RE = re.compile(r"CLINFR0771|CLINFR0519|[Cc]onfig(?:uration)? lock")


def _run_clish_breaking_lock(client: SSHClient | GaiaSession, command: str) -> CommandResult:
    """Run a mutating clish command, taking the config lock only if we are
    actually blocked by it.

    Deliberately NOT a pre-emptive `lock database override` on every call:
    that forcibly evicts whoever legitimately holds the lock (an admin mid-
    change in SmartConsole or clish) and is exactly the pattern the security
    review flagged in cpuse.py. Override only on an observed conflict, on a
    mutating path we are already committed to, and log who held it."""
    result = client.run(command)
    if result.ok or not _CONFIG_LOCK_RE.search(result.stdout + result.stderr):
        return result
    logger.warning(
        "clish config lock held; overriding to continue",
        command=command,
        detail=(result.stdout.strip() or result.stderr.strip())[:200],
    )
    client.run("lock database override")
    return client.run(command)


def _restore_clish_shell(client: SSHClient, username: str) -> None:
    """Flip an account's shell back to clish from a session that is
    currently bash — used only by ``GaiaSession``'s transfer maneuver below,
    after a login-shell toggle to bash has already happened. Wrapped as
    ``clish -c`` since the connection this runs on is bash right now."""
    require_ok(
        _run_clish_breaking_lock(
            client, f"clish -c {shlex.quote(f'set user {username} shell /etc/cli.sh')}"
        )
    )
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
        # Both of these are clish config writes, and this session has almost
        # certainly just taken the config lock by elevating to expert for an
        # earlier step (a disk check, a sha1) -- so they must be able to break
        # that lock or the transfer can never start.
        require_ok(
            _run_clish_breaking_lock(self, f"set user {shlex.quote(username)} shell /bin/bash")
        )
        require_ok(_run_clish_breaking_lock(self, "save config"))
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
