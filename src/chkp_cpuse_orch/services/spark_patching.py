"""Spark (Quantum Spark / Gaia Embedded) firmware patching service.

Spark firewalls don't go through CPUSE or CDT — see patching.py's module
docstring for that path, used by every other host kind this tool patches.
Spark patches via SCP + expert-mode shell commands instead (operator-
specified, 2026-08-19): enable ``bashUser``, transfer a ``.img`` file to
``/storage``, disable ``bashUser`` again, then run
``upgrade_revert_image.sh ... upgrade safe``, which reboots the device on its
own a minute or two later. See .claude/memory/spark-firmware-patching.md for
the two assumptions here that are **unvalidated against real Spark
hardware** — whether SFTP (reused from Transport.put, same as the Gaia CPUSE
path) actually works in either ``bashUser`` state, and the exact prompt text
the ``expert`` command's password escalation uses (transport/ssh.py's
GaiaExpertSession) — and why both are isolated behind narrow interfaces so a
wrong guess is a contained fix.

Two job kinds:

- **test_credentials** — proves SSH login *and* ``expert``-mode escalation
  work for a Spark firewall's assigned credential set. Never runs a mutating
  command, so it's safe to run repeatedly with no confirmation gate — unlike
  transfer_upgrade below.
- **transfer_upgrade** — the actual firmware push. Requires
  ``confirmed=True``: the device reboots on its own once the upgrade command
  is issued, and that can't be undone or cancelled after the fact. The job
  cannot and does not confirm the upgrade actually completed — Spark has
  nothing like CPUSE's ``show installer package`` to poll — success here only
  means the command was issued.
"""

from __future__ import annotations

import asyncio
import contextlib
import posixpath
from pathlib import Path
from typing import Protocol, cast

from ..credentials import CredentialBundle, CredentialKind, JobCredentialVault
from ..errors import CredentialError, ExpertModeError, JobError, TransportError
from ..inventory import Host
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore, package_kind
from ..store import JobRecord, Store
from ..transport.ssh import GaiaExpertSession, InteractiveShell
from .common import (
    EnvironmentRegistry,
    HostConnector,
    ProgressReporter,
    Transport,
    ensure_host_free,
    job_run_credentials,
    submit_host_job,
    verify_uploaded_file,
)

__all__ = [
    "JOB_TEST_CREDENTIALS",
    "JOB_TRANSFER_UPGRADE",
    "EnvironmentRegistry",
    "HostConnector",
    "SparkPatchingService",
]

JOB_TEST_CREDENTIALS = "spark.test_credentials"
JOB_TRANSFER_UPGRADE = "spark.transfer_upgrade"

# Gaia Embedded's fixed staging location for upgrade_revert_image.sh.
_STORAGE_DIR = "/storage"

# Generous — the script validates the image and may take a while before
# either printing something or the device drops the connection to reboot.
_UPGRADE_TIMEOUT = 120.0


class ExpertCapableTransport(Transport, Protocol):
    """A Transport that can also open a pty-backed interactive shell — what
    the Spark expert-mode commands (bashUser on/off,
    upgrade_revert_image.sh) need. SSHClient satisfies this structurally
    (see transport/ssh.py); tests substitute a fake with the same shape."""

    def open_interactive_shell(self) -> InteractiveShell: ...


def _safe_close(closable: object) -> None:
    """Best-effort close — used in ``finally`` blocks around a connection
    that may already be dead (e.g. the device started rebooting). A raise
    here would shadow whatever real exception is propagating."""
    close = getattr(closable, "close", None)
    if close is None:
        return
    with contextlib.suppress(Exception):
        close()


class SparkPatchingService:
    """Per-Spark-firewall firmware operations, across independent environments."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        packages: PackageStore,
        runner: JobRunner,
        vault: JobCredentialVault,
        store: Store,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self._packages = packages
        self._vault = vault
        self._store = store
        runner.register(JOB_TEST_CREDENTIALS, self._test_credentials_job)
        runner.register(JOB_TRANSFER_UPGRADE, self._transfer_upgrade_job)

    # -- job submission -----------------------------------------------------------

    def submit_test_credentials(
        self,
        environment: str,
        host_name: str,
        *,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: SSH login + ``expert``-mode escalation, nothing more —
        never touches device state, so it's safe to run repeatedly."""
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        ensure_host_free(self._store, environment, host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_TEST_CREDENTIALS,
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def submit_transfer_upgrade(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        confirmed: bool,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Enqueue: bashUser on -> transfer the .img to /storage -> verify ->
        bashUser off -> upgrade_revert_image.sh ... upgrade safe.
        ``confirmed`` must be True — the device reboots on its own once the
        upgrade command is issued, and that can't be undone or cancelled."""
        if not confirmed:
            raise JobError(
                "firmware transfer requires explicit confirmation — the firewall reboots "
                "on its own once the upgrade command is issued, and this cannot be undone"
            )
        if package_kind(package_filename) != "spark_image":
            raise JobError(
                f"{package_filename!r} isn't a Spark firmware image (.img) — Spark firewalls "
                "only accept .img packages"
            )
        connector = self.registry.get(environment)
        host = connector.spark_firewall_host(host_name)
        ensure_host_free(self._store, environment, host_name)
        self._packages.path_for(package_filename)  # validates record + content file
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_TRANSFER_UPGRADE,
            params={"package": package_filename},
            credentials=credentials,
            triggered_by=triggered_by,
        )

    # -- job handlers (async wrappers over blocking SSH work) ----------------------

    async def _test_credentials_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_test_credentials, ctx)

    async def _transfer_upgrade_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_transfer_upgrade, ctx)

    # -- shared helpers -------------------------------------------------------------

    def _resolve_bundle(
        self, connector: HostConnector, host: Host, ctx: JobContext
    ) -> CredentialBundle:
        """The full credential bundle for this job, whichever way it's
        sourced — the vault (storage-disabled) or the store (storage-
        enabled). The same bundle object is then passed straight to
        ``connect()`` so the expert-password check below and the actual
        connection always see identical credentials."""
        creds = job_run_credentials(connector, self._vault, ctx.job)
        if creds is not None:
            return creds
        return connector.host_credentials(host)

    def _require_expert_password(
        self, bundle: CredentialBundle, host: Host, ctx: JobContext
    ) -> str:
        """Checked before any SSH attempt: a Spark firewall's assigned set
        isn't guaranteed to carry an expert password just because the
        Spark credential modal enforces it at creation time — a set could
        have been reassigned since. Missing it is a config problem, not a
        connectivity one, so this fails without ever opening a connection."""
        cred = bundle.get(CredentialKind.EXPERT_PASSWORD)
        if cred is None:
            raise CredentialError(
                f"the credential set assigned to {host.name!r} has no expert-mode "
                "password — edit it on the Provisioning tab"
            )
        return cred.reveal()

    def _connect(
        self, connector: HostConnector, host: Host, bundle: CredentialBundle
    ) -> ExpertCapableTransport:
        return cast(ExpertCapableTransport, connector.connect(host, bundle))

    # -- test_credentials -------------------------------------------------------------

    def _do_test_credentials(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.spark_firewall_host(ctx.job.target or "")
        bundle = self._resolve_bundle(connector, host, ctx)
        expert_password = self._require_expert_password(bundle, host, ctx)  # no SSH before this

        ctx.log(f"connecting over SSH to {host.name}")
        client = self._connect(connector, host, bundle)
        try:
            ctx.log("SSH login succeeded")
            shell = client.open_interactive_shell()
            try:
                session = GaiaExpertSession(shell)
                try:
                    session.enter_expert(expert_password)
                except ExpertModeError:
                    ctx.log("expert-mode password was rejected", level="error")
                    raise
                ctx.log("expert mode entered successfully")
                session.exit_expert()
            finally:
                _safe_close(shell)
        finally:
            _safe_close(client)

    # -- transfer_upgrade -------------------------------------------------------------

    def _do_transfer_upgrade(self, ctx: JobContext) -> None:
        connector = self.registry.get(ctx.job.environment)
        host = connector.spark_firewall_host(ctx.job.target or "")
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        expected_sha1 = self._packages.get(package).sha1
        remote_path = posixpath.join(_STORAGE_DIR, package)

        bundle = self._resolve_bundle(connector, host, ctx)
        expert_password = self._require_expert_password(bundle, host, ctx)  # no SSH before this

        self._enable_bash_user(connector, host, bundle, expert_password, ctx)
        self._transfer_image(
            connector, host, bundle, local_path, local_size, expected_sha1, remote_path, ctx
        )
        self._run_upgrade(connector, host, bundle, expert_password, remote_path, ctx)

        ctx.log(
            "upgrade command issued — the firewall is expected to reboot on its own within "
            "1-2 minutes; this job does not and cannot confirm the upgrade's outcome, use "
            "Refresh to check post-reboot state once it's back up",
            level="warning",
        )

    def _enable_bash_user(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        expert_password: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (phase 1: enabling SCP transfer)")
        client = self._connect(connector, host, bundle)
        try:
            shell = client.open_interactive_shell()
            try:
                session = GaiaExpertSession(shell)
                session.enter_expert(expert_password)
                ctx.raise_if_cancelled()  # last safe stop before mutating device state
                output = session.run_expert("bashUser on")
                if output:
                    ctx.log(f"bashUser on output:\n{output}")
                session.exit_expert()
            finally:
                _safe_close(shell)
        finally:
            _safe_close(client)
        # Full logout between enabling bashUser and the file transfer, not just
        # exiting expert mode — some Gaia Embedded builds only pick up the new
        # bashUser state on a fresh session (operator-specified sequence).
        ctx.log("logging out before file transfer (full session boundary)")

    def _transfer_image(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        local_path: Path,
        local_size: int,
        expected_sha1: str,
        remote_path: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (phase 2: transferring the firmware image)")
        client = self._connect(connector, host, bundle)
        try:
            filename = posixpath.basename(remote_path)
            ctx.log(f"uploading {filename} ({local_size} bytes) to {host.name}:{remote_path}")
            reporter = ProgressReporter(ctx, local_size)
            remote_size = client.put(str(local_path), remote_path, progress=reporter)
            verify_uploaded_file(
                client,
                remote_path,
                remote_size=remote_size,
                expected_size=local_size,
                expected_sha1=expected_sha1,
                ctx=ctx,
            )
        finally:
            _safe_close(client)
        ctx.log("logging out before the upgrade phase (full session boundary)")

    def _run_upgrade(
        self,
        connector: HostConnector,
        host: Host,
        bundle: CredentialBundle,
        expert_password: str,
        remote_path: str,
        ctx: JobContext,
    ) -> None:
        ctx.log(f"connecting over SSH to {host.name} (phase 3: running the upgrade)")
        client = self._connect(connector, host, bundle)
        shell = None
        try:
            shell = client.open_interactive_shell()
            session = GaiaExpertSession(shell)
            session.enter_expert(expert_password)
            # LAST safe stop — the upgrade command below cannot be undone or
            # cancelled once issued.
            ctx.raise_if_cancelled()
            output = session.run_expert("bashUser off")
            if output:
                ctx.log(f"bashUser off output:\n{output}")
            upgrade_cmd = f"upgrade_revert_image.sh {remote_path} upgrade safe"
            ctx.log(
                f"starting upgrade: {upgrade_cmd} — the firewall will reboot on its own "
                "in ~1-2 minutes; this job cannot wait for that"
            )
            try:
                output = session.run_expert(upgrade_cmd, timeout=_UPGRADE_TIMEOUT)
                if output:
                    ctx.log(f"upgrade command output:\n{output}")
            except TransportError as exc:
                # Expected outcome, not a failure: the device may drop the
                # connection mid-response as it begins rebooting.
                ctx.log(
                    "connection dropped while waiting for upgrade_revert_image.sh output "
                    f"— expected if the device began rebooting immediately: {exc}",
                    level="warning",
                )
        finally:
            if shell is not None:
                _safe_close(shell)
            _safe_close(client)
