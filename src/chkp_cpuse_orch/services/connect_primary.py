"""Connect to a primary management server over SSH and provision Management API
access on it — the automated replacement for the old "paste these into expert
mode" step (see the command builders in ``provisioning.py``).

Mirrors ``PatchingService``'s shape (registry + vault + runner + store), kept
separate from ``prov_ops.py`` (plain server/firewall add/edit/delete CRUD)
because this handler owns SSH execution and secret handling. The upsert of the
server's inventory row happens synchronously in ``submit_connect_primary`` —
cheap local DB write, so a bad role/name collision surfaces immediately rather
than as a failed job — before the SSH-borne job itself is enqueued.

The generated API key is never written anywhere persisted: not ``ctx.log``,
not a raised exception's message (which ends up on ``JobRecord.error``), not
structlog. It lives only in local variables during the job, then in this
service's in-process, pop-once ``_ApiKeyReveal`` map, read exactly once by the
web layer's reveal endpoint.

This job creates the administrator/API key but doesn't itself confirm the
Management API is actually *reachable* — its ``accessibility`` setting might
still be scoped to ``require-local``. The web UI checks that separately,
automatically, right after this job succeeds (see services/api_access.py).
"""

from __future__ import annotations

import asyncio
import threading

from ..credentials import CredentialBundle, CredentialStore, JobCredentialVault
from ..errors import OrchestratorError, StoreError
from ..jobs import JobContext, JobRunner
from ..store import JobRecord, Store
from ..transport.ssh import require_ok
from .common import EnvironmentRegistry, job_run_credentials, submit_host_job
from .environments import EnvironmentManager
from .provisioning import (
    parse_api_key_from_add_api_key_output,
    render_add_administrator_command,
    render_add_api_key_command,
    render_mgmt_login_command,
    render_publish_logout_commands,
    render_show_administrator_command,
)

JOB_CONNECT_PRIMARY = "prov.connect_primary"

__all__ = ["JOB_CONNECT_PRIMARY", "PrimaryConnectService"]


class _ApiKeyReveal:
    """One-time-read store for a job's captured API key: plain in-process
    memory, never persisted to disk. Mirrors ``JobCredentialVault``'s shape but
    for job *output* rather than input credentials."""

    def __init__(self) -> None:
        self._by_job: dict[str, str] = {}
        self._lock = threading.Lock()

    def put(self, job_id: str, api_key: str) -> None:
        with self._lock:
            self._by_job[job_id] = api_key

    def pop(self, job_id: str) -> str | None:
        """Return and discard the key, or None if there isn't one (never
        generated, already consumed, or the job failed)."""
        with self._lock:
            return self._by_job.pop(job_id, None)


class PrimaryConnectService:
    """Upserts a primary management server into inventory, then SSHes in to
    create (or verify) its Management API administrator and issue a fresh API
    key — re-runnable at any time to regenerate a key for the same admin."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        env_manager: EnvironmentManager,
        credentials: CredentialStore | None,
        vault: JobCredentialVault,
        runner: JobRunner,
        store: Store,
    ) -> None:
        self.runner = runner
        self._registry = registry
        self._env_manager = env_manager
        self._credentials = credentials
        self._vault = vault
        self._store = store
        self._reveal = _ApiKeyReveal()
        runner.register(JOB_CONNECT_PRIMARY, self._connect_job)

    def submit_connect_primary(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int,
        credential_set: str | None,
        is_mds: bool,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        self._env_manager.add_server(
            environment,
            name=name,
            address=address,
            role=role,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
        )
        if credential_set is not None:
            self._env_manager.assign_credential(environment, name, credential_set)
        # Re-fetch after add_server/assign_credential: both rebuild the
        # registry, so any connector/Host fetched beforehand would be stale.
        connector = self._registry.get(environment)
        host = connector.mgmt_host(name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_CONNECT_PRIMARY,
            params={
                "username": ssh_user,
                "is_mds": is_mds,
                "credential_set": credential_set,
            },
            credentials=credentials,
            triggered_by=triggered_by,
        )

    def reveal_api_key(self, job_id: str) -> str | None:
        """Pop-once read of a completed connect-primary job's captured key."""
        try:
            job = self._store.get_job(job_id)
        except StoreError:
            return None
        if job.kind != JOB_CONNECT_PRIMARY:
            return None
        return self._reveal.pop(job_id)

    # -- job handler --------------------------------------------------------------

    async def _connect_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_connect, ctx)

    def _do_connect(self, ctx: JobContext) -> None:
        environment = ctx.job.environment
        name = ctx.job.target
        assert name is not None
        connector = self._registry.get(environment)
        host = connector.mgmt_host(name)
        username = str(ctx.job.params["username"])
        is_mds = bool(ctx.job.params["is_mds"])
        credential_set = ctx.job.params.get("credential_set")

        creds = job_run_credentials(connector, self._vault, ctx.job)
        client = connector.connect(host, creds)
        try:
            ctx.log(f"connected to {host.name} ({host.address}) over SSH")
            require_ok(client.run(render_mgmt_login_command(is_mds=is_mds)))

            # NOT YET CONFIRMED against live gear: whether a not-found
            # administrator makes this command exit non-zero or return a JSON
            # error body with exit 0 — either is treated as "doesn't exist
            # yet" for now (see render_show_administrator_command).
            probe = client.run(render_show_administrator_command(username))
            if probe.ok:
                ctx.log(
                    f"Management API administrator {username!r} already exists — "
                    "issuing a new API key"
                )
            else:
                require_ok(client.run(render_add_administrator_command(username, is_mds=is_mds)))
                ctx.log(f"created Management API administrator {username!r}")

            key_result = require_ok(client.run(render_add_api_key_command(username)))
            api_key = parse_api_key_from_add_api_key_output(key_result.stdout)

            for cmd in render_publish_logout_commands():
                require_ok(client.run(cmd))
            ctx.log("published changes and logged out")
        finally:
            client.close()

        if credential_set is not None and self._credentials is not None:
            try:
                self._credentials.put_set(environment, str(credential_set), api_key=api_key)
                ctx.log(f"saved the new API key to credential set {credential_set!r}")
            except OrchestratorError as exc:
                # Best-effort: the key is still recoverable via reveal_api_key
                # below, so a save failure here is a warning, not a job failure.
                # Never include the key itself in this message.
                ctx.log(
                    f"could not save API key to credential set {credential_set!r}: {exc}",
                    level="warning",
                )
        self._reveal.put(ctx.job.id, api_key)
