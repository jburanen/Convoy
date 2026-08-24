"""Push a stored package into the management server's own Package Repository,
via the Check Point Management API — the roadmap's "upload a stored package to
the smartconsole packages repo using mgmt api".

Confirmed against Check Point's official API reference: the real command,
``add-repository-package``, does **not** accept file bytes — it requires the
package to already exist at a path on the *management server's own
filesystem*, and returns a ``task-id`` to poll via ``show-task``. So this is a
two-step job: SFTP the file onto the primary management server (same
size-verified, resumable-by-reuse pattern as cdt_ops.py's stage step), then
call the API and poll the task to completion.

Genuinely slow (large-file SFTP + a server-side import) — unlike the rest of
the Packages tab's CRUD (services/pkgs_ops.py), which now runs synchronously,
this stays a tracked background job. Not part of services/discovery.py, whose
docstring states it "never writes" — a real architectural boundary this
respects by living in its own module.

Open question, to verify against live gear: whether ``add-repository-package``
needs a ``publish`` call afterward. Task-based commands (like
``install-policy``) normally don't, unlike object CRUD — assumed here; a wrong
assumption surfaces as a clear task-failure error, not a silent false success.
"""

from __future__ import annotations

import asyncio
import posixpath
import time
from collections.abc import Callable
from types import TracebackType
from typing import Any, Protocol

from ..cpuse import DEFAULT_STAGING_DIR
from ..credentials import CredentialBundle, JobCredentialVault
from ..errors import TransportError
from ..inventory import Host
from ..jobs import JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord
from ..transport.mgmt_api import ManagementAPIClient
from .common import (
    EnvironmentRegistry,
    HostConnector,
    api_auth,
    job_run_credentials,
    submit_host_job,
)
from .patching import ProgressReporter

JOB_PKG_PUSH_TO_REPO = "pkgs.push_to_repo"

# Task statuses observed/documented for add-repository-package's show-task
# polling. Check Point's own extracted docs list two different, inconsistent
# enums for "status" on this command — treat this as the authoritative set and
# fall back to "still running" for anything else, rather than trust it's
# exhaustive.
_TASK_SUCCESS = {"succeeded", "succeeded with warnings"}
_TASK_FAILURE = {"failed", "partially succeeded", "aborted", "timed out", "verification_failed"}


class _RepoClient(Protocol):
    """The slice of ManagementAPIClient this job uses (as a context manager)."""

    def __enter__(self) -> Any: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
    def add_repository_package(self, name: str, path: str, *, source: str = ...) -> str: ...
    def show_task(self, task_id: str) -> dict[str, Any]: ...


RepoClientFactory = Callable[..., _RepoClient]


def _default_repo_client_factory(host: Host, **kwargs: Any) -> _RepoClient:
    return ManagementAPIClient(host, **kwargs)


class PackageRepoService:
    """Pushes a stored package onto the environment's primary management
    server and registers it in the Package Repository."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        packages: PackageStore,
        runner: JobRunner,
        vault: JobCredentialVault,
        mgmt_client_factory: RepoClientFactory | None = None,
        staging_dir: str = DEFAULT_STAGING_DIR,
        poll_interval: float = 5.0,
    ) -> None:
        self.registry = registry
        self._packages = packages
        self.runner = runner
        self._vault = vault
        self._mgmt_client_factory = mgmt_client_factory or _default_repo_client_factory
        self._staging_dir = staging_dir
        self._poll_interval = poll_interval
        runner.register(JOB_PKG_PUSH_TO_REPO, self._push_job)

    # -- job submission -----------------------------------------------------------

    def submit_push_to_repo(
        self,
        environment: str,
        package_filename: str,
        *,
        credentials: CredentialBundle | None = None,
        triggered_by: str | None = None,
    ) -> JobRecord:
        connector = self.registry.get(environment)
        host = connector.primary_mgmt_host()
        self._packages.path_for(package_filename)  # validates record + content up front
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_PKG_PUSH_TO_REPO,
            params={"package": package_filename},
            credentials=credentials,
            triggered_by=triggered_by,
            require_expert=True,  # `stat`/upload/cleanup are all bash-native
        )

    # -- job handler ---------------------------------------------------------------

    async def _push_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_push, ctx)

    def _do_push(self, ctx: JobContext) -> None:
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        remote_pkg = posixpath.join(self._staging_dir, package)

        connector = self.registry.get(ctx.job.environment)
        host = connector.mgmt_host(ctx.job.target or "")
        creds = job_run_credentials(connector, self._vault, ctx.job)
        # The transport `creds` may be None (storage-enabled: connect() resolves
        # from the store) but the Management API auth below always needs the
        # actual bundle, so resolve it explicitly in that case.
        api_creds = creds if creds is not None else connector.host_credentials(host)

        try:
            transport = connector.connect(host, creds)
            try:
                existing = transport.run_bash(f"stat -c %s {remote_pkg} 2>/dev/null")
                if existing.ok and existing.stdout.strip() == str(local_size):
                    ctx.log(
                        f"{package} already staged at {remote_pkg} (size matches) — skip upload"
                    )
                else:
                    ctx.log(f"uploading {package} ({local_size} bytes) to {host.name}:{remote_pkg}")
                    remote_size = transport.put(
                        str(local_path), remote_pkg, progress=ProgressReporter(ctx, local_size)
                    )
                    if remote_size != local_size:
                        raise TransportError(
                            f"size mismatch after upload: local {local_size}, remote {remote_size}"
                        )
                    ctx.log("upload complete and size-verified")
            finally:
                transport.close()

            ctx.raise_if_cancelled()

            auth = api_auth(api_creds)
            domain = "Global" if connector.is_mds else None
            with self._mgmt_client_factory(host, read_only=False, domain=domain, **auth) as client:
                ctx.log("calling Management API add-repository-package")
                # The API requires `path` to be a directory ending in "/" —
                # reject otherwise ("must ... end with the forward slash").
                repo_path = (
                    self._staging_dir
                    if self._staging_dir.endswith("/")
                    else self._staging_dir + "/"
                )
                task_id = client.add_repository_package(package, repo_path, source="local")
                ctx.log(f"repository task {task_id} submitted — polling for completion")
                self._poll_task(ctx, client, task_id)
        except Exception:
            self._cleanup_staged_package(ctx, connector, host, creds, remote_pkg)
            raise

    def _cleanup_staged_package(
        self,
        ctx: JobContext,
        connector: HostConnector,
        host: Host,
        creds: CredentialBundle | None,
        remote_pkg: str,
    ) -> None:
        """Best-effort removal of the remote staged package after a failed (or
        cancelled) push, so a retry doesn't inherit a stale or partially-written
        file. Never raises — this runs while another exception is already
        propagating."""
        try:
            transport = connector.connect(host, creds)
        except Exception as exc:
            ctx.log(
                f"cleanup: could not connect to remove staged {remote_pkg}: {exc}",
                level="warning",
            )
            return
        try:
            result = transport.run_bash(f"rm -f {remote_pkg}")
            if result.ok:
                ctx.log(f"cleanup: removed staged package {remote_pkg}")
            else:
                detail = (
                    result.stderr.strip() or result.stdout.strip() or f"exit {result.exit_status}"
                )
                ctx.log(
                    f"cleanup: failed to remove staged package {remote_pkg}: {detail}",
                    level="warning",
                )
        except Exception as exc:
            ctx.log(
                f"cleanup: failed to remove staged package {remote_pkg}: {exc}",
                level="warning",
            )
        finally:
            transport.close()

    def _poll_task(self, ctx: JobContext, client: _RepoClient, task_id: str) -> None:
        last_status = ""
        while True:
            time.sleep(self._poll_interval)
            task = client.show_task(task_id)
            status = str(task.get("status", "")).strip()
            if status != last_status:
                last_status = status
                pct = task.get("progress-percentage")
                suffix = f" ({pct}%)" if pct is not None else ""
                ctx.log(f"repository task status: {status or 'unknown'}{suffix}")
            if status.lower() in _TASK_SUCCESS:
                ctx.log("package added to the management server's repository")
                return
            if status.lower() in _TASK_FAILURE:
                raise TransportError(
                    f"add-repository-package task failed: {_task_detail(task) or status}"
                )
            ctx.raise_if_cancelled()


def _task_detail(task: dict[str, Any]) -> str:
    """Best-effort human-readable detail from a failed show-task response —
    the exact task-details shape isn't confirmed against live gear."""
    details = task.get("task-details")
    if isinstance(details, list) and details:
        first = details[0]
        if isinstance(first, dict):
            for key in ("statusDescription", "status-description", "description", "message"):
                value = first.get(key)
                if value:
                    return str(value)
    return ""
