"""CDT service (the gateway-fleet subsystem), driven from a management server.

Operator flow the web UI exposes (see .claude/memory/cdt-cpuse-domain.md):

1. **stage**      — upload the package to the mgmt server + write the CDT config
                    XML (WHAT to deploy)
2. **generate**   — build the candidates CSV (WHERE to deploy)
3. *edit*         — fetch/reorder/trim candidates in the UI; row order is the
                    deployment order, i.e. the blast-radius control
4. **prepare**    — optional: front-load slow work before the window
5. **execute**    — the real deployment, under nohup on the server; we poll
                    ``CDT_status_brief.txt`` into job events until it finishes

Execute requires an explicit operator confirmation. Cancelling our *job* only
stops the polling — CDT keeps running on the server (logged loudly), because
killing a fleet deployment midway is more dangerous than letting it finish.
"""

from __future__ import annotations

import asyncio
import posixpath
import tempfile
import time
from pathlib import Path

from ..cdt import CDT, CandidatesFile, build_config_xml
from ..cpuse import DEFAULT_STAGING_DIR
from ..credentials import CredentialBundle, JobCredentialVault
from ..errors import CDTError, JobError, TransportError
from ..jobs import JobCancelled, JobContext, JobRunner
from ..packages import PackageStore
from ..store import JobRecord
from .common import EnvironmentRegistry, Transport, job_run_credentials, submit_host_job
from .patching import ProgressReporter

JOB_CDT_STAGE = "cdt.stage"
JOB_CDT_GENERATE = "cdt.generate"
JOB_CDT_PREPARE = "cdt.prepare"
JOB_CDT_EXECUTE = "cdt.execute"


class CDTService:
    """CDT operations on a management server, over the shared core."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        packages: PackageStore,
        runner: JobRunner,
        vault: JobCredentialVault,
        staging_dir: str = DEFAULT_STAGING_DIR,
        poll_interval: float = 15.0,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self._packages = packages
        self._vault = vault
        self._staging_dir = staging_dir
        self._poll_interval = poll_interval
        runner.register(JOB_CDT_STAGE, self._stage_job)
        runner.register(JOB_CDT_GENERATE, self._generate_job)
        runner.register(JOB_CDT_PREPARE, self._prepare_job)
        runner.register(JOB_CDT_EXECUTE, self._execute_job)

    # -- sync queries (blocking SSH; call via asyncio.to_thread from routes) -------

    def get_status(
        self, environment: str, host_name: str, *, credentials: CredentialBundle | None = None
    ) -> dict[str, object]:
        with self._query_session(environment, host_name, credentials) as s:
            status = s.cdt.status()
            return {
                "available": s.cdt.is_available(),
                "running": status.running,
                "brief": status.brief,
            }

    def get_candidates(
        self, environment: str, host_name: str, *, credentials: CredentialBundle | None = None
    ) -> CandidatesFile:
        with self._query_session(environment, host_name, credentials) as s:
            return s.cdt.read_candidates()

    def save_candidates(
        self,
        environment: str,
        host_name: str,
        candidates: CandidatesFile,
        *,
        credentials: CredentialBundle | None = None,
    ) -> int:
        """Push an edited candidates CSV back. Returns the row count. Refused
        while CDT is running — changing targets mid-deployment is never OK."""
        with self._query_session(environment, host_name, credentials) as s:
            if s.cdt.status().running:
                raise CDTError("CDT is currently running — refusing to change candidates")
            _put_text(s.transport, candidates.to_csv(), s.cdt.candidates_path)
            return len(candidates.rows)

    # -- job submission -------------------------------------------------------------

    def submit_stage(
        self,
        environment: str,
        host_name: str,
        package_filename: str,
        *,
        credentials: CredentialBundle | None = None,
    ) -> JobRecord:
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        self._packages.path_for(package_filename)  # validates record + content
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_CDT_STAGE,
            params={"package": package_filename},
            credentials=credentials,
        )

    def submit_generate(
        self, environment: str, host_name: str, *, credentials: CredentialBundle | None = None
    ) -> JobRecord:
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        return submit_host_job(
            self.runner, self._vault, connector, host, JOB_CDT_GENERATE, credentials=credentials
        )

    def submit_prepare(
        self,
        environment: str,
        host_name: str,
        *,
        extended: bool = False,
        credentials: CredentialBundle | None = None,
    ) -> JobRecord:
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        return submit_host_job(
            self.runner,
            self._vault,
            connector,
            host,
            JOB_CDT_PREPARE,
            params={"extended": extended},
            credentials=credentials,
        )

    def submit_execute(
        self,
        environment: str,
        host_name: str,
        *,
        confirmed: bool,
        credentials: CredentialBundle | None = None,
    ) -> JobRecord:
        """The real fleet deployment. ``confirmed`` must be True — this touches
        every gateway in the candidates list, in CSV order."""
        if not confirmed:
            raise JobError(
                "execute requires explicit confirmation — it deploys to every "
                "gateway in the candidates list"
            )
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        return submit_host_job(
            self.runner, self._vault, connector, host, JOB_CDT_EXECUTE, credentials=credentials
        )

    # -- job handlers ---------------------------------------------------------------

    async def _stage_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_stage, ctx)

    async def _generate_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_generate, ctx)

    async def _prepare_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_prepare, ctx)

    async def _execute_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_execute, ctx)

    def _do_stage(self, ctx: JobContext) -> None:
        package = str(ctx.job.params["package"])
        local_path = self._packages.path_for(package)
        local_size = local_path.stat().st_size
        remote_pkg = posixpath.join(self._staging_dir, package)

        with self._job_session(ctx.job) as s:
            existing = s.transport.run(f"stat -c %s {remote_pkg} 2>/dev/null")
            if existing.ok and existing.stdout.strip() == str(local_size):
                ctx.log(f"{package} already staged at {remote_pkg} (size matches) — skip upload")
            else:
                ctx.log(f"uploading {package} ({local_size} bytes) to {remote_pkg}")
                remote_size = s.transport.put(
                    str(local_path), remote_pkg, progress=ProgressReporter(ctx, local_size)
                )
                if remote_size != local_size:
                    raise TransportError(
                        f"size mismatch after upload: local {local_size}, remote {remote_size}"
                    )
                ctx.log("upload complete and size-verified")

            ctx.raise_if_cancelled()
            xml = build_config_xml(remote_pkg)
            _put_text(s.transport, xml, s.cdt.config_path)
            ctx.log(f"CDT config written to {s.cdt.config_path} (PackageToInstall={remote_pkg})")

    def _do_generate(self, ctx: JobContext) -> None:
        with self._job_session(ctx.job) as s:
            ctx.log("generating candidates CSV (CentralDeploymentTool -generate)")
            s.cdt.generate()
            candidates = s.cdt.read_candidates()
            ctx.log(
                f"generated {len(candidates.rows)} candidate(s) at {s.cdt.candidates_path} — "
                "review and order them before executing"
            )

    def _do_prepare(self, ctx: JobContext) -> None:
        extended = bool(ctx.job.params.get("extended", False))
        with self._job_session(ctx.job) as s:
            verb = "extended preparations" if extended else "preparations"
            ctx.log(f"running CDT {verb} (packages shipped to targets ahead of the window)")
            s.cdt.preparations(extended=extended)
            ctx.log(f"{verb} finished")

    def _do_execute(self, ctx: JobContext) -> None:
        with self._job_session(ctx.job) as s:
            candidates = s.cdt.read_candidates()  # also proves generate ran
            ctx.log(
                f"launching CDT execute for {len(candidates.rows)} candidate(s) "
                "under nohup — survives SSH drops"
            )
            s.cdt.start_execute()

            last_brief = ""
            try:
                while True:
                    time.sleep(self._poll_interval)
                    status = s.cdt.status()
                    if status.brief and status.brief != last_brief:
                        last_brief = status.brief
                        ctx.log(f"CDT status: {status.brief}")
                    if not status.running:
                        break
                    ctx.raise_if_cancelled()
            except JobCancelled:
                ctx.log(
                    "job cancelled — NOTE: CDT keeps running on the server; "
                    "watch CDT_status.txt there",
                    level="warning",
                )
                raise

            final = s.cdt.status()
            if final.looks_failed:
                raise CDTError(
                    "CDT finished but reported failures — review CDT_status.txt "
                    f"on {ctx.job.target}: {final.brief}"
                )
            ctx.log(f"CDT execute finished: {final.brief or 'no status text'}")

    # -- plumbing --------------------------------------------------------------------

    def _query_session(
        self, environment: str, host_name: str, credentials: CredentialBundle | None
    ) -> _CDTSession:
        """Session for a synchronous query. Credentials are validated and used
        one-shot (never stored) for storage-disabled environments."""
        connector = self.registry.get(environment)
        host = connector.mgmt_host(host_name)
        creds = connector.require_credentials(host, credentials)
        return _CDTSession(connector.connect(host, creds))

    def _job_session(self, job: JobRecord) -> _CDTSession:
        """Session for a running job: credentials come from the store (enabled)
        or the in-memory vault (disabled)."""
        connector = self.registry.get(job.environment)
        host = connector.mgmt_host(job.target or "")
        creds = job_run_credentials(connector, self._vault, job)
        return _CDTSession(connector.connect(host, creds))


def _put_text(transport: Transport, text: str, remote_path: str) -> None:
    """Write text content to a file on the server via a local temp file."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".tmp", delete=False, newline="\n", encoding="utf-8"
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    try:
        transport.put(str(tmp_path), remote_path)
    finally:
        tmp_path.unlink(missing_ok=True)


class _CDTSession:
    """Context manager pairing a connected transport with a CDT wrapper."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.cdt = CDT(transport)

    def __enter__(self) -> _CDTSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.transport.close()
