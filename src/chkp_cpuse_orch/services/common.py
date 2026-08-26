"""Shared plumbing for service-core modules: how to reach a management server.

Both the CPUSE-local subsystem (patching.py) and the CDT subsystem (cdt_ops.py)
connect to management servers the same way: resolve the host from inventory,
require the SSH credential from the named credential set assigned to that server,
and open a transport via a swappable factory (tests inject fakes).
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from typing import Any, Protocol

from ..credentials import (
    Credential,
    CredentialBundle,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
    ensure_ssh_credential,
)
from ..errors import CredentialError, InventoryError, JobError, TransportError
from ..inventory import FIREWALL_ROLES, MANAGEMENT_PLANE_ROLES, Host, Inventory, Role
from ..jobs import JobContext, JobRunner
from ..store import JobRecord, JobStatus, Store, new_id
from ..transport.ssh import CommandResult, GaiaSession, GaiaShell

_MGMT_ROLES = MANAGEMENT_PLANE_ROLES
_FW_ROLES = FIREWALL_ROLES
# Any host this tool can drive through the CPUSE import/install lifecycle
# directly (management server or firewall) — CDT-only gateway fleets aren't
# stored here at all, so this gate never needs to exclude them separately.
# Spark firewalls (Gaia Embedded) are patchable directly too (operator-
# directed, 2026-08-18) — previously excluded here, see git history/
# .claude/memory/patching-web-design.md for the prior "not wired in yet"
# state and what changed.
_PATCHABLE_FW_ROLES = _FW_ROLES
_PATCHABLE_ROLES = _MGMT_ROLES + _PATCHABLE_FW_ROLES


class Transport(Protocol):
    """What an operation needs from a connection. ``GaiaSession`` satisfies
    it; tests substitute fakes."""

    @property
    def shell(self) -> GaiaShell: ...

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult: ...

    def run_bash(self, command: str, *, timeout: float | None = None) -> CommandResult: ...

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> int: ...

    def close(self) -> None: ...


ClientFactory = Callable[[Host, dict[CredentialKind, Credential]], Transport]


def default_client_factory(host: Host, creds: dict[CredentialKind, Credential]) -> Transport:
    key = creds.get(CredentialKind.SSH_PRIVATE_KEY)
    password = creds.get(CredentialKind.SSH_PASSWORD)
    expert = creds.get(CredentialKind.EXPERT_PASSWORD)
    # The credential's own username — from a stored credential set's
    # ssh_username, or an inline per-job credential's username — is the
    # single source of truth for SSH login once one is assigned; host.ssh_user
    # is only a fallback (storage-disabled hosts, or a credential with no
    # username attached). See .claude/memory/ssh-username-source-of-truth.md —
    # this used to always use host.ssh_user, which could silently diverge
    # from whichever credential set was actually assigned.
    cred = password or key
    return GaiaSession(
        host,
        username=cred.username if cred and cred.username else None,
        password=password.reveal() if password else None,
        private_key=key.reveal() if key else None,
        expert_password=expert.reveal() if expert else None,
    )


def require_expert_password(bundle: CredentialBundle, host: Host) -> str:
    """Checked before any SSH attempt that will need bash access on a Gaia
    host (CPUSE import/install/uninstall, CDT, the primary-connect
    bootstrap, every Spark job): a host's assigned credential set isn't
    guaranteed to carry an expert password just because the storage-side
    requirement exists now (older sets predate it; a set could have been
    reassigned) — missing it is a config problem, not a connectivity one, so
    this fails without ever opening a connection. Shared by every service
    that escalates to expert mode."""
    cred = bundle.get(CredentialKind.EXPERT_PASSWORD)
    if cred is None:
        raise CredentialError(
            f"the credential set assigned to {host.name!r} has no expert-mode password — "
            "edit it on the Provisioning tab"
        )
    return cred.reveal()


class HostConnector:
    """Inventory + credentials + factory → connected transports to mgmt servers.
    One connector per environment; credential lookups stay inside it."""

    def __init__(
        self,
        inventory: Inventory,
        credentials: CredentialStore | None,
        client_factory: ClientFactory | None = None,
        environment: str = "default",
        *,
        credential_storage_enabled: bool = True,
        is_mds: bool = False,
        api_only: bool = False,
    ) -> None:
        self.inventory = inventory
        self.environment = environment
        self.credential_storage_enabled = credential_storage_enabled
        # Declared once per environment (see services/environments.py) — an
        # environment is either an SMS estate or a Multi-Domain one, never both.
        # Command selection (e.g. discovery) reads this instead of guessing from
        # whichever host happens to be the primary.
        self.is_mds = is_mds
        # Declared once per environment, orthogonal to is_mds — this estate's
        # management server(s) are reachable ONLY via the Management API, never
        # SSH (e.g. a cloud/third-party-managed SMS the operator only has an
        # API key for). Enforced in require_ssh_credential()/connect() below;
        # never blocks firewalls, which are unrelated to mgmt reachability.
        self.api_only = api_only
        self._credentials = credentials
        self._client_factory = client_factory or default_client_factory

    def management_servers(self) -> list[Host]:
        return [h for role in _MGMT_ROLES for h in self.inventory.hosts_by_role(role)]

    def primary_mgmt_host(self) -> Host:
        """The environment's one primary management server (Primary SMS or
        Primary MDS). Environments are modeled as having exactly one — never a
        Primary SMS *and* a Primary MDS, and never more than one of either —
        so discovery flows resolve it automatically instead of asking the
        operator to pick a source server."""
        primaries = [
            h
            for role in (Role.PRIMARY_SMS, Role.PRIMARY_MDS)
            for h in self.inventory.hosts_by_role(role)
        ]
        if not primaries:
            raise InventoryError(
                f"environment {self.environment!r} has no Primary SMS or Primary MDS "
                "server configured — add one on the Provisioning tab"
            )
        return primaries[0]

    def mgmt_host(self, host_name: str) -> Host:
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role not in _MGMT_ROLES:
            raise InventoryError(
                f"host {host_name!r} is a {host.role.value}, not a management server — "
                "gateways are patched via CDT, not addressed directly"
            )
        return host

    def firewalls(self) -> list[Host]:
        return [h for role in _FW_ROLES for h in self.inventory.hosts_by_role(role)]

    def firewall_host(self, host_name: str) -> Host:
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role not in _FW_ROLES:
            raise InventoryError(f"host {host_name!r} is a {host.role.value}, not a firewall")
        return host

    def spark_firewall_host(self, host_name: str) -> Host:
        """Resolve a host that must specifically be a Spark (Gaia Embedded)
        firewall — stricter than patchable_host() (which accepts any
        CPUSE-patchable host, Spark included): the expert-mode SSH commands
        the Spark patching service issues are meaningless on a Gaia gateway
        or management server, so this fails closed rather than let a
        mis-targeted job run them there."""
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role != Role.SPARK_FIREWALL:
            raise InventoryError(f"host {host_name!r} is a {host.role.value}, not a Spark firewall")
        return host

    def patchable_host(self, host_name: str) -> Host:
        """Resolve any host this tool CPUSE-patches directly — management
        server or firewall (Spark/Gaia Embedded included). Used by
        PatchingService, which doesn't care which kind it's talking to."""
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.role not in _PATCHABLE_ROLES:
            raise InventoryError(
                f"host {host_name!r} is a {host.role.value}, which isn't patched directly"
            )
        return host

    def assigned_credential(self, host_name: str) -> str | None:
        """Name of the credential set assigned to a server (secret-free), or None.
        Always None for a storage-disabled environment — nothing is persisted."""
        if self._credentials is None or not self.credential_storage_enabled:
            return None
        host = self.inventory.host(host_name)  # raises InventoryError if unknown
        if host.credential_set_id is None:
            return None
        return self._credentials.set_name(host.credential_set_id)

    def _check_ssh_reachable(self, host: Host) -> None:
        """Refuse SSH to a management-plane host in an API-only environment —
        there is no SSH service account there to reach at all. Never applies
        to firewalls (patching them is unrelated to how the management server
        itself is reached). Called from both require_credentials()
        (submit-time rejection for every job-submitting service, storage
        enabled or not) and connect() (execution-time backstop for the direct
        callers that don't go through submit_host_job — connect_primary,
        api_access, pkg_repo_ops, and discovery's MDS-SSH peer scan, which
        already treats a CredentialError here as a soft warning rather than a
        hard failure)."""
        if self.api_only and host.role in _MGMT_ROLES:
            raise CredentialError(
                f"environment {self.environment!r} is API-only management access — "
                f"{host.name!r} has no SSH service account to connect to"
            )

    def require_ssh_credential(self, host: Host, *, require_expert: bool = False) -> None:
        creds = self.host_credentials(host)  # raises if unassigned / store locked
        if CredentialKind.SSH_PASSWORD not in creds and CredentialKind.SSH_PRIVATE_KEY not in creds:
            raise CredentialError(
                f"the credential set assigned to {host.name!r} has no SSH password or "
                "private key — edit the set on the Provisioning tab"
            )
        if require_expert:
            require_expert_password(creds, host)

    def require_credentials(
        self, host: Host, provided: CredentialBundle | None = None, *, require_expert: bool = False
    ) -> CredentialBundle | None:
        """Gate an SSH operation and decide the credential source.

        - storage enabled  → verify a stored SSH credential exists; return None,
          meaning ``connect`` resolves from the store.
        - storage disabled → validate the caller-``provided`` bundle and return
          it, to be passed straight to ``connect`` (never persisted).

        ``require_expert`` additionally requires an expert-mode password —
        set by callers submitting a job kind that will actually escalate to
        expert mode (CPUSE import/install/uninstall, CDT, the primary-connect
        bootstrap, Spark's jobs), not blanket-applied to every job (a plain
        clish-only Refresh never needs one). Storage-enabled environments
        already require an expert password on every credential set at save
        time (see ``credentials.py``'s ``put_set``), but a set saved before
        that requirement existed could still lack one — this is the
        pre-connect check that catches it with a clear error either way,
        rather than failing mid-job when ``GaiaSession`` actually tries to
        elevate."""
        self._check_ssh_reachable(host)
        if self.credential_storage_enabled:
            self.require_ssh_credential(host, require_expert=require_expert)
            return None
        bundle = provided or {}
        ensure_ssh_credential(bundle, host.name, self.environment)
        if require_expert and CredentialKind.EXPERT_PASSWORD not in bundle:
            raise CredentialError(
                f"an expert-mode password is required for this operation on {host.name!r} — "
                "this environment does not store credentials, supply one for this job"
            )
        return bundle

    def host_credentials(self, host: Host) -> CredentialBundle:
        if self._credentials is None:
            raise CredentialError(
                "credential store is locked — set the master key and restart the service"
            )
        if host.credential_set_id is None:
            raise CredentialError(
                f"no credential assigned to {host.name!r} in environment "
                f"{self.environment!r} — assign a credential set on the Management tab"
            )
        return self._credentials.get_set_bundle(host.credential_set_id, host.name)

    def connect(self, host: Host, creds: CredentialBundle | None = None) -> Transport:
        """Open a transport. ``creds`` supplies explicit credentials (storage-
        disabled path); when omitted they are resolved from the store."""
        self._check_ssh_reachable(host)
        if creds is None:
            if not self.credential_storage_enabled:
                raise CredentialError(
                    f"environment {self.environment!r} does not store credentials — "
                    "supply them for this operation"
                )
            creds = self.host_credentials(host)
        return self._client_factory(host, creds)


def submit_host_job(
    runner: JobRunner,
    vault: JobCredentialVault,
    connector: HostConnector,
    host: Host,
    kind: str,
    *,
    params: dict[str, object] | None = None,
    credentials: CredentialBundle | None = None,
    triggered_by: str | None = None,
    require_expert: bool = False,
) -> JobRecord:
    """Validate credentials for a host job and enqueue it. For storage-disabled
    environments the credentials are stashed in the vault under the job id
    *before* the job is submitted (so the runner can't start it first), and
    removed again if submission fails. ``triggered_by`` is the logged-in
    username, recorded on the job for the Jobs tab's User column/filter.
    ``require_expert`` is set by the caller for job kinds that will actually
    escalate to expert mode — see ``HostConnector.require_credentials``."""
    creds = connector.require_credentials(host, credentials, require_expert=require_expert)
    job_id = new_id()
    if creds is not None:
        vault.put(job_id, creds)
    try:
        return runner.submit(
            kind,
            target=host.name,
            params=params or {},
            environment=connector.environment,
            job_id=job_id,
            triggered_by=triggered_by,
        )
    except Exception:
        vault.discard(job_id)
        raise


def job_run_credentials(
    connector: HostConnector, vault: JobCredentialVault, job: JobRecord
) -> CredentialBundle | None:
    """Credentials a job handler should ``connect`` with: None (resolve from the
    store) when storage is enabled, else the vault bundle put there at submit."""
    if connector.credential_storage_enabled:
        return None
    return vault.require(job.id)


def ensure_host_free(store: Store, environment: str, host_name: str) -> None:
    """Refuse to start a new job while one is already pending/running for this
    host — two operations touching the same box's CPUSE/SSH (or, for Spark,
    expert-mode) state at once is unsafe. Mirrors the Firewalls/Management tab
    UI, which replaces a busy host's selection checkbox with a status glyph
    for the same reason (see app.js markRowIfJobActive) — this is the
    enforcement behind that, since a stale page or a direct API call could
    otherwise still race two jobs onto the same host. Scoped to the
    environment too — host names are only unique within one, not globally.
    Shared by every host-job-submitting service: PatchingService,
    SparkPatchingService, CDTService and PackageRepoService. The latter two
    skipped it until 2026-08-26 — which mattered most for CDT, where a stage
    can rewrite the shared candidates CSV underneath a running execute."""
    active = store.list_jobs(
        targets=[host_name],
        environments=[environment],
        statuses=[JobStatus.PENDING, JobStatus.RUNNING],
        limit=1,
    )
    if active:
        raise JobError(
            f"a job is already {active[0].status.value} for {host_name!r} — wait for it "
            "to finish before starting another"
        )


class ProgressReporter:
    """Paramiko progress callback that logs at ~10% steps, not every chunk.
    Shared by PatchingService's CPUSE import and SparkPatchingService's
    firmware-image transfer — both upload a large file over the same
    ``Transport.put()`` mechanism."""

    def __init__(self, ctx: JobContext, total: int) -> None:
        self._ctx = ctx
        self._total = max(total, 1)
        self._last_decile = 0

    def __call__(self, transferred: int, _total: int) -> None:
        decile = (transferred * 10) // self._total
        if decile > self._last_decile:
            self._last_decile = decile
            pct = min(decile * 10, 100)
            self._ctx.log(f"upload progress: {pct}%")
            # Also surfaces live in the Jobs tab's Output column (status_text —
            # see JobContext.set_status()) without opening the row's log, same
            # mechanism Spark install's "waiting for reboot"/"pinging" already uses.
            self._ctx.set_status(f"uploading: {pct}%")


def format_bytes(n: int) -> str:
    """Human-readable byte count for pre-check error/log messages. Shared by
    PatchingService's CPUSE import disk-space check and SparkPatchingService's
    /storage check."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def remote_free_bytes(client: Transport, path: str) -> int:
    """Available space on ``path``, via `df -Pk` (POSIX output format — one
    line per filesystem, immune to the line-wrapping long device names can
    cause in `df`'s default format). Shared by PatchingService's CPUSE import
    disk-space check and SparkPatchingService's /storage check."""
    result = client.run_bash(f"df -Pk {shlex.quote(path)}")
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TransportError(f"could not check disk space on {path}: {detail}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    fields = lines[-1].split() if lines else []
    if len(fields) < 4:
        raise TransportError(f"unexpected `df` output for {path}: {result.stdout!r}")
    try:
        available_kb = int(fields[3])
    except ValueError as exc:
        raise TransportError(f"unexpected `df` output for {path}: {result.stdout!r}") from exc
    return available_kb * 1024


def remote_sha1(client: Transport, remote_path: str) -> str:
    """sha1 of a just-uploaded file, computed on the host itself — catches a
    corrupted/truncated transfer before it's acted on (the size check alone
    wouldn't notice bit-level corruption). Shared by PatchingService and
    SparkPatchingService."""
    result = client.run_bash(f"sha1sum {remote_path}")
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TransportError(f"could not compute remote sha1 for {remote_path}: {detail}")
    digest = result.stdout.split()[0] if result.stdout.split() else ""
    if not digest:
        raise TransportError(f"unexpected `sha1sum` output for {remote_path}: {result.stdout!r}")
    return digest.lower()


def verify_uploaded_file(
    client: Transport,
    remote_path: str,
    *,
    remote_size: int,
    expected_size: int,
    expected_sha1: str,
    ctx: JobContext,
) -> None:
    """Fail closed on either a size mismatch (from the upload's own return
    value — the caller passes it in rather than re-stat'ing) or a host-side
    sha1 recompute mismatch, before the caller acts on the uploaded file.
    Shared by PatchingService's CPUSE import and SparkPatchingService's
    firmware-image transfer."""
    if remote_size != expected_size:
        raise TransportError(
            f"size mismatch after upload: local {expected_size}, remote {remote_size}"
        )
    ctx.log("upload complete and size-verified")
    ctx.log("verifying integrity of the uploaded copy")
    digest = remote_sha1(client, remote_path)
    if digest != expected_sha1.lower():
        raise TransportError(
            f"sha1 mismatch after upload: expected {expected_sha1}, "
            f"remote copy at {remote_path} hashes to {digest}"
        )
    ctx.log("sha1 verified — remote copy matches the stored file")


def api_auth(bundle: CredentialBundle) -> dict[str, Any]:
    """Build Management API auth kwargs from a credential bundle: prefer an API key,
    else the SSH username/password (the Gaia admin usually doubles as the API user)."""
    api_key_cred = bundle.get(CredentialKind.API_KEY)
    if api_key_cred is not None:
        return {"api_key": api_key_cred.reveal()}
    pw_cred = bundle.get(CredentialKind.SSH_PASSWORD)
    if pw_cred is not None and pw_cred.username:
        return {"username": pw_cred.username, "password": pw_cred.reveal()}
    raise CredentialError(
        "the credential set has no API key or username/password — add one on the Provisioning tab"
    )


class EnvironmentRegistry:
    """Named, independent management environments → their connectors.

    Mutable so the web UI can add/edit environments at runtime: services hold a
    long-lived reference and call ``get()`` per request, so a ``rebuild()`` from
    the database is seen immediately without reconstructing the services."""

    def __init__(self) -> None:
        self._envs: dict[str, HostConnector] = {}

    def add(self, name: str, connector: HostConnector) -> None:
        if name in self._envs:
            raise InventoryError(f"environment {name!r} registered twice")
        self._envs[name] = connector

    def rebuild(self, connectors: dict[str, HostConnector]) -> None:
        """Atomically replace all environments (after a DB mutation)."""
        self._envs = dict(connectors)

    def get(self, name: str) -> HostConnector:
        connector = self._envs.get(name)
        if connector is None:
            raise InventoryError(
                f"unknown environment: {name!r} (have: {', '.join(self._envs) or 'none'})"
            )
        return connector

    def names(self) -> list[str]:
        return list(self._envs)
