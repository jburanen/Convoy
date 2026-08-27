"""Connect an environment to its Smart-1 Cloud tenant.

Smart-1 Cloud is Check Point's hosted management: the management server is
theirs, not the operator's, and there is no SSH, no expert mode, no CPUSE and no
file system to reach. Everything this tool does against such an environment's
management plane goes through the Management API, and the whole connection is
three facts the operator copies off one screen (Smart-1 Cloud → Settings → API &
SmartConsole):

* the **maas URL prefix** — the tenant's subdomain of ``maas.checkpoint.com``
* the **tenant UUID** — the path segment before ``/web_api``
* the **Management API key** — what ``{"api-key": ...}`` logs in with

Together those are the login URL that screen shows::

    https://<prefix>.maas.checkpoint.com/<tenant-uuid>/web_api/login

Deliberately NOT a new kind of object: the tenant is stored as this
environment's one management server (``env_hosts``, with the UUID in
``mgmt_api_context`` — migration v29) and the key as an ordinary credential set
assigned to it. Discovery, package repository pushes and every other Management
API caller then work unchanged, because what they need — a ``Host`` and an API
key — is exactly what they get. The only thing that had to learn about S1C is
the URL builder in ``transport/mgmt_api.py``.

Runs **synchronously**, like credential CRUD (services/cred_ops.py): one HTTPS
login and two local DB writes, with nothing to wait on a device for. Each call
still records a terminal ``JobRecord`` for Jobs-tab visibility and audit
history. The API key passes straight through this call stack into the encrypted
credential row — never into ``JobRecord.params``, which is persisted as plain
JSON and later archived to a flat file.

The credentials are proven before anything is stored: a wrong key or a mistyped
tenant leaves no half-configured server row behind to confuse the next job.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..credentials import CredentialStore
from ..errors import CredentialError, InventoryError, OrchestratorError
from ..inventory import Host, Role
from ..reporting import get_logger
from ..store import JobRecord, JobStatus, Store, utcnow
from ..transport.mgmt_api import ManagementAPIClient
from .common import EnvironmentRegistry
from .environments import EnvironmentManager

logger = get_logger(__name__)

JOB_CONNECT_S1C = "prov.connect_s1c"

# Every Smart-1 Cloud tenant is a subdomain of this one Check Point domain, so
# the operator copies a prefix and we build the host. A prefix that already
# carries dots is taken as a full hostname instead — see normalize_maas_host.
MAAS_DOMAIN = "maas.checkpoint.com"

# The tenant is the environment's only management server, so its row and its
# credential set are named for what they are rather than by the operator. One
# fewer field to fill in on a panel whose whole point is that there is exactly
# one of these per environment.
S1C_SERVER_NAME = "smart-1-cloud"
S1C_CREDENTIAL_SET = "smart-1-cloud"

__all__ = [
    "JOB_CONNECT_S1C",
    "MAAS_DOMAIN",
    "S1C_CREDENTIAL_SET",
    "S1C_SERVER_NAME",
    "Smart1CloudConnection",
    "Smart1CloudService",
    "normalize_maas_host",
]


class _LoginClient(Protocol):
    """The slice of ManagementAPIClient this service uses — logging in and out
    IS the connection test, so there is no command to call."""

    def __enter__(self) -> Any: ...
    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None: ...


def _default_mgmt_client_factory(host: Host, **kwargs: Any) -> _LoginClient:
    return ManagementAPIClient(host, **kwargs)


def normalize_maas_host(value: str) -> str:
    """Turn what the operator pasted into the tenant's hostname.

    The Settings screen shows a whole login URL, so the prefix may well arrive
    as ``tenant-abc123``, ``tenant-abc123.maas.checkpoint.com``, or the full
    ``https://tenant-abc123.maas.checkpoint.com/<uuid>/web_api/login``. All
    three mean the same host and all three are accepted; anything already
    carrying a dot is trusted as a complete hostname, so a tenant on some other
    Check Point domain is not silently rewritten to maas.checkpoint.com.
    """
    text = value.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]  # drop any path
    text = text.split("@")[-1]  # drop any userinfo
    text = text.split(":", 1)[0]  # drop any port
    text = text.strip().strip(".")
    if not text:
        raise InventoryError("enter the Smart-1 Cloud maas URL prefix")
    return text if "." in text else f"{text}.{MAAS_DOMAIN}"


@dataclass(frozen=True)
class Smart1CloudConnection:
    """What the Provisioning tab's Smart-1 Cloud panel shows. Secret-free."""

    name: str
    maas_host: str
    tenant_uuid: str
    credential_set: str | None
    has_api_key: bool

    @property
    def login_url(self) -> str:
        """The same URL the tenant's own Settings screen prints, so an operator
        can eyeball it against the portal without decoding two fields."""
        return f"https://{self.maas_host}/{self.tenant_uuid}/web_api/login"


class Smart1CloudService:
    """Stores and verifies an environment's Smart-1 Cloud connection."""

    def __init__(
        self,
        *,
        registry: EnvironmentRegistry,
        env_manager: EnvironmentManager,
        credentials: CredentialStore | None,
        store: Store,
        mgmt_client_factory: Any = None,
    ) -> None:
        self._registry = registry
        self._env_manager = env_manager
        self._credentials = credentials
        self._store = store
        self._mgmt_client_factory = mgmt_client_factory or _default_mgmt_client_factory

    # -- read -------------------------------------------------------------------

    def connection(self, environment: str) -> Smart1CloudConnection | None:
        """The environment's stored tenant, or None if it has never connected."""
        for row in self._env_manager.list_servers(environment):
            if not row.mgmt_api_context:
                continue
            set_name: str | None = None
            has_api_key = False
            if row.credential_set_id is not None:
                cred_row = self._store.get_credential_set(row.credential_set_id)
                if cred_row is not None:
                    set_name = cred_row.name
                    if self._credentials is not None:
                        info = self._credentials.get_info(environment, cred_row.name)
                        has_api_key = info is not None and info.has_api
            return Smart1CloudConnection(
                name=row.name,
                maas_host=row.address,
                tenant_uuid=row.mgmt_api_context,
                credential_set=set_name,
                has_api_key=has_api_key,
            )
        return None

    # -- write ------------------------------------------------------------------

    def submit_connect(
        self,
        environment: str,
        *,
        maas_prefix: str,
        tenant_uuid: str,
        api_key: str,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """Verify the three facts against the tenant, then store them.

        Raises before any job is recorded when the request can't be attempted at
        all (wrong environment type, no credential storage, malformed input) —
        those are the operator's own form to fix, not a failed operation worth
        an audit row. Anything that happens once we start talking to Check Point
        is recorded on the job, success or failure.
        """
        connector = self._registry.get(environment)
        if not connector.api_only:
            raise InventoryError(
                f"environment {environment!r} is not a Smart-1 Cloud environment — set its "
                "type to Smart-1 Cloud in Manage environments first"
            )
        if self._credentials is None or not connector.credential_storage_enabled:
            raise CredentialError(
                "Smart-1 Cloud needs encrypted credential storage enabled for this "
                "environment — the Management API key is the only way to reach the tenant, "
                "so there is nothing to connect with unless it can be stored"
            )
        if not api_key.strip():
            raise CredentialError("enter the tenant's Management API key")

        host = self._build_host(maas_prefix, tenant_uuid)
        job = self._start(
            JOB_CONNECT_S1C,
            target=host.address,
            environment=environment,
            # Secret-free by construction: the key is a local variable from here
            # to the encrypted row. Params are persisted as plain JSON.
            params={"maas_host": host.address, "tenant_uuid": host.mgmt_api_context},
            triggered_by=triggered_by,
        )
        try:
            self._verify(host, api_key, job)
            self._persist(environment, host, api_key, job)
            self._succeed(
                job,
                f"connected to Smart-1 Cloud tenant at {host.address} — stored as management "
                f"server {host.name!r} with credential set {S1C_CREDENTIAL_SET!r}",
            )
        except Exception as exc:  # job boundary: record failure, don't raise
            self._fail(job, exc)
        return self._store.get_job(job.id)

    # -- internals --------------------------------------------------------------

    def _build_host(self, maas_prefix: str, tenant_uuid: str) -> Host:
        """Validate the operator's two identifiers through the Host model, which
        is what rejects a URL-shaped address or a context path that could point
        the API somewhere other than the tenant."""
        address = normalize_maas_host(maas_prefix)
        try:
            return Host(
                name=S1C_SERVER_NAME,
                address=address,
                role=Role.PRIMARY_SMS,
                mgmt_api_context=tenant_uuid,
            )
        except ValueError as exc:
            raise InventoryError(f"invalid Smart-1 Cloud connection details: {exc}") from exc

    def _verify(self, host: Host, api_key: str, job: JobRecord) -> None:
        connection = Smart1CloudConnection(
            name=host.name,
            maas_host=host.address,
            tenant_uuid=host.mgmt_api_context or "",
            credential_set=None,
            has_api_key=True,
        )
        self._store.append_event(job.id, f"logging in to {connection.login_url}")
        # Entering the client logs in and leaving it logs out; a session that
        # opens and closes cleanly is the whole proof, and read_only keeps it
        # from taking the tenant's global write lock while it does.
        with self._mgmt_client_factory(host, api_key=api_key, read_only=True):
            self._store.append_event(job.id, "Management API login succeeded")

    def _persist(self, environment: str, host: Host, api_key: str, job: JobRecord) -> None:
        if self._credentials is None:  # pragma: no cover - guarded in submit_connect
            raise CredentialError("credential storage is not available")
        self._credentials.put_set(environment, S1C_CREDENTIAL_SET, api_key=api_key)
        self._store.append_event(
            job.id, f"stored the API key as credential set {S1C_CREDENTIAL_SET!r}"
        )
        self._env_manager.add_server(
            environment,
            name=host.name,
            address=host.address,
            role=host.role.value,
            ssh_user=host.ssh_user,
            mgmt_api_context=host.mgmt_api_context,
            notes="Smart-1 Cloud tenant — Management API only, no SSH",
        )
        self._env_manager.assign_credential(environment, host.name, S1C_CREDENTIAL_SET)
        self._store.append_event(job.id, f"registered management server {host.name!r}")

    def _start(
        self,
        kind: str,
        *,
        target: str,
        environment: str,
        params: dict[str, object],
        triggered_by: str | None,
    ) -> JobRecord:
        job = JobRecord(
            kind=kind,
            target=target,
            environment=environment,
            params=params,
            username=triggered_by,
            status=JobStatus.RUNNING,
            started_at=utcnow(),
        )
        self._store.insert_job(job)
        return job

    def _succeed(self, job: JobRecord, message: str) -> None:
        self._store.append_event(job.id, message)
        self._store.finish_job(job.id, JobStatus.SUCCEEDED)

    def _fail(self, job: JobRecord, exc: Exception) -> None:
        error = f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, OrchestratorError):
            logger.exception("smart-1 cloud connect failed", job_id=job.id)
        self._store.append_event(job.id, f"job failed: {error}", level="error")
        self._store.finish_job(job.id, JobStatus.FAILED, error=error)
