"""Check Point Management API client (thin).

Wraps the management server's ``web_api`` (the same surface ``mgmt_cli`` drives).
Used for management-plane facts the orchestrator needs around a deployment — today
its first real consumer is estate **discovery** (``show-gateways-and-servers``);
gateway policy status etc. remain TODOs below.

Kept deliberately thin per .claude/memory/architecture.md: it logs in, POSTs a
command, returns parsed JSON, logs out. All mapping/decision logic lives in the
service layer (services/discovery.py), never here.

Auth: an API key (preferred, from a credential set) or user/password. The session
id (``sid``) returned by ``login`` is sent as ``X-chkp-sid`` on every later call.

Sessions default read-only (``read_only=True``) — enough for discovery-style
reads and avoids taking a global write lock. Pass ``read_only=False`` for
commands that actually write (e.g. ``add_repository_package``, used by
services/pkg_repo_ops.py).

TLS: management servers present a self-signed certificate by default, so
``verify_tls`` defaults to ``False`` (with a logged note). Set it True when the
server presents a CA-trusted certificate.

Set ``CONVOY_LOG_API_CALLS`` to log every request/response through
``docker compose logs`` — off by default (this is every Management API call in
full, useful for troubleshooting but noisy). Payloads/bodies are redacted
(``_redact``) before logging so passwords/API keys/session ids never land in
the log, and logged at WARNING regardless of ``CONVOY_WEB_LOG_LEVEL`` so
turning this on is never silently neutered by the default log-level threshold.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from ..envcompat import compat_env
from ..errors import ManagementAPIForbidden, TransportError
from ..inventory import Host
from ..reporting import get_logger

logger = get_logger(__name__)

# Server-side default page size for list commands; we page until we've seen `total`.
_PAGE_LIMIT = 200

LOG_API_CALLS_ENV = "CONVOY_LOG_API_CALLS"

# Substrings marking a key whose value must be redacted before a payload or
# response body is logged. Matched as SUBSTRINGS, not exact keys: exact matching
# silently missed every compound name the API actually uses — "new-password",
# "password-hash", "api_key", "session-id" — and, worst, "script". The
# credential-bootstrap run-script payload carries the whole clish script
# including `set user <u> password-hash $6$...`, so with exact matching, turning
# on CONVOY_LOG_API_CALLS wrote a crackable hash of a gateway's admin
# password into `docker compose logs` at WARNING level.
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "api-key",
    "apikey",
    "api_key",
    "secret",
    "token",
    "hash",
    "script",
    # "sid" is the API's own session-id field; "session" also catches
    # session-id / session_id, which "sid" does not contain.
    "sid",
    "session",
)
_REDACTED = "***REDACTED***"

# Bounds on paging (see _paged_objects). Generous enough that no real estate
# reaches them; small enough that a hostile or broken server can't make this
# loop or allocate without limit.
_MAX_PAGES = 200
_MAX_OBJECTS = 50_000


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _log_api_calls_enabled() -> bool:
    raw = compat_env().get(LOG_API_CALLS_ENV, "")
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _redact(value: Any) -> Any:
    """Recursively replace sensitive values (see ``_SENSITIVE_KEY_PARTS``) so a
    logged payload/response body never carries a real secret."""
    if isinstance(value, dict):
        return {k: (_REDACTED if _is_sensitive_key(k) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class ManagementAPIClient:
    """Minimal Check Point Management API client (httpx-backed)."""

    def __init__(
        self,
        server: Host,
        *,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        port: int = 443,
        verify_tls: bool = False,
        read_only: bool = True,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key and not (username and password):
            raise TransportError("Management API needs an API key or a username/password to log in")
        self.server = server
        self._api_key = api_key
        self._username = username
        self._password = password
        # Multi-Domain Server login only: which Domain (CMA) or the "Global" domain
        # to log into. Ignored on a single-domain SMS.
        self._domain = domain
        self._base_url = f"https://{server.address}:{port}/web_api"
        self._verify_tls = verify_tls
        self._read_only = read_only
        self._timeout = timeout
        self._transport = transport  # tests inject an httpx.MockTransport
        self._sid: str | None = None
        self._client: httpx.Client | None = None

    # -- context manager ---------------------------------------------------------

    def __enter__(self) -> ManagementAPIClient:
        self.login()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.logout()

    # -- session -----------------------------------------------------------------

    def login(self) -> None:
        if not self._verify_tls:
            # Warning, not debug: this is a standing security posture the
            # operator has accepted (see .claude/memory/security-review-2026-08.md),
            # and a posture nobody can see is one nobody can reconsider.
            logger.warning(
                "mgmt-api: TLS verification disabled — API key and admin password "
                "cross the network without certificate verification",
                server=self.server.address,
            )
        self._client = httpx.Client(
            base_url=self._base_url,
            verify=self._verify_tls,
            timeout=self._timeout,
            headers={"Content-Type": "application/json"},
            transport=self._transport,
        )
        payload: dict[str, Any] = (
            {"api-key": self._api_key}
            if self._api_key
            else {"user": self._username, "password": self._password}
        )
        payload["read-only"] = self._read_only
        if self._domain is not None:
            payload["domain"] = self._domain
        data = self._post("login", payload, authed=False)
        sid = data.get("sid")
        if not isinstance(sid, str) or not sid:
            raise TransportError("Management API login returned no session id")
        self._sid = sid

    def logout(self) -> None:
        # Best-effort: a failed logout must never mask the caller's real result.
        if self._client is None:
            return
        try:
            if self._sid is not None:
                self._post("logout", {})
        except TransportError as exc:
            logger.debug("mgmt-api: logout failed (ignored)", error=str(exc))
        finally:
            self._sid = None
            self._client.close()
            self._client = None

    # -- commands ----------------------------------------------------------------

    def _paged_objects(self, command: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Page through a ``show-*`` command's ``objects`` list, bounded.

        The management server is the far end of an unverified TLS connection
        (see verify_tls) and its ``total`` is just a number in a response body,
        so nothing here treats it as trustworthy: a non-numeric total is an
        error rather than an unhandled ValueError, page count and object count
        are both capped, and a page that fails to advance the offset ends the
        loop instead of spinning on it forever."""
        objects: list[dict[str, Any]] = []
        offset = 0
        for _page in range(_MAX_PAGES):
            data = self._post(command, {**payload, "limit": _PAGE_LIMIT, "offset": offset})
            batch = data.get("objects") or []
            objects.extend(batch)
            if len(objects) > _MAX_OBJECTS:
                raise TransportError(
                    f"{command} returned more than {_MAX_OBJECTS} objects — refusing to "
                    "keep paging; this is far beyond any real estate size"
                )
            raw_total = data.get("total", len(objects))
            try:
                total = int(raw_total)
            except (TypeError, ValueError) as exc:
                raise TransportError(
                    f"{command} returned a non-numeric 'total': {raw_total!r}"
                ) from exc
            if not batch:  # no progress possible
                break
            offset += len(batch)
            if offset >= total:
                break
        else:
            raise TransportError(
                f"{command} did not finish paging within {_MAX_PAGES} pages — refusing "
                "to keep going"
            )
        return objects

    def show_gateways_and_servers(self, *, details_level: str = "full") -> list[dict[str, Any]]:
        """Return every gateway/server object the management database knows about.

        Pages through the result set (``show-gateways-and-servers`` caps each page)
        and returns the concatenated ``objects`` list untouched — mapping object
        types to roles is the service layer's job."""
        return self._paged_objects("show-gateways-and-servers", {"details-level": details_level})

    def show_simple_clusters(self, *, details_level: str = "full") -> list[dict[str, Any]]:
        """Return every ClusterXL/VRRP cluster object the management database
        knows about, each with its ``members`` list — used to resolve a
        gateway's real cluster object name (the SmartConsole name, unlike the
        peer-hostname stand-in ``clusterxl.py`` builds from live `cphaprob`
        output). Paged the same way as ``show_gateways_and_servers``."""
        return self._paged_objects("show-simple-clusters", {"details-level": details_level})

    def show_domains(self) -> list[dict[str, Any]]:
        """Return every Domain (CMA) a Multi-Domain Server knows about.

        Only meaningful for a session logged into the MDS system context (no
        ``domain`` in the login payload) — ``show-domains`` operates above any
        single Domain/Global scope. Paged the same way as
        ``show_gateways_and_servers``."""
        objects: list[dict[str, Any]] = []
        offset = 0
        while True:
            data = self._post(
                "show-domains",
                {"limit": _PAGE_LIMIT, "offset": offset},
            )
            batch = data.get("objects") or []
            objects.extend(batch)
            total = int(data.get("total", len(objects)))
            offset += len(batch)
            if not batch or offset >= total:
                break
        return objects

    def add_repository_package(self, name: str, path: str, *, source: str = "local") -> str:
        """Register a package already sitting on the management server's own
        filesystem (at ``path``, a directory — ``name`` is the filename inside
        it) into the SmartConsole Package Repository. Note this does **not**
        upload bytes — the caller must get the file onto the server first
        (e.g. via ``Transport.put``, see services/pkg_repo_ops.py). Requires a
        write-capable (``read_only=False``) session. Returns a ``task-id`` to
        poll via ``show_task``."""
        data = self._post("add-repository-package", {"name": name, "path": path, "source": source})
        task_id = data.get("task-id")
        if not isinstance(task_id, str) or not task_id:
            raise TransportError("add-repository-package returned no task-id")
        return task_id

    def run_script(
        self, script: str, targets: list[str], *, script_name: str = "convoy-run"
    ) -> str:
        """Execute ``script`` (bash) on each of ``targets`` (gateway names)
        via SIC — no SSH needed. Returns a ``task-id`` to poll via
        ``show_task``.

        Requires a write-capable (``read_only=False``) session — this
        mutates the target(s). ``show-task``'s response shape was confirmed
        against live gear 2026-08-18 (see services/gateway_bootstrap.py) —
        but that verification used ``mgmt_cli``, which auto-polls and prints
        the *completed* task, not ``run-script``'s own immediate response.
        A live 2026-08-18 failure (``run-script returned no task-id``) showed
        the flat ``task-id`` key this shares with ``add-repository-package``
        is NOT what ``run-script`` itself returns — so this also tries the
        same nested ``tasks[0]["task-id"]`` shape ``show-task`` uses (the two
        commands share the same underlying task/notification mechanism).
        NOT YET CONFIRMED which of the two actually matches — if neither
        does, the raised error carries the raw response so the real shape
        can finally be read directly off a live failure."""
        data = self._post(
            "run-script",
            {"script-name": script_name, "script": script, "targets": targets},
        )
        task_id = data.get("task-id")
        if not isinstance(task_id, str) or not task_id:
            tasks = data.get("tasks")
            if isinstance(tasks, list) and tasks and isinstance(tasks[0], dict):
                nested = tasks[0].get("task-id")
                if isinstance(nested, str) and nested:
                    task_id = nested
        if not isinstance(task_id, str) or not task_id:
            raise TransportError(f"run-script returned no task-id: {data!r}")
        return task_id

    def show_task(self, task_id: str) -> dict[str, Any]:
        """Poll one async task's status/progress (e.g. from
        ``add_repository_package``)."""
        data = self._post("show-task", {"task-id": task_id})
        tasks = data.get("tasks") or []
        if not tasks:
            raise TransportError(f"show-task returned no tasks for {task_id}")
        result: dict[str, Any] = tasks[0]
        return result

    # -- transport ---------------------------------------------------------------

    def _post(
        self, command: str, payload: dict[str, Any], *, authed: bool = True
    ) -> dict[str, Any]:
        if self._client is None:
            raise TransportError("Management API client is not logged in")
        headers = {"X-chkp-sid": self._sid} if authed and self._sid else {}
        log_calls = _log_api_calls_enabled()
        if log_calls:
            logger.warning(
                "mgmt-api request",
                server=self.server.address,
                command=command,
                payload=_redact(payload),
            )
        try:
            resp = self._client.post(f"/{command}", json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(
                f"Management API {command} unreachable at {self.server.address}: {exc}"
            ) from exc
        if resp.status_code != httpx.codes.OK:
            # The API returns a JSON body with 'message'/'code' on error.
            message = _error_message(resp)
            if resp.status_code == httpx.codes.FORBIDDEN:
                raise ManagementAPIForbidden(
                    f"Management API {command} failed: HTTP 403 Forbidden ({message})"
                )
            raise TransportError(f"Management API {command} failed: {message}")
        try:
            body: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise TransportError(f"Management API {command} returned invalid JSON") from exc
        if log_calls:
            logger.warning(
                "mgmt-api response",
                server=self.server.address,
                command=command,
                status=resp.status_code,
                body=_redact(body),
            )
        return body


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}"
    msg = body.get("message") or body.get("code") or f"HTTP {resp.status_code}"
    return str(msg)
