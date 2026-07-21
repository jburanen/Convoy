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

TLS: management servers present a self-signed certificate by default, so
``verify_tls`` defaults to ``False`` (with a logged note). Set it True when the
server presents a CA-trusted certificate.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from ..errors import TransportError
from ..inventory import Host
from ..reporting import get_logger

logger = get_logger(__name__)

# Server-side default page size for list commands; we page until we've seen `total`.
_PAGE_LIMIT = 200


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
            logger.debug("mgmt-api: TLS verification disabled", server=self.server.address)
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
        # read-only is enough for discovery and avoids taking a global write lock.
        payload["read-only"] = True
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

    def show_gateways_and_servers(self, *, details_level: str = "full") -> list[dict[str, Any]]:
        """Return every gateway/server object the management database knows about.

        Pages through the result set (``show-gateways-and-servers`` caps each page)
        and returns the concatenated ``objects`` list untouched — mapping object
        types to roles is the service layer's job."""
        objects: list[dict[str, Any]] = []
        offset = 0
        while True:
            data = self._post(
                "show-gateways-and-servers",
                {"details-level": details_level, "limit": _PAGE_LIMIT, "offset": offset},
            )
            batch = data.get("objects") or []
            objects.extend(batch)
            total = int(data.get("total", len(objects)))
            offset += len(batch)
            if not batch or offset >= total:
                break
        return objects

    # -- transport ---------------------------------------------------------------

    def _post(
        self, command: str, payload: dict[str, Any], *, authed: bool = True
    ) -> dict[str, Any]:
        if self._client is None:
            raise TransportError("Management API client is not logged in")
        headers = {"X-chkp-sid": self._sid} if authed and self._sid else {}
        try:
            resp = self._client.post(f"/{command}", json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(
                f"Management API {command} unreachable at {self.server.address}: {exc}"
            ) from exc
        if resp.status_code != httpx.codes.OK:
            # The API returns a JSON body with 'message'/'code' on error.
            message = _error_message(resp)
            raise TransportError(f"Management API {command} failed: {message}")
        try:
            body: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise TransportError(f"Management API {command} returned invalid JSON") from exc
        return body


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}"
    msg = body.get("message") or body.get("code") or f"HTTP {resp.status_code}"
    return str(msg)
