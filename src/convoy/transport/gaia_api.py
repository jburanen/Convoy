"""Gaia REST API client (thin).

Used where the Gaia REST API is enabled and preferable to screen-scraping clish
(e.g. structured version/HA state). Stub for now.
"""

from __future__ import annotations

from ..inventory import Host


class GaiaAPIClient:
    """Minimal Gaia REST API client (httpx-backed). Stub."""

    def __init__(self, host: Host, *, token: str | None = None, verify_tls: bool = True) -> None:
        self.host = host
        self._token = token
        self._verify_tls = verify_tls

    def login(self) -> None:
        # TODO: POST /gaia_api/.../login, store session id.
        raise NotImplementedError("Gaia API login not yet implemented")

    def show_version(self) -> dict[str, object]:
        # TODO: call the version endpoint and return parsed JSON.
        raise NotImplementedError("Gaia API show_version not yet implemented")
