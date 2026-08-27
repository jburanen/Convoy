"""Production entrypoint: ``python -m convoy.web``.

Equivalent to ``uvicorn convoy.web.app:app --host 0.0.0.0 --port 8080``
(see app.py's module docstring) but also wires up optional, off-by-default HTTPS
from the environment (see .env.example). Plain HTTP unless both
``CONVOY_SSL_CERTFILE`` and ``CONVOY_SSL_KEYFILE`` are set; a partial pair
fails startup rather than silently serving HTTP. Also applies
``CONVOY_WEB_LOG_LEVEL`` (see reporting.resolve_log_level) to uvicorn's own
access/error logs, same level app.py's lifespan applies to the app's own
structlog output — so the two never drift apart under docker compose logs.
"""

from __future__ import annotations

from collections.abc import Mapping

import uvicorn

from ..envcompat import compat_env
from ..errors import ConfigError
from ..reporting import resolve_log_level

SSL_CERTFILE_ENV = "CONVOY_SSL_CERTFILE"
SSL_KEYFILE_ENV = "CONVOY_SSL_KEYFILE"


def resolve_ssl(environ: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
    """Read the TLS cert/key paths from the environment, or ``(None, None)`` for
    plain HTTP. Raises ``ConfigError`` if only one of the pair is set."""
    env = compat_env(environ)
    certfile = env.get(SSL_CERTFILE_ENV) or None
    keyfile = env.get(SSL_KEYFILE_ENV) or None
    if bool(certfile) != bool(keyfile):
        raise ConfigError(
            f"incomplete TLS config: set both {SSL_CERTFILE_ENV} and {SSL_KEYFILE_ENV} "
            "to enable HTTPS, or neither to run plain HTTP"
        )
    return certfile, keyfile


def main() -> None:
    certfile, keyfile = resolve_ssl()
    uvicorn.run(
        "convoy.web.app:app",
        host="0.0.0.0",
        port=8080,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        log_level=resolve_log_level(),
    )


if __name__ == "__main__":  # pragma: no cover
    main()
