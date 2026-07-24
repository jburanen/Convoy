"""Production entrypoint: ``python -m chkp_cpuse_orch.web``.

Equivalent to ``uvicorn chkp_cpuse_orch.web.app:app --host 0.0.0.0 --port 8080``
(see app.py's module docstring) but also wires up optional, off-by-default HTTPS
from the environment (see .env.example). Plain HTTP unless both
``CHKP_CPUSE_SSL_CERTFILE`` and ``CHKP_CPUSE_SSL_KEYFILE`` are set; a partial pair
fails startup rather than silently serving HTTP.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

import uvicorn

from ..errors import ConfigError

SSL_CERTFILE_ENV = "CHKP_CPUSE_SSL_CERTFILE"
SSL_KEYFILE_ENV = "CHKP_CPUSE_SSL_KEYFILE"


def resolve_ssl(environ: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
    """Read the TLS cert/key paths from the environment, or ``(None, None)`` for
    plain HTTP. Raises ``ConfigError`` if only one of the pair is set."""
    env = os.environ if environ is None else environ
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
        "chkp_cpuse_orch.web.app:app",
        host="0.0.0.0",
        port=8080,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
