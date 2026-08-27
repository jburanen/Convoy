"""Structured, auditable run reporting.

Every deployment must be reconstructable after the fact. This module configures
structlog and provides a run recorder. Output goes to git-ignored ``reports/`` and
``logs/`` — it may contain live infrastructure detail. See
.claude/memory/security-hygiene.md.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

import structlog

from .envcompat import compat_env
from .errors import ConfigError

# Web server verbosity (also applied to uvicorn's own access/error logs — see
# web/__main__.py). Defaults to WARNING so routine per-request INFO chatter
# doesn't fill `docker compose logs`; set DEBUG/INFO to see more.
LOG_LEVEL_ENV = "CONVOY_WEB_LOG_LEVEL"
DEFAULT_LOG_LEVEL = logging.WARNING


def resolve_log_level(environ: Mapping[str, str] | None = None) -> int:
    """Read the web server's log level from the environment, or WARNING if unset.
    Raises ``ConfigError`` on a name ``logging`` doesn't recognize."""
    env = compat_env(environ)
    raw = (env.get(LOG_LEVEL_ENV) or "").strip().upper()
    if not raw:
        return DEFAULT_LOG_LEVEL
    levels = logging.getLevelNamesMapping()
    if raw not in levels:
        raise ConfigError(f"{LOG_LEVEL_ENV} must be one of {sorted(levels)}, got {raw!r}")
    return levels[raw]


def configure_logging(*, level: int = logging.INFO, json_output: bool = False) -> None:
    """Configure structlog once at startup.

    ``json_output`` emits machine-readable audit lines (recommended for stored run
    reports); otherwise a human-friendly console renderer is used.
    """
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger. Bind run-id / target context at call sites."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
