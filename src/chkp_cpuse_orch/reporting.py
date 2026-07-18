"""Structured, auditable run reporting.

Every deployment must be reconstructable after the fact. This module configures
structlog and provides a run recorder. Output goes to git-ignored ``reports/`` and
``logs/`` — it may contain live infrastructure detail. See
.claude/memory/security-hygiene.md.
"""

from __future__ import annotations

import logging

import structlog


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
