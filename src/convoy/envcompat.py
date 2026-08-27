"""Backward compatibility for the ``CHKP_CPUSE_*`` → ``CONVOY_*`` environment rename.

Every setting this app reads changed prefix when the project was renamed to Convoy.
A deployment's ``.env`` is operator-managed and lives outside this repo, so a hard
cutover would break a running install on its next ``git pull`` — and one of those
variables, ``CHKP_CPUSE_MASTER_KEY``, derives the key for the credential store.
Losing that one doesn't degrade the app, it locks the operator out of every stored
credential.

So both spellings work: ``CONVOY_*`` wins, ``CHKP_CPUSE_*`` is still honoured, and
reading a value from the old name logs a warning naming its replacement.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping

logger = logging.getLogger(__name__)

PREFIX = "CONVOY_"
LEGACY_PREFIX = "CHKP_CPUSE_"

# Warn once per variable per process; these helpers are called on every read.
_warned: set[str] = set()


def compat_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``environ`` in which every ``CHKP_CPUSE_*`` variable is also
    visible under its ``CONVOY_*`` name.

    An explicit ``CONVOY_*`` value always wins, so an operator can migrate one
    variable at a time without the stale old name overriding the new one.
    """
    env = dict(os.environ if environ is None else environ)
    for legacy_key in [k for k in env if k.startswith(LEGACY_PREFIX)]:
        new_key = PREFIX + legacy_key[len(LEGACY_PREFIX) :]
        if new_key in env:
            continue
        env[new_key] = env[legacy_key]
        if legacy_key not in _warned:
            _warned.add(legacy_key)
            logger.warning(
                "%s is deprecated and will be removed; rename it to %s",
                legacy_key,
                new_key,
            )
    return env
