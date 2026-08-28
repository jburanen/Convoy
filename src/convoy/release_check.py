"""Is a newer Convoy release published on GitHub?

The footer prints the version this instance is running; this is what lets it add
"Build x.y.z is available" beside it, linked to that release's notes.

Strictly best-effort. Convoy runs on an internal network next to the firewalls
it patches, where GitHub is often unreachable or deliberately blocked — so every
failure here is swallowed and simply means the footer shows nothing extra. The
outcome (a release, or nothing) is cached in memory for hours, so a room full of
open browser tabs still costs at most one GitHub call every few hours. Operators
who want no outbound call at all set ``CONVOY_DISABLE_UPDATE_CHECK``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from . import __version__
from .envcompat import compat_env
from .reporting import get_logger

logger = get_logger(__name__)

REPO = "jburanen/Convoy"
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases"
# Not /releases/latest: that endpoint excludes prereleases, and Convoy's own
# releases are cut as release candidates (v1.0.0-rc.2), which GitHub marks as
# prereleases. Read a page of the list and pick the highest version here.
PER_PAGE = 20
REQUEST_TIMEOUT = 5.0
# A published release doesn't change often, and a blocked network won't unblock
# itself on the next page load — so cache the answer either way, failures for
# less long than successes so a transient outage self-heals within the hour.
SUCCESS_TTL_SECONDS = 6 * 60 * 60
FAILURE_TTL_SECONDS = 15 * 60
DISABLE_ENV = "CONVOY_DISABLE_UPDATE_CHECK"
# Unset, empty, or an explicit off-value leaves the check on; anything else
# turns it off.
_OFF_VALUES = {"", "0", "false", "no", "off"}


@dataclass(frozen=True)
class Release:
    """A published release, as the footer needs it."""

    version: str  # display form — the tag without its leading "v"
    url: str  # the release-notes page for that tag


def _prerelease_key(pre: str) -> tuple[tuple[int, int, str], ...]:
    """Order semver prerelease identifiers: numeric ones compare as numbers and
    sort below alphanumeric ones (so rc.2 > rc.1, and rc > 2)."""
    ids: list[tuple[int, int, str]] = []
    for part in pre.split("."):
        ids.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return tuple(ids)


def version_key(version: str) -> tuple[Any, ...] | None:
    """A sortable key for ``1.2.3`` / ``v1.2.3`` / ``1.0.0-rc.2``, or None for
    anything that isn't version-shaped (a tag like ``nightly`` — skipped rather
    than guessed at). Semver ordering: a prerelease sorts below the release of
    the same number, and build metadata (``+sha``) doesn't affect ordering."""
    text = version.strip()
    if text[:1] in {"v", "V"}:
        text = text[1:]
    text = text.split("+", 1)[0]
    core, sep, pre = text.partition("-")
    parts = core.split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() for p in parts):
        return None
    if sep and not pre:
        return None
    nums = tuple(int(p) for p in parts) + (0,) * (3 - len(parts))
    return (nums, 0 if pre else 1, _prerelease_key(pre) if pre else ())


def is_newer(candidate: str, current: str) -> bool:
    """True only when both versions parse AND candidate is the higher one — an
    unparseable version on either side means "don't claim an update"."""
    candidate_key, current_key = version_key(candidate), version_key(current)
    if candidate_key is None or current_key is None:
        return False
    return candidate_key > current_key


def newest_release(entries: Iterable[Any]) -> Release | None:
    """The highest-versioned published release in a GitHub releases payload.
    Drafts are skipped (nobody but the maintainer can open one); prereleases are
    not, since that is how Convoy itself ships."""
    best: Release | None = None
    best_key: tuple[Any, ...] | None = None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("draft"):
            continue
        tag = str(entry.get("tag_name") or "")
        key = version_key(tag)
        if key is None or (best_key is not None and key <= best_key):
            continue
        best_key = key
        best = Release(
            version=tag[1:] if tag[:1] in {"v", "V"} else tag,
            url=str(entry.get("html_url") or f"https://github.com/{REPO}/releases/tag/{tag}"),
        )
    return best


def check_disabled(environ: Mapping[str, str] | None = None) -> bool:
    """Whether the operator has turned the check off. Set the variable to
    anything other than an off-value and no call is made."""
    return compat_env(environ).get(DISABLE_ENV, "").strip().lower() not in _OFF_VALUES


def fetch_releases() -> list[Any]:
    """One GitHub API call. Raises on anything that isn't a clean list response —
    ReleaseChecker turns that into "no update to show"."""
    resp = httpx.get(
        RELEASES_URL,
        params={"per_page": PER_PAGE},
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"convoy/{__version__}",
        },
        timeout=REQUEST_TIMEOUT,
        follow_redirects=True,
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload if isinstance(payload, list) else []


class ReleaseChecker:
    """Cached, best-effort "is there a newer release?" for the footer.

    ``fetch`` and ``clock`` are injectable so tests never touch the network.
    """

    def __init__(
        self,
        *,
        fetch: Callable[[], Iterable[Any]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        success_ttl: float = SUCCESS_TTL_SECONDS,
        failure_ttl: float = FAILURE_TTL_SECONDS,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._fetch = fetch or fetch_releases
        self._clock = clock
        self._success_ttl = success_ttl
        self._failure_ttl = failure_ttl
        self._environ = environ
        # The lock is deliberately held across the HTTP call: several browser
        # tabs loading at once should produce one call, not one each.
        self._lock = threading.Lock()
        self._cached: Release | None = None
        self._expires_at: float | None = None

    def latest(self) -> Release | None:
        """The newest published release, or None if the check is off, the call
        failed, or nothing version-shaped is published."""
        if check_disabled(self._environ):
            return None
        with self._lock:
            now = self._clock()
            if self._expires_at is not None and now < self._expires_at:
                return self._cached
            try:
                release: Release | None = newest_release(self._fetch())
                ttl = self._success_ttl
            except Exception as exc:  # offline, blocked, rate-limited, malformed
                logger.debug("release check failed", error=str(exc))
                release, ttl = None, self._failure_ttl
            self._cached = release
            self._expires_at = now + ttl
            return release

    def update_available(self, current: str = __version__) -> Release | None:
        """The newer release to point the operator at, or None when the running
        version is already the newest (or the check couldn't answer)."""
        release = self.latest()
        if release is None or not is_newer(release.version, current):
            return None
        return release
