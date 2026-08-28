from __future__ import annotations

from typing import Any

import pytest

from convoy.release_check import (
    DISABLE_ENV,
    Release,
    ReleaseChecker,
    check_disabled,
    is_newer,
    newest_release,
    version_key,
)


def _entry(tag: str, *, draft: bool = False, url: str | None = None) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "draft": draft,
        "html_url": url or f"https://github.com/jburanen/Convoy/releases/tag/{tag}",
    }


def test_prerelease_sorts_below_the_release_of_the_same_number() -> None:
    assert is_newer("1.0.0", "1.0.0-rc.2")
    assert is_newer("1.0.0-rc.2", "1.0.0-rc.1")
    assert is_newer("v1.0.0-rc.10", "1.0.0-rc.9")  # numeric ids compare as numbers
    assert not is_newer("1.0.0-rc.1", "1.0.0-rc.2")
    assert not is_newer("1.0.0-rc.2", "1.0.0")


def test_version_ordering_across_components() -> None:
    assert is_newer("v1.2.0", "1.1.9")
    assert is_newer("2.0", "1.99.99")  # a short tag fills missing components with 0
    assert not is_newer("1.0.0", "1.0.0")
    assert version_key("1.0.0+abc123") == version_key("1.0.0")  # build metadata is ignored


def test_unparseable_versions_never_claim_an_update() -> None:
    assert version_key("nightly") is None
    assert version_key("1.0.0-") is None
    assert not is_newer("nightly", "1.0.0")
    assert not is_newer("2.0.0", "not-a-version")


def test_newest_release_skips_drafts_but_not_prereleases() -> None:
    release = newest_release(
        [
            _entry("v1.0.0-rc.1"),
            _entry("v9.9.9", draft=True),  # invisible to everyone but the maintainer
            _entry("v1.0.0-rc.2"),
            _entry("nightly"),  # not version-shaped — skipped, not guessed at
            "junk",
        ]
    )
    assert release == Release(
        version="1.0.0-rc.2",
        url="https://github.com/jburanen/Convoy/releases/tag/v1.0.0-rc.2",
    )


def test_newest_release_falls_back_to_a_built_tag_url() -> None:
    release = newest_release([{"tag_name": "v1.1.0"}])
    assert release is not None
    assert release.url == "https://github.com/jburanen/Convoy/releases/tag/v1.1.0"


def test_update_available_only_when_the_published_release_is_newer() -> None:
    checker = ReleaseChecker(fetch=lambda: [_entry("v1.0.0-rc.2")], environ={})
    assert checker.update_available("1.0.0-rc.1") == Release(
        version="1.0.0-rc.2",
        url="https://github.com/jburanen/Convoy/releases/tag/v1.0.0-rc.2",
    )
    assert checker.update_available("1.0.0-rc.2") is None
    assert checker.update_available("1.1.0") is None  # running ahead of the repo


def test_success_is_cached_until_the_ttl_expires() -> None:
    calls = []
    now = [0.0]

    def fetch() -> list[Any]:
        calls.append(1)
        return [_entry(f"v1.{len(calls)}.0")]

    checker = ReleaseChecker(
        fetch=fetch, clock=lambda: now[0], success_ttl=100, failure_ttl=10, environ={}
    )
    assert checker.latest() == Release(
        version="1.1.0", url="https://github.com/jburanen/Convoy/releases/tag/v1.1.0"
    )
    now[0] = 99
    assert checker.latest().version == "1.1.0"  # type: ignore[union-attr]
    assert len(calls) == 1
    now[0] = 101
    assert checker.latest().version == "1.2.0"  # type: ignore[union-attr]
    assert len(calls) == 2


def test_failure_is_swallowed_and_retried_on_its_own_shorter_ttl() -> None:
    calls = []
    now = [0.0]

    def fetch() -> list[Any]:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("connection refused")  # blocked/offline instance
        return [_entry("v2.0.0")]

    checker = ReleaseChecker(
        fetch=fetch, clock=lambda: now[0], success_ttl=100, failure_ttl=10, environ={}
    )
    assert checker.latest() is None
    now[0] = 9
    assert checker.latest() is None
    assert len(calls) == 1  # not retried on every page load
    now[0] = 11
    assert checker.latest() == Release(
        version="2.0.0", url="https://github.com/jburanen/Convoy/releases/tag/v2.0.0"
    )


def test_disabled_makes_no_call_at_all() -> None:
    def fetch() -> list[Any]:
        raise AssertionError("the check is off — nothing should reach out")

    checker = ReleaseChecker(fetch=fetch, environ={DISABLE_ENV: "1"})
    assert checker.latest() is None
    assert checker.update_available("0.1.0") is None


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "OFF"])
def test_off_values_leave_the_check_enabled(value: str) -> None:
    assert check_disabled({DISABLE_ENV: value}) is False


def test_unset_leaves_the_check_enabled() -> None:
    assert check_disabled({}) is False
