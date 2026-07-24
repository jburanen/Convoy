from __future__ import annotations

import json

import httpx
import pytest

from chkp_cpuse_orch.errors import TransportError
from chkp_cpuse_orch.inventory import Host, Role
from chkp_cpuse_orch.transport import mgmt_api
from chkp_cpuse_orch.transport.mgmt_api import LOG_API_CALLS_ENV, ManagementAPIClient, _redact


def _host() -> Host:
    return Host(name="mgmt-01", address="192.0.2.10", role=Role.PRIMARY_SMS)


def _client(handler) -> ManagementAPIClient:  # type: ignore[no-untyped-def]
    return ManagementAPIClient(_host(), api_key="k", transport=httpx.MockTransport(handler))


def test_login_query_logout_paginates() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        body = json.loads(request.content or b"{}")
        if path.endswith("/login"):
            assert body["api-key"] == "k"
            assert body["read-only"] is True
            return httpx.Response(200, json={"sid": "SID-123"})
        if path.endswith("/show-gateways-and-servers"):
            assert request.headers["X-chkp-sid"] == "SID-123"
            # Two objects, one per page — exercise the offset loop.
            offset = body["offset"]
            obj = {"name": f"srv-{offset}", "type": "CpmiManagementServer"}
            return httpx.Response(200, json={"objects": [obj], "total": 2})
        if path.endswith("/logout"):
            return httpx.Response(200, json={"message": "OK"})
        raise AssertionError(f"unexpected path {path}")

    with _client(handler) as client:
        objects = client.show_gateways_and_servers()

    assert [o["name"] for o in objects] == ["srv-0", "srv-1"]
    assert calls[0].endswith("/login")
    assert calls[-1].endswith("/logout")


def test_login_without_sid_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "no session for you"})

    with pytest.raises(TransportError, match="no session id"):
        _client(handler).login()


def test_error_status_becomes_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "S"})
        return httpx.Response(400, json={"message": "bad command"})

    client = _client(handler)
    client.login()
    with pytest.raises(TransportError, match="bad command"):
        client.show_gateways_and_servers()


def test_requires_some_credential() -> None:
    with pytest.raises(TransportError, match="API key or a username/password"):
        ManagementAPIClient(_host())


def test_login_sends_domain_when_set() -> None:
    seen_payload = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            seen_payload.update(json.loads(request.content or b"{}"))
            return httpx.Response(200, json={"sid": "SID-123"})
        return httpx.Response(200, json={"objects": [], "total": 0})

    client = ManagementAPIClient(
        _host(), api_key="k", domain="Global", transport=httpx.MockTransport(handler)
    )
    client.login()
    assert seen_payload["domain"] == "Global"


def test_login_omits_domain_when_unset() -> None:
    seen_payload = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            seen_payload.update(json.loads(request.content or b"{}"))
            return httpx.Response(200, json={"sid": "SID-123"})
        return httpx.Response(200, json={"objects": [], "total": 0})

    ManagementAPIClient(_host(), api_key="k", transport=httpx.MockTransport(handler)).login()
    assert "domain" not in seen_payload


def test_redact_hides_sensitive_keys_recursively() -> None:
    redacted = _redact(
        {
            "user": "admin",
            "password": "hunter2",
            "nested": {"api-key": "abc123", "note": "keep me"},
            "list": [{"sid": "S-1"}, "plain"],
        }
    )
    assert redacted == {
        "user": "admin",
        "password": "***REDACTED***",
        "nested": {"api-key": "***REDACTED***", "note": "keep me"},
        "list": [{"sid": "***REDACTED***"}, "plain"],
    }


def test_api_calls_not_logged_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(mgmt_api.logger, "warning", lambda msg, **kw: calls.append((msg, kw)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"sid": "SID-123"})

    _client(handler).login()
    assert calls == []


def test_api_calls_logged_and_sanitized_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LOG_API_CALLS_ENV, "true")
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(mgmt_api.logger, "warning", lambda msg, **kw: calls.append((msg, kw)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"sid": "SID-123"})

    _client(handler).login()

    messages = {msg: kw for msg, kw in calls}
    assert messages["mgmt-api request"]["payload"]["api-key"] == "***REDACTED***"
    assert messages["mgmt-api response"]["body"]["sid"] == "***REDACTED***"
