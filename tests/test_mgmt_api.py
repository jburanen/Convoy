from __future__ import annotations

import json

import httpx
import pytest

from convoy.errors import ManagementAPIForbidden, TransportError
from convoy.inventory import Host, Role
from convoy.transport import mgmt_api
from convoy.transport.mgmt_api import LOG_API_CALLS_ENV, ManagementAPIClient, _redact


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


def test_403_becomes_management_api_forbidden() -> None:
    """A 403 gets its own exception type — a subclass of TransportError — so
    callers (services/discovery.py) can distinguish "API not reachable" from
    "API refused this host" and offer the SSH diagnose/repair flow."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "S"})
        return httpx.Response(403, json={"message": "Forbidden"})

    client = _client(handler)
    client.login()
    with pytest.raises(ManagementAPIForbidden, match="403"):
        client.show_gateways_and_servers()
    # Still catchable by callers that only know about the base type.
    with pytest.raises(TransportError):
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
    # The TLS-verification-disabled notice is a deliberate standing warning
    # (it was logger.debug, i.e. invisible at the default level) — what must
    # not appear without CONVOY_LOG_API_CALLS is the calls themselves.
    assert not [msg for msg, _ in calls if msg.startswith("mgmt-api request")]
    assert not [msg for msg, _ in calls if msg.startswith("mgmt-api response")]


def test_login_defaults_to_read_only() -> None:
    seen_payload = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payload.update(json.loads(request.content or b"{}"))
        return httpx.Response(200, json={"sid": "SID-123"})

    ManagementAPIClient(_host(), api_key="k", transport=httpx.MockTransport(handler)).login()
    assert seen_payload["read-only"] is True


def test_login_write_mode_sends_read_only_false() -> None:
    seen_payload = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payload.update(json.loads(request.content or b"{}"))
        return httpx.Response(200, json={"sid": "SID-123"})

    ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    ).login()
    assert seen_payload["read-only"] is False


def test_add_repository_package_returns_task_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        if request.url.path.endswith("/add-repository-package"):
            body = json.loads(request.content or b"{}")
            assert body == {"name": "jhf.tgz", "path": "/var/log/upload", "source": "local"}
            return httpx.Response(200, json={"task-id": "TASK-1"})
        raise AssertionError(f"unexpected path {request.url.path}")

    client = ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    )
    client.login()
    assert client.add_repository_package("jhf.tgz", "/var/log/upload") == "TASK-1"


def test_add_repository_package_raises_without_task_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        return httpx.Response(200, json={"message": "ok"})

    client = ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    )
    client.login()
    with pytest.raises(TransportError, match="no task-id"):
        client.add_repository_package("jhf.tgz", "/var/log/upload")


def test_run_script_returns_flat_task_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        if request.url.path.endswith("/run-script"):
            body = json.loads(request.content or b"{}")
            assert body == {"script-name": "s", "script": "echo hi", "targets": ["gw-1"]}
            return httpx.Response(200, json={"task-id": "TASK-1"})
        raise AssertionError(f"unexpected path {request.url.path}")

    client = ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    )
    client.login()
    assert client.run_script("echo hi", ["gw-1"], script_name="s") == "TASK-1"


def test_run_script_falls_back_to_nested_tasks_shape() -> None:
    # Same nested shape show-task returns — not yet confirmed this is what
    # run-script itself sends back, but it's the best fallback guess when the
    # flat key (add-repository-package's shape) isn't present.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        if request.url.path.endswith("/run-script"):
            return httpx.Response(
                200, json={"tasks": [{"task-id": "TASK-2", "status": "in progress"}]}
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    client = ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    )
    client.login()
    assert client.run_script("echo hi", ["gw-1"]) == "TASK-2"


def test_run_script_raises_with_raw_response_when_unrecognized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        return httpx.Response(200, json={"message": "accepted"})

    client = ManagementAPIClient(
        _host(), api_key="k", read_only=False, transport=httpx.MockTransport(handler)
    )
    client.login()
    with pytest.raises(TransportError, match=r"no task-id.*accepted"):
        client.run_script("echo hi", ["gw-1"])


def test_show_task_returns_first_task() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        if request.url.path.endswith("/show-task"):
            body = json.loads(request.content or b"{}")
            assert body == {"task-id": "TASK-1"}
            return httpx.Response(
                200, json={"tasks": [{"status": "succeeded", "task-id": "TASK-1"}]}
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    client = _client(handler)
    client.login()
    task = client.show_task("TASK-1")
    assert task["status"] == "succeeded"


def test_show_task_raises_when_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"sid": "SID-123"})
        return httpx.Response(200, json={"tasks": []})

    client = _client(handler)
    client.login()
    with pytest.raises(TransportError, match="no tasks"):
        client.show_task("TASK-1")


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


# -- log redaction (H6) ------------------------------------------------------------
#
# _redact used to match keys EXACTLY, which missed every compound name the API
# actually uses. The sharp one was "script": the credential-bootstrap run-script
# payload carries the whole clish script including `set user <u> password-hash
# $6$...`, so enabling CONVOY_LOG_API_CALLS wrote a crackable hash of a
# gateway's admin password into `docker compose logs` at WARNING level.


def test_redact_covers_compound_and_nested_secret_keys() -> None:
    payload = {
        "script": "set user svc password-hash $6$salt$hash",
        "new-password": "p",
        "password-hash": "h",
        "api_key": "k",
        "session-id": "s",
        "sid": "s",
        "nested": {"passwd": "q", "targets": ["fw-01"]},
    }
    out = _redact(payload)

    for key in ("script", "new-password", "password-hash", "api_key", "session-id", "sid"):
        assert out[key] == "***REDACTED***", key
    assert out["nested"]["passwd"] == "***REDACTED***"
    assert "$6$" not in json.dumps(out)


def test_redact_leaves_ordinary_fields_alone() -> None:
    payload = {"name": "fw-01", "uid": "abc", "targets": ["fw-01"], "details-level": "full"}
    assert _redact(payload) == payload


def test_tls_disabled_posture_is_warned_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verification-off is an accepted operator decision, but a posture nobody
    can see is one nobody can reconsider — it used to be logger.debug."""
    calls: list[str] = []
    monkeypatch.setattr(mgmt_api.logger, "warning", lambda msg, **kw: calls.append(msg))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"sid": "SID-123"})

    _client(handler).login()
    assert any("TLS verification disabled" in m for m in calls)
