from __future__ import annotations

import hashlib
import io
import tarfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from convoy import __version__ as convoy_version
from convoy.config import Config, EnvironmentDef, Paths
from convoy.credentials import MASTER_KEY_ENV
from convoy.release_check import ReleaseChecker
from convoy.store import JobRecord, JobStatus
from convoy.web import app as web_app
from convoy.web.app import create_app
from convoy.web.auth import AuthSettings

from .fakes import DA_BUILD, SHOW_PACKAGES_ALL, FakeAuthenticator, FakeTransport, make_factory

# Credential storage requires authentication, so web tests run with a fake LDAP
# backend enabled and log in before exercising the API (see .claude/memory).
TEST_USER = "operator"
TEST_PASS = "correct horse battery"
AUTH_SETTINGS = AuthSettings(
    url="ldap://test",
    required_group="cn=admins",
    user_dn_template="{username}",
    cookie_secure=False,  # TestClient talks plain HTTP
    idle_minutes=30,
)


def _fake_auth() -> FakeAuthenticator:
    return FakeAuthenticator({TEST_USER: TEST_PASS})


def _login(c: TestClient, username: str = TEST_USER, password: str = TEST_PASS) -> None:
    resp = c.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text


INVENTORY_YAML = """\
sites:
  - name: test-site
    hosts:
      - name: mgmt-01
        address: 192.0.2.10
        role: management
      - name: fw-01
        address: 192.0.2.20
        role: firewall
"""


def _config(tmp_path: Path) -> Config:
    (tmp_path / "inventory.yaml").write_text(INVENTORY_YAML, encoding="utf-8")
    return Config(
        paths=Paths(
            reports_dir=tmp_path / "reports",
            logs_dir=tmp_path / "logs",
            state_dir=tmp_path / "state",
            db_path=tmp_path / "state" / "orch.db",
            packages_dir=tmp_path / "packages",
            job_archive_path=tmp_path / "state" / "job_archive.log",
            inventory_path=tmp_path / "inventory.yaml",
        )
    )


CANDIDATES_CSV = "Object Name,IP,Upgrade Order\nfw-a1,192.0.2.31,1\nfw-a2,192.0.2.32,2\n"


@pytest.fixture
def transport() -> FakeTransport:
    uploaded_sha1 = hashlib.sha1(b"x" * 64).hexdigest()  # matches _upload_package's default content
    return FakeTransport(
        responses={
            # More specific keys first — FakeTransport._lookup matches in
            # insertion order, and these must win over the generic "show
            # installer packages" below for PatchingService._wait_until_imported.
            "show installer packages imported": "jhf.tgz      Imported",
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer package ": "Status:           Installed",
            "show installer status build": DA_BUILD,
            "sha1sum": f"{uploaded_sha1}  /var/log/upload/jhf.tgz",
            "cat /opt/CPcdt/orch_candidates.csv": CANDIDATES_CSV,
            "pgrep": (1, ""),  # no CDT process running by default
            "test -x": (0, ""),  # CDT binary present
            "show administrator name": (1, ""),  # not found by default — connect-primary tests
            "add api-key": '{"api-key": "generated-key-xyz"}',
        }
    )


@pytest.fixture
def client(
    tmp_path: Path, transport: FakeTransport, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    monkeypatch.setenv(MASTER_KEY_ENV, "api test master key")
    app = create_app(
        _config(tmp_path),
        client_factory=make_factory(transport),
        authenticator=_fake_auth(),
        auth_settings=AUTH_SETTINGS,
        # Real reachability probing is pure network I/O against inventory
        # addresses that don't exist in tests — see test_spark_patching_service.py's
        # `service` fixture for the same substitution at the service-unit level.
        spark_probe_reachable=lambda address, port: True,
    )
    with TestClient(app) as c:
        _login(c)
        yield c


def _enable_storage(client: TestClient, env: str) -> None:
    resp = client.post(f"/api/environments/{env}/credential-storage", json={"enabled": True})
    assert resp.status_code == 200, resp.text


def _put_set(
    client: TestClient, env: str = "default", name: str = "primary", **extra: object
) -> dict:
    """PUT a credential set. Executes immediately (see services/cred_ops.py) —
    the response body is already the finished cred.add/cred.edit JobRecord, no
    polling needed. Returned for callers that need the outcome (e.g. which
    kind ran, or is_default)."""
    body: dict[str, object] = {
        "name": name,
        "ssh_username": "admin",
        "ssh_password": "pw",
        "expert_password": "expert-pw",
    }
    body.update(extra)
    resp = client.put(f"/api/env/{env}/credentials", json=body)
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    return job


def _assign_set(
    client: TestClient, host: str, env: str = "default", name: str | None = "primary"
) -> None:
    resp = client.post(f"/api/env/{env}/servers/{host}/credential", json={"set": name})
    assert resp.status_code == 200, resp.text


def _add_ssh_credential(client: TestClient, host: str = "mgmt-01") -> None:
    """Create the shared 'primary' login set and assign it to a server."""
    _put_set(client)
    _assign_set(client, host)


# Inline credentials for a storage-disabled environment (one-shot per request).
_SSH_CREDS = [{"kind": "ssh_password", "username": "admin", "secret": "pw"}]
# Import/install/CDT/etc. escalate to expert mode (disk check, sha1 verify,
# install-log capture, ...) — a storage-disabled job submitting one of those
# kinds needs this in the body too, unlike a plain state/detect query.
_SSH_CREDS_WITH_EXPERT = [*_SSH_CREDS, {"kind": "expert_password", "secret": "expert-pw"}]


def _upload_package(client: TestClient, name: str = "jhf.tgz", content: bytes = b"x" * 64) -> None:
    """Upload a package. Executes immediately (see services/pkgs_ops.py) — the
    response is already the finished pkgs.upload job, so callers can assume
    the package exists the moment this returns."""
    resp = client.post("/api/packages", files={"file": (name, content)})
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]


def _wait_for_job(client: TestClient, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("pending", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def _add_server(client: TestClient, env: str = "default", **body: object) -> dict:
    """POST a server. Executes immediately as a tracked prov.add/prov.edit job
    (see services/prov_ops.py) — the response is already the finished job
    dict (callers assert its status; validation errors like a bad role or a
    name collision surface as a *failed* job, not a synchronous 400/409)."""
    resp = client.post(f"/api/environments/{env}/servers", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _remove_server(client: TestClient, env: str, name: str) -> dict:
    """DELETE a server. Runs as a prov.delete job — see _add_server above."""
    resp = client.delete(f"/api/environments/{env}/servers/{name}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _add_firewall(client: TestClient, env: str = "default", **body: object) -> dict:
    """POST a firewall. Runs as a prov.add/prov.edit job — see _add_server."""
    resp = client.post(f"/api/environments/{env}/firewalls", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _remove_firewall(client: TestClient, env: str, name: str) -> dict:
    """DELETE a firewall. Runs as a prov.delete job — see _add_server."""
    resp = client.delete(f"/api/environments/{env}/firewalls/{name}")
    assert resp.status_code == 200, resp.text
    return resp.json()


# -- basics ----------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root_serves_static_ui(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Convoy" in resp.text


def test_status_reports_unlocked_and_counts(client: TestClient) -> None:
    body = client.get("/api/status").json()
    assert body["credentials_unlocked"] is True
    assert body["management_servers"] == 1  # fw-01 is a firewall, not counted
    assert body["environments"] == ["default"]
    assert body["job_archive_path"]  # Jobs tab points the operator here


def test_update_check_reports_a_newer_published_release(client: TestClient) -> None:
    # The real checker would reach out to GitHub; swap in one with a canned
    # payload so the test stays offline (see test_release_check.py for the
    # checker's own behaviour).
    client.app.state.release_checker = ReleaseChecker(  # type: ignore[attr-defined]
        fetch=lambda: [{"tag_name": "v99.0.0", "html_url": "https://example.invalid/rel"}],
        environ={},
    )
    body = client.get("/api/update").json()
    assert body["update_available"] is True
    assert body["version"] == "99.0.0"
    assert body["url"] == "https://example.invalid/rel"
    assert body["current"] == convoy_version


def test_update_check_is_silent_when_the_running_build_is_current(client: TestClient) -> None:
    client.app.state.release_checker = ReleaseChecker(  # type: ignore[attr-defined]
        fetch=lambda: [{"tag_name": "v0.0.1"}], environ={}
    )
    body = client.get("/api/update").json()
    assert body["update_available"] is False
    assert body["version"] is None and body["url"] is None


def test_update_check_survives_an_unreachable_github(client: TestClient) -> None:
    def boom() -> list[object]:
        raise RuntimeError("connection refused")

    client.app.state.release_checker = ReleaseChecker(fetch=boom, environ={})  # type: ignore[attr-defined]
    body = client.get("/api/update").json()
    assert body["update_available"] is False


def test_environments_endpoint(client: TestClient) -> None:
    envs = client.get("/api/environments").json()
    assert envs == [
        {
            "name": "default",
            "management_servers": 1,
            "credential_storage_enabled": True,
            "is_mds": False,
            "api_only": False,
            "skip_verify_by_default": False,
        }
    ]


def test_new_environment_defaults_to_storage_disabled(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "dmz"})
    envs = {
        e["name"]: e["credential_storage_enabled"] for e in client.get("/api/environments").json()
    }
    assert envs["dmz"] is False  # UI-created environments don't store credentials
    assert envs["default"] is True  # config-seeded ones keep the old behaviour


def test_create_environment_declares_mds_kind(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "mds-estate", "is_mds": True})
    envs = {e["name"]: e["is_mds"] for e in client.get("/api/environments").json()}
    assert envs["mds-estate"] is True
    assert envs["default"] is False


def test_set_environment_kind_toggles_is_mds(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "dmz"})
    resp = client.post("/api/environments/dmz/kind", json={"is_mds": True})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"is_mds": True}
    envs = {e["name"]: e["is_mds"] for e in client.get("/api/environments").json()}
    assert envs["dmz"] is True


def test_set_environment_kind_unknown_environment_404s(client: TestClient) -> None:
    resp = client.post("/api/environments/nope/kind", json={"is_mds": True})
    assert resp.status_code == 404


def test_set_environment_type_applies_both_flags_at_once(client: TestClient) -> None:
    """The UI offers one three-way choice (SMS / MDS / Smart-1 Cloud) over two
    flags, so it needs to set both in a single call — applying them as two
    sequential requests can leave an environment in a combination the operator
    never picked, and a failure between them makes that permanent."""
    client.post("/api/environments", json={"name": "cloud"})

    # Smart-1 Cloud: API-only, and NOT multi-domain.
    resp = client.post("/api/environments/cloud/type", json={"is_mds": False, "api_only": True})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"is_mds": False, "api_only": True}
    env = next(e for e in client.get("/api/environments").json() if e["name"] == "cloud")
    assert (env["is_mds"], env["api_only"]) == (False, True)

    # ...and switching to MDS clears api_only in the same call, rather than
    # leaving the environment briefly both.
    resp = client.post("/api/environments/cloud/type", json={"is_mds": True, "api_only": False})
    assert resp.status_code == 200, resp.text
    env = next(e for e in client.get("/api/environments").json() if e["name"] == "cloud")
    assert (env["is_mds"], env["api_only"]) == (True, False)


def test_set_environment_type_rejects_an_unknown_environment(client: TestClient) -> None:
    resp = client.post("/api/environments/nope/type", json={"is_mds": True, "api_only": False})
    assert resp.status_code == 404


def test_set_environment_access_toggles_api_only(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "cloud-mgmt"})
    resp = client.post("/api/environments/cloud-mgmt/access", json={"api_only": True})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"api_only": True}
    envs = {e["name"]: e["api_only"] for e in client.get("/api/environments").json()}
    assert envs["cloud-mgmt"] is True
    assert envs["default"] is False


def test_set_environment_access_unknown_environment_404s(client: TestClient) -> None:
    resp = client.post("/api/environments/nope/access", json={"api_only": True})
    assert resp.status_code == 404


def test_set_skip_verify_default(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "dmz"})
    envs = {e["name"]: e["skip_verify_by_default"] for e in client.get("/api/environments").json()}
    assert envs["dmz"] is False  # new environments default to unchecked

    resp = client.post(
        "/api/environments/dmz/skip-verify-default", json={"skip_verify_by_default": True}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"skip_verify_by_default": True}
    envs = {e["name"]: e["skip_verify_by_default"] for e in client.get("/api/environments").json()}
    assert envs["dmz"] is True
    assert envs["default"] is False  # unaffected


def test_set_skip_verify_default_unknown_environment_404s(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/nope/skip-verify-default", json={"skip_verify_by_default": True}
    )
    assert resp.status_code == 404


def test_storage_disabled_env_rejects_stored_credentials(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "dmz"})
    resp = client.put("/api/env/dmz/credentials", json={"name": "primary", "ssh_password": "pw"})
    assert resp.status_code == 409
    assert "storage is disabled" in resp.json()["detail"]


def test_edit_credential_set_adds_api_key_without_resending_secret(client: TestClient) -> None:
    # Bootstrap entry (SSH password only), like the provisioning flow creates.
    _put_set(client)
    sets = client.get("/api/env/default/credentials").json()
    assert sets[0]["has_api"] is False

    # "Edit" it to add just the API key — no SSH secret in the body.
    resp = client.put(
        "/api/env/default/credentials", json={"name": "primary", "api_key": "APIKEY123"}
    )
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "cred.edit"  # a set with this name already existed
    sets = client.get("/api/env/default/credentials").json()
    assert len(sets) == 1  # merged into the same set, not a second one
    assert sets[0]["has_api"] is True
    assert sets[0]["ssh_auth"] == "password"  # SSH password preserved


def test_bootstrap_credentials_become_the_default(client: TestClient) -> None:
    # First set with default_if_none → becomes the environment default.
    resp = client.put(
        "/api/env/default/credentials",
        json={
            "name": "primary",
            "ssh_username": "admin",
            "ssh_password": "pw",
            "expert_password": "expert-pw",
            "default_if_none": True,
        },
    )
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    sets = client.get("/api/env/default/credentials").json()
    assert sets[0]["is_default"] is True

    # A second set also asking default_if_none does NOT steal the default.
    resp2 = client.put(
        "/api/env/default/credentials",
        json={
            "name": "backup",
            "ssh_username": "admin",
            "ssh_password": "pw",
            "expert_password": "expert-pw",
            "default_if_none": True,
        },
    )
    assert resp2.status_code == 200, resp2.text
    defaults = [
        s["name"] for s in client.get("/api/env/default/credentials").json() if s["is_default"]
    ]
    assert defaults == ["primary"]


def test_set_default_endpoint_switches_the_default(client: TestClient) -> None:
    _put_set(client, name="a")
    _put_set(client, name="b")
    assert client.post("/api/env/default/credentials/a/default").json() == {"default": "a"}
    assert client.post("/api/env/default/credentials/b/default").json() == {"default": "b"}
    defaults = [
        s["name"] for s in client.get("/api/env/default/credentials").json() if s["is_default"]
    ]
    assert defaults == ["b"]
    assert client.post("/api/env/default/credentials/ghost/default").status_code == 404


def test_new_server_gets_the_default_credential(client: TestClient) -> None:
    _put_set(client, name="primary")
    client.post("/api/env/default/credentials/primary/default")
    job = _add_server(client, name="m9", address="192.0.2.99", role="primary_sms")
    assert job["status"] == "succeeded", job["error"]
    servers = {
        s["name"]: s.get("credential_set") for s in client.get("/api/env/default/servers").json()
    }
    assert servers["m9"] == "primary"


def test_toggle_credential_storage_purges_on_disable(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "corp"})
    _enable_storage(client, "corp")
    _put_set(client, "corp")
    assert len(client.get("/api/env/corp/credentials").json()) == 1

    resp = client.post("/api/environments/corp/credential-storage", json={"enabled": False})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"enabled": False, "purged_credentials": 1}
    assert client.get("/api/env/corp/credentials").json() == []


def test_unknown_environment_is_404(client: TestClient) -> None:
    assert client.get("/api/env/nope/servers").status_code == 404
    assert client.get("/api/env/nope/credentials").status_code == 404


# -- environment management (create/edit via API) ----------------------------------


def test_default_environment_seeded_from_inventory_file(client: TestClient) -> None:
    # The seed imports management servers from the inventory file into the DB.
    servers = client.get("/api/environments/default/servers").json()
    assert [s["name"] for s in servers] == ["mgmt-01"]  # fw-01 firewall not seeded
    assert servers[0]["role"] == "management"


def test_create_environment_and_add_server(client: TestClient) -> None:
    assert client.post("/api/environments", json={"name": "dmz"}).status_code == 201
    # It now shows up in the environment list.
    assert "dmz" in [e["name"] for e in client.get("/api/environments").json()]

    job = _add_server(client, "dmz", name="mgmt-dmz", address="192.0.2.60", role="management")
    assert job["status"] == "succeeded", job["error"]
    # The new environment is immediately usable operationally (registry rebuilt).
    servers = client.get("/api/env/dmz/servers").json()
    assert [s["name"] for s in servers] == ["mgmt-dmz"]


def test_duplicate_environment_is_409(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "dup"})
    resp = client.post("/api/environments", json={"name": "dup"})
    assert resp.status_code == 409
    assert "already exists" in resp.json()["detail"]


def test_invalid_environment_name_is_400(client: TestClient) -> None:
    resp = client.post("/api/environments", json={"name": "Bad Name!"})
    assert resp.status_code == 400
    assert "invalid environment name" in resp.json()["detail"]


def test_add_firewall_role_server_rejected(client: TestClient) -> None:
    # Validation happens inside the prov.add job (services/prov_ops.py), so it
    # surfaces as a failed job, not a synchronous 400 (matches cred.*).
    job = _add_server(client, name="fw-x", address="192.0.2.70", role="firewall")
    assert job["status"] == "failed"
    assert "not a management server role" in job["error"]


# -- firewalls (distinct from management servers; same CPUSE mechanics) -----------


def test_add_list_remove_firewall(client: TestClient) -> None:
    job = _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    assert job["status"] == "succeeded", job["error"]

    editable = client.get("/api/environments/default/firewalls").json()
    assert [f["name"] for f in editable] == ["fw-x"]
    assert editable[0]["role"] == "firewall"

    # Also visible on the patching-view listing, separate from servers.
    action_view = client.get("/api/env/default/firewalls").json()
    assert [f["name"] for f in action_view] == ["fw-x"]
    assert [s["name"] for s in client.get("/api/env/default/servers").json()] == ["mgmt-01"]

    del_job = _remove_firewall(client, "default", "fw-x")
    assert del_job["status"] == "succeeded", del_job["error"]
    assert client.get("/api/environments/default/firewalls").json() == []


def test_add_firewall_name_collision_with_server_rejected(client: TestClient) -> None:
    job = _add_firewall(client, name="mgmt-01", address="192.0.2.70", role="firewall")
    assert job["status"] == "failed"
    assert "already used by a management server" in job["error"]


def test_add_server_name_collision_with_firewall_rejected(client: TestClient) -> None:
    fw_job = _add_firewall(client, name="fw-y", address="192.0.2.71", role="firewall")
    assert fw_job["status"] == "succeeded", fw_job["error"]
    job = _add_server(client, name="fw-y", address="192.0.2.72", role="management")
    assert job["status"] == "failed"
    assert "already used by a firewall" in job["error"]


def test_add_management_role_firewall_rejected(client: TestClient) -> None:
    job = _add_firewall(client, name="fw-z", address="192.0.2.73", role="management")
    assert job["status"] == "failed"
    assert "not a firewall role" in job["error"]


def test_firewall_new_gets_default_credential_and_can_be_patched(client: TestClient) -> None:
    _put_set(client, name="primary")
    client.post("/api/env/default/credentials/primary/default")
    fw_job = _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    assert fw_job["status"] == "succeeded", fw_job["error"]
    firewalls = {
        f["name"]: f.get("credential_set") for f in client.get("/api/env/default/firewalls").json()
    }
    assert firewalls["fw-x"] == "primary"

    _upload_package(client)
    resp = client.post("/api/env/default/firewalls/fw-x/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_firewall_cluster_recheck_never_falls_back_to_ssh(
    client: TestClient, transport: FakeTransport
) -> None:
    """The "default" environment's only management-plane host is "mgmt-01"
    with role "management" (legacy), not Primary SMS/MDS — so
    DiscoveryService.find_cluster_name has no primary to log into and
    returns None. There is no SSH fallback: a live cphaprob response must be
    ignored entirely, and any previously stored name must survive untouched."""
    _put_set(client, name="primary")
    client.post("/api/env/default/credentials/primary/default")
    fw_job = _add_firewall(client, name="fw-x", address="192.0.2.70", role="cluster_member")
    assert fw_job["status"] == "succeeded", fw_job["error"]

    transport.responses["show cluster state"] = (
        "ID         Unique Address  Assigned Load   State          Name\n"
        "1 (local)  11.22.33.245    100%            ACTIVE(!)      Member1\n"
        "2          11.22.33.246    0%              DOWN           Member2\n"
    )
    resp = client.post("/api/env/default/firewalls/fw-x/cluster-recheck")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"cluster_name": None, "resolved": False}

    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["cluster_name"] is None


def test_firewall_cluster_recheck_preserves_manual_name_when_api_cannot_resolve(
    client: TestClient,
) -> None:
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    set_resp = client.post(
        "/api/env/default/firewalls/fw-x/cluster-name", json={"cluster_name": "prod-cluster"}
    )
    assert set_resp.status_code == 200, set_resp.text
    assert set_resp.json() == {"cluster_name": "prod-cluster"}

    # No primary management server configured — the API can't resolve anything,
    # but the manually-entered name must not be wiped out.
    resp = client.post("/api/env/default/firewalls/fw-x/cluster-recheck")
    assert resp.json() == {"cluster_name": "prod-cluster", "resolved": False}
    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["cluster_name"] == "prod-cluster"


def test_firewall_set_cluster_name_manually_can_clear_it(client: TestClient) -> None:
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/cluster-name", json={"cluster_name": "manual-1"})
    resp = client.post("/api/env/default/firewalls/fw-x/cluster-name", json={"cluster_name": None})
    assert resp.json() == {"cluster_name": None}
    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["cluster_name"] is None


def test_discover_firewalls_import_carries_mds_domain(client: TestClient) -> None:
    """FirewallIn.mds_domain is only applied on genuine creation, same
    JOB_ADD gate as cluster_name — the discover-firewalls import flow relies
    on this to pre-fill it."""
    job = _add_firewall(
        client, name="fw-x", address="192.0.2.70", role="firewall", mds_domain="CustomerA"
    )
    assert job["status"] == "succeeded", job["error"]
    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["mds_domain"] == "CustomerA"

    # An ordinary edit (mds_domain omitted) must not clobber it.
    _add_firewall(client, name="fw-x", address="192.0.2.71", role="firewall")
    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["mds_domain"] == "CustomerA"


def test_firewall_tags_roundtrip_on_both_list_endpoints(client: TestClient) -> None:
    """Tags need to show up on both the editor list (GET .../environments/
    {env}/firewalls, what the edit modal reads) and the cached-state list
    (GET .../env/{env}/firewalls, what the table row renders from) — unlike
    cluster_name/mds_domain, an ordinary edit (tags omitted) also updates
    them, since tags are plain operator data like notes, not JOB_ADD-gated."""
    job = _add_firewall(
        client, name="fw-x", address="192.0.2.70", role="firewall", tags=["prod", "east-region"]
    )
    assert job["status"] == "succeeded", job["error"]

    editable = {f["name"]: f for f in client.get("/api/environments/default/firewalls").json()}
    assert editable["fw-x"]["tags"] == ["prod", "east-region"]
    cached = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert cached["fw-x"]["tags"] == ["prod", "east-region"]

    # An ordinary edit replaces the full tag list, same as notes.
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall", tags=["prod"])
    cached = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert cached["fw-x"]["tags"] == ["prod"]


def test_firewall_set_mds_domain_manually(client: TestClient) -> None:
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    resp = client.post(
        "/api/env/default/firewalls/fw-x/mds-domain", json={"mds_domain": "CustomerB"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"mds_domain": "CustomerB"}
    firewalls = {f["name"]: f for f in client.get("/api/env/default/firewalls").json()}
    assert firewalls["fw-x"]["mds_domain"] == "CustomerB"

    # Clearing it, and unknown firewall 404s (mirrors cluster-name).
    resp = client.post("/api/env/default/firewalls/fw-x/mds-domain", json={"mds_domain": None})
    assert resp.json() == {"mds_domain": None}
    resp = client.post("/api/env/default/firewalls/ghost/mds-domain", json={"mds_domain": "x"})
    assert resp.status_code == 404, resp.text


def test_firewall_cluster_recheck_uses_the_firewalls_stored_mds_domain(
    client: TestClient,
) -> None:
    """Regression guard for the bug report this shipped to fix: on a Multi-
    Domain environment the cluster-name lookup must log into the firewall's
    tracked Domain, not the MDS system context — without a domain, the
    Management API has nothing to scope the lookup to."""
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/mds-domain", json={"mds_domain": "CustomerA"})

    # No primary management server configured in "default" — find_cluster_name
    # can't reach the API regardless, so this only verifies the endpoint reads
    # and forwards the stored domain without erroring, not the login payload
    # itself (that's covered at the service layer, see test_discovery.py).
    resp = client.post("/api/env/default/firewalls/fw-x/cluster-recheck")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"cluster_name": None, "resolved": False}


def test_delete_environment_and_its_servers(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "temp"})
    job = _add_server(client, "temp", name="m1", address="192.0.2.80", role="mds")
    assert job["status"] == "succeeded", job["error"]
    assert client.delete("/api/environments/temp").json() == {"deleted": True}
    assert "temp" not in [e["name"] for e in client.get("/api/environments").json()]
    # Env-scoped access to the deleted environment now 404s.
    assert client.get("/api/env/temp/servers").status_code == 404


def test_delete_environment_purges_its_credentials(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "corp"})
    _enable_storage(client, "corp")
    _put_set(client, "corp")
    assert len(client.get("/api/env/corp/credentials").json()) == 1

    assert client.delete("/api/environments/corp").json() == {"deleted": True}
    # Recreate the same name — no credentials carry over.
    client.post("/api/environments", json={"name": "corp"})
    assert client.get("/api/env/corp/credentials").json() == []


def test_rename_environment_moves_servers_and_credentials(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "old name"})
    _enable_storage(client, "old name")
    job = _add_server(client, "old name", name="m1", address="192.0.2.85", role="management")
    assert job["status"] == "succeeded", job["error"]
    _put_set(client, "old name")

    resp = client.post("/api/environments/old name/rename", json={"name": "New Name"})
    assert resp.status_code == 200
    assert resp.json() == {"name": "New Name"}

    names = [e["name"] for e in client.get("/api/environments").json()]
    assert "New Name" in names and "old name" not in names
    assert [s["name"] for s in client.get("/api/env/New Name/servers").json()] == ["m1"]
    assert len(client.get("/api/env/New Name/credentials").json()) == 1
    assert client.get("/api/env/old name/servers").status_code == 404


def test_rename_environment_errors(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "r1"})
    client.post("/api/environments", json={"name": "r2"})
    assert client.post("/api/environments/ghost/rename", json={"name": "x"}).status_code == 404
    assert client.post("/api/environments/r1/rename", json={"name": "r2"}).status_code == 409
    assert client.post("/api/environments/r1/rename", json={"name": "x!"}).status_code == 400


def test_remove_server(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "e1"})
    job = _add_server(client, "e1", name="m1", address="192.0.2.90", role="management")
    assert job["status"] == "succeeded", job["error"]
    del_job = _remove_server(client, "e1", "m1")
    assert del_job["status"] == "succeeded", del_job["error"]
    assert client.get("/api/environments/e1/servers").json() == []
    # Deleting an already-gone server is a synchronous 404 (pre-submit
    # existence check in ProvisioningJobService.submit_delete_server) — no job
    # row is created for an obviously-doomed delete, same as cred.delete.
    assert client.delete("/api/environments/e1/servers/m1").status_code == 404


# -- servers ---------------------------------------------------------------------


def test_servers_lists_management_only_with_assigned_set(client: TestClient) -> None:
    servers = client.get("/api/env/default/servers").json()
    assert [s["name"] for s in servers] == ["mgmt-01"]
    assert servers[0]["credential_set"] is None
    _add_ssh_credential(client)
    servers = client.get("/api/env/default/servers").json()
    assert servers[0]["credential_set"] == "primary"


def test_state_version_tracks_the_newest_cached_check(client: TestClient) -> None:
    # The token the UI polls while waiting for a background refresh to land
    # (services/state_refresh.py) — null until any host has been checked.
    assert client.get("/api/env/default/state-version").json() == {"checked_at": None}
    _add_ssh_credential(client)
    state = client.post("/api/env/default/servers/mgmt-01/state")
    assert state.status_code == 200, state.text
    token = client.get("/api/env/default/state-version").json()["checked_at"]
    assert token is not None
    # Same value as the row's own checked_at — it IS that timestamp, so a later
    # refresh of any host in the environment moves it.
    assert token.startswith(state.json()["checked_at"][:19])


def test_server_state_detects_live_packages(client: TestClient) -> None:
    _add_ssh_credential(client)
    state = client.post("/api/env/default/servers/mgmt-01/state")
    assert state.status_code == 200, state.text
    body = state.json()
    assert body["agent_build"] == DA_BUILD
    assert body["packages"][0]["is_imported"] is True
    assert body["packages"][1]["is_installed"] is True
    # Check_Point_R81_10_JHF_T45.tgz (installed) -> R81.10 / Take 45.
    assert body["version"] == "R81.10"
    assert body["jhf"] == "Take 45"
    assert body["checked_at"]
    # The Install picker's option comes from a dedicated `show installer
    # packages imported` query (the identifier `installer verify`/`install`
    # actually recognize — see PatchingService._cache_state), not from the
    # `all`-scoped query above — hence "jhf.tgz" here, not the JHF's name in
    # SHOW_PACKAGES_ALL.
    assert body["installable"] == ["jhf.tgz"]


def test_server_state_without_credentials_is_409(client: TestClient) -> None:
    resp = client.post("/api/env/default/servers/mgmt-01/state")
    assert resp.status_code == 409
    assert "no credential assigned" in resp.json()["detail"]


def test_servers_list_exposes_cached_state_after_a_refresh(client: TestClient) -> None:
    _add_ssh_credential(client)
    # Before any /state query, nothing is cached yet.
    before = client.get("/api/env/default/servers").json()[0]
    assert before["version"] is None
    assert before["jhf"] is None
    assert before["checked_at"] is None
    assert before["installable"] == []

    client.post("/api/env/default/servers/mgmt-01/state")

    after = client.get("/api/env/default/servers").json()[0]
    assert after["version"] == "R81.10"
    assert after["jhf"] == "Take 45"
    assert after["checked_at"]
    # See test_server_state_detects_live_packages — installable identifiers
    # come from the dedicated "show installer packages imported" query.
    assert after["installable"] == ["jhf.tgz"]


# -- credentials ------------------------------------------------------------------


def test_credential_sets_roundtrip_never_echoes_secret(client: TestClient) -> None:
    _put_set(client, expert_password="rootpw")
    listing = client.get("/api/env/default/credentials").json()
    assert listing == [
        {
            "name": "primary",
            "environment": "default",
            "ssh_username": "admin",
            "ssh_auth": "password",
            "has_expert": True,
            "has_api": False,
            "is_default": False,
        }
    ]
    assert "pw" not in str(listing) and "rootpw" not in str(listing)
    resp = client.delete("/api/env/default/credentials/primary")
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "cred.delete"
    assert client.get("/api/env/default/credentials").json() == []


def test_missing_expert_password_fails_as_a_job_not_a_sync_422(client: TestClient) -> None:
    """Every credential set requires an expert-mode password now (every
    stored host is a management server or a firewall, either of which may
    escalate to expert mode — see .claude/memory/gaia-shell-posture.md), not
    just Spark's old opt-in require_expert flag. CredentialStore.put_set
    enforces it, so — same as any other put_set validation error (e.g. a
    missing SSH secret) — it surfaces as a failed job, not a synchronous
    422."""
    resp = client.put(
        "/api/env/default/credentials",
        json={"name": "spark-01", "ssh_username": "admin", "ssh_password": "pw"},
    )
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "failed"
    assert "expert-mode password" in (job["error"] or "")
    assert client.get("/api/env/default/credentials").json() == []  # nothing written


def test_expert_password_accepted_and_listed(client: TestClient) -> None:
    resp = client.put(
        "/api/env/default/credentials",
        json={
            "name": "spark-01",
            "ssh_username": "admin",
            "ssh_password": "pw",
            "expert_password": "expertpw",
        },
    )
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    listing = client.get("/api/env/default/credentials").json()
    assert listing[0]["has_expert"] is True


def test_locked_credential_store_returns_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    app = create_app(_config(tmp_path))
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200  # app still boots
        resp = c.get("/api/env/default/credentials")
        assert resp.status_code == 503
        assert "master key" in resp.json()["detail"]
        assert c.get("/api/status").json()["credentials_unlocked"] is False


def test_seeded_environment_storage_still_requires_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """config.yaml-seeded environments (e.g. "default") get
    credential_storage_enabled=True in the DB unconditionally (see
    EnvironmentManager.seed_from_config) — that's a stored preference, not a
    guarantee. With the master key set but no authenticator configured, that
    preference must NOT translate into usable storage: same prerequisite
    (master key + auth) as a UI-created environment, which starts with
    storage off and can't be flipped on without auth either (see
    _enable_storage's use elsewhere)."""
    monkeypatch.setenv(MASTER_KEY_ENV, "api test master key")
    app = create_app(_config(tmp_path))  # no authenticator passed -> auth off
    with TestClient(app) as c:
        status = c.get("/api/status").json()
        assert status["auth_enabled"] is False
        assert status["credentials_unlocked"] is True

        envs = {e["name"]: e for e in c.get("/api/environments").json()}
        assert envs["default"]["credential_storage_enabled"] is False

        # Trying to actually store a credential set is blocked exactly like it
        # would be for a fresh environment that never had storage seeded on.
        resp = c.put(
            "/api/env/default/credentials",
            json={"name": "primary", "ssh_username": "admin", "ssh_password": "pw"},
        )
        assert resp.status_code == 409
        assert "authentication" in resp.json()["detail"]


# -- packages ---------------------------------------------------------------------


def test_package_upload_list_delete(client: TestClient) -> None:
    _upload_package(client, content=b"payload-bytes")
    listing = client.get("/api/packages").json()
    assert listing[0]["filename"] == "jhf.tgz"
    assert listing[0]["size"] == len(b"payload-bytes")
    assert len(listing[0]["sha256"]) == 64

    resp = client.delete("/api/packages/jhf.tgz")
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    assert client.get("/api/packages").json() == []


def test_package_upload_extracts_compatibility_metadata(client: TestClient) -> None:
    hf_config = (
        "2474\nPATCH_NAME=BUNDLE_R82_10_JUMBO_HF_MAIN\nTAKE_NUMBER=24\n"
        "PACKAGE_TYPE=BUNDLE\nARCH=x86_64\nCATEGORY=JUMBO\nDIRECT_BASE_VERSION=R82.10\n"
    )
    conditions = '{"set_description": "This hotfix is supported only for R82.10.\\n"}'
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in {
            "hf.config": hf_config.encode(),
            "conditions_set.json": conditions.encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

    _upload_package(client, name="jhf_t24.tar", content=buf.getvalue())
    listing = client.get("/api/packages").json()
    assert listing[0]["direct_base_version"] == "R82.10"
    assert listing[0]["take_number"] == 24
    assert listing[0]["category"] == "JUMBO"
    assert listing[0]["arch"] == "x86_64"
    assert listing[0]["compatibility_note"] == "This hotfix is supported only for R82.10."


def test_package_conflict_rejected(client: TestClient) -> None:
    _upload_package(client, content=b"original")
    # The name/content dedupe check only runs once add_stream hashes the
    # staged file, so the conflict surfaces as a failed job in the (already
    # terminal) response, not an immediate HTTP error (unlike retention/delete,
    # which 404 synchronously since PackageStore.get() is cheap to check
    # before creating a job at all).
    resp = client.post("/api/packages", files={"file": ("jhf.tgz", b"different")})
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "failed"
    assert "different content" in job["error"]


def test_uploaded_package_gets_default_expiry(client: TestClient) -> None:
    _upload_package(client)
    rec = client.get("/api/packages").json()[0]
    assert rec["expires_at"] is not None  # retention window applied by default


def test_package_retention_pin_and_unpin(client: TestClient) -> None:
    _upload_package(client)

    resp = client.post("/api/packages/jhf.tgz/retention", json={"pinned": True})
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "pkgs.keep"
    assert client.get("/api/packages").json()[0]["expires_at"] is None  # kept indefinitely

    resp = client.post("/api/packages/jhf.tgz/retention", json={"pinned": False})
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "pkgs.notkeep"
    assert client.get("/api/packages").json()[0]["expires_at"] is not None  # window reapplied


def test_package_retention_missing_is_404(client: TestClient) -> None:
    # Still an immediate 404 — submit_retention() checks existence before
    # creating a job at all, so an unknown filename never gets a job row.
    resp = client.post("/api/packages/ghost.tgz/retention", json={"pinned": True})
    assert resp.status_code == 404


def test_push_package_to_repo_starts_a_job(client: TestClient) -> None:
    # Unlike the rest of the packages section, this genuinely needs a real
    # primary (mgmt-01 in the default fixture inventory only has the legacy
    # "management" role, which primary_mgmt_host() doesn't recognize).
    job = _add_server(client, name="m9", address="192.0.2.99", role="primary_sms")
    assert job["status"] == "succeeded", job["error"]
    _add_ssh_credential(client, host="m9")
    _upload_package(client)

    resp = client.post("/api/env/default/packages/jhf.tgz/push-to-repo", json={})
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["kind"] == "pkgs.push_to_repo"
    assert job["status"] == "pending"


def test_push_package_to_repo_missing_package_is_404(client: TestClient) -> None:
    job = _add_server(client, name="m9", address="192.0.2.99", role="primary_sms")
    assert job["status"] == "succeeded", job["error"]
    _add_ssh_credential(client, host="m9")

    resp = client.post("/api/env/default/packages/ghost.tgz/push-to-repo", json={})
    assert resp.status_code == 404


def test_push_package_to_repo_without_a_primary_is_400(client: TestClient) -> None:
    # default fixture's mgmt-01 is role "management" (legacy), not a primary.
    _upload_package(client)
    resp = client.post("/api/env/default/packages/jhf.tgz/push-to-repo", json={})
    assert resp.status_code == 400
    assert "no primary" in resp.json()["detail"].lower()


# -- import / install jobs through the API ----------------------------------------


def test_import_flow_end_to_end(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    _upload_package(client)

    resp = client.post("/api/env/default/servers/mgmt-01/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    events = client.get(f"/api/jobs/{job['id']}/events").json()
    assert any("confirmed: package is listed as imported" in e["message"] for e in events)
    assert transport.puts[0][1] == "/var/log/upload/jhf.tgz"


def test_bulk_import_starts_a_job_for_every_selected_server(
    client: TestClient, transport: FakeTransport
) -> None:
    """Reproduces the app.js bulk-import flow (select multiple rows -> Upload
    and import) for two management servers, one host at a time, exactly as
    bulkImport()'s sequential loop does. Regression guard for an operator
    report that only the first selected server's job was ever queued.

    No precheck step: the disk-space check moved inside the import job
    (operator-directed, 2026-08-26), so bulk import now submits every job
    straight away instead of blocking on a per-host SSH round trip."""
    _add_ssh_credential(client, "mgmt-01")
    job = _add_server(client, "default", name="mgmt-02", address="192.0.2.11", role="management")
    assert job["status"] == "succeeded", job["error"]
    _assign_set(client, "mgmt-02")
    _upload_package(client)

    job_ids = []
    for host in ("mgmt-01", "mgmt-02"):
        resp = client.post(
            f"/api/env/default/servers/{host}/import",
            json={"package": "jhf.tgz", "force_low_space": False},
        )
        assert resp.status_code == 202, resp.text
        job_ids.append(resp.json()["id"])

    assert len(job_ids) == 2
    assert len(set(job_ids)) == 2  # two distinct jobs, not the same one twice
    for job_id in job_ids:
        finished = _wait_for_job(client, job_id)
        assert finished["status"] == "succeeded", finished["error"]

    targets = {j["target"] for j in client.get("/api/jobs?limit=0").json()}
    assert {"mgmt-01", "mgmt-02"} <= targets


def test_recheck_import_route_resolves_timed_out_job(
    client: TestClient, transport: FakeTransport
) -> None:
    """Simulates the Jobs tab's "Check status" link without waiting out a
    real 5-minute poll: inserts a TIMED_OUT cpuse.import job directly (same
    shape submit_import would have produced), same as the server would once
    _wait_until_imported gave up — then hits the route the "Check status"
    link calls."""
    _add_ssh_credential(client)
    _upload_package(client)
    store = client.app.state.store
    job = JobRecord(
        kind="cpuse.import",
        target="mgmt-01",
        environment="default",
        params={"package": "jhf.tgz"},
    )
    store.insert_job(job)
    store.finish_job(job.id, JobStatus.TIMED_OUT, error="gave up waiting")

    resp = client.post(f"/api/jobs/{job.id}/recheck-import", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"

    events = client.get(f"/api/jobs/{job.id}/events").json()
    assert any("manual check: confirmed" in e["message"] for e in events)


def test_recheck_import_route_leaves_job_timed_out_when_still_not_imported(
    client: TestClient, transport: FakeTransport
) -> None:
    _add_ssh_credential(client)
    _upload_package(client)
    transport.responses["show installer packages imported"] = ""
    store = client.app.state.store
    job = JobRecord(
        kind="cpuse.import",
        target="mgmt-01",
        environment="default",
        params={"package": "jhf.tgz"},
    )
    store.insert_job(job)
    store.finish_job(job.id, JobStatus.TIMED_OUT, error="gave up waiting")

    resp = client.post(f"/api/jobs/{job.id}/recheck-import", json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "timed_out"


def test_recheck_import_route_rejects_job_that_is_not_timed_out(
    client: TestClient, transport: FakeTransport
) -> None:
    _add_ssh_credential(client)
    _upload_package(client)

    resp = client.post("/api/env/default/servers/mgmt-01/import", json={"package": "jhf.tgz"})
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    resp = client.post(f"/api/jobs/{job['id']}/recheck-import", json={})
    assert resp.status_code == 400
    assert "isn't timed out" in resp.json()["detail"]


def test_import_cloud_flow_end_to_end(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)

    resp = client.post(
        "/api/env/default/servers/mgmt-01/import-cloud",
        json={"package_id": "Check_Point_R81.20_JHF_T99"},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    events = client.get(f"/api/jobs/{job['id']}/events").json()
    assert any("import finished" in e["message"] for e in events)
    assert transport.puts == []  # no upload — nothing was staged locally


def test_jobs_facets_and_filters(client: TestClient) -> None:
    _add_ssh_credential(client)
    _upload_package(client)
    # Sequential — a second job for the same host is now rejected while one
    # is still pending/running (see PatchingService._ensure_host_free).
    import_job = client.post(
        "/api/env/default/servers/mgmt-01/import", json={"package": "jhf.tgz"}
    ).json()
    _wait_for_job(client, import_job["id"])
    cloud_job = client.post(
        "/api/env/default/servers/mgmt-01/import-cloud",
        json={"package_id": "Check_Point_R81.20_JHF_T99"},
    ).json()
    _wait_for_job(client, cloud_job["id"])

    # Facets reflect every job, not just whatever a limited /api/jobs page shows.
    # _upload_package() also runs a pkgs.upload job (target: the filename), so
    # these check "at least" rather than an exact set/list.
    facets = client.get("/api/jobs/facets").json()
    assert {"cpuse.import", "cpuse.import_cloud"} <= set(facets["kinds"])
    assert {"mgmt-01"} <= set(facets["targets"])
    assert facets["environments"] == ["default"]
    assert facets["statuses"] == ["succeeded"]
    assert facets["usernames"] == [TEST_USER]  # every job here ran as the logged-in operator

    by_kind = client.get("/api/jobs", params={"kind": "cpuse.import"}).json()
    assert {j["id"] for j in by_kind} == {import_job["id"]}

    by_status = client.get("/api/jobs", params={"status": "succeeded"}).json()
    assert {j["id"] for j in by_status} >= {import_job["id"], cloud_job["id"]}

    none_match = client.get("/api/jobs", params={"kind": "cpuse.install"}).json()
    assert none_match == []

    bad_status = client.get("/api/jobs", params={"status": "not-a-real-status"})
    assert bad_status.status_code == 400


def test_job_records_and_filters_by_triggering_user(client: TestClient) -> None:
    _add_ssh_credential(client)
    resp = client.post(
        "/api/env/default/servers/mgmt-01/import-cloud",
        json={"package_id": "Check_Point_R81.20_JHF_T99"},
    )
    job_id = resp.json()["id"]
    job = _wait_for_job(client, job_id)
    assert job["username"] == TEST_USER

    matching = client.get(f"/api/jobs?user={TEST_USER}").json()
    assert job_id in [j["id"] for j in matching]
    assert client.get("/api/jobs?user=nobody").json() == []


def test_install_requires_confirmation_flag(client: TestClient) -> None:
    _add_ssh_credential(client)
    resp = client.post(
        "/api/env/default/servers/mgmt-01/install",
        json={"package_id": "Check_Point_R81_20_T89", "confirmed": False},
    )
    assert resp.status_code == 400
    assert "confirmation" in resp.json()["detail"]


def test_install_flow_end_to_end(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    resp = client.post(
        "/api/env/default/servers/mgmt-01/install",
        json={"package_id": "Check_Point_R81_20_T89", "confirmed": True},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert any("installer install" in c for c in transport.commands)


def test_import_against_firewall_not_in_inventory_is_404(client: TestClient) -> None:
    # Firewalls are not seeded into an environment's management-server inventory
    # (only management/mds roles are), so a firewall name is simply unknown here.
    _upload_package(client)
    resp = client.post("/api/env/default/servers/fw-01/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


# -- CDT --------------------------------------------------------------------------


def test_cdt_status_endpoint(client: TestClient) -> None:
    _add_ssh_credential(client)
    body = client.post("/api/env/default/cdt/mgmt-01/status").json()
    assert body == {"available": True, "running": False, "brief": ""}


def test_cdt_candidates_get_and_put(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    cands = client.post("/api/env/default/cdt/mgmt-01/candidates/read").json()
    assert cands["header"][0] == "Object Name"
    assert len(cands["rows"]) == 2

    # Reverse the order and save — this is the blast-radius edit.
    resp = client.put(
        "/api/env/default/cdt/mgmt-01/candidates",
        json={"header": cands["header"], "rows": list(reversed(cands["rows"]))},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"rows": 2}
    assert transport.puts[-1][1] == "/opt/CPcdt/orch_candidates.csv"


def test_cdt_execute_requires_confirmation(client: TestClient) -> None:
    _add_ssh_credential(client)
    resp = client.post("/api/env/default/cdt/mgmt-01/execute", json={"confirmed": False})
    assert resp.status_code == 400
    assert "confirmation" in resp.json()["detail"]


def test_cdt_stage_and_generate_flow(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    _upload_package(client)
    transport.responses["stat -c %s"] = (1, "")  # package not staged yet

    resp = client.post("/api/env/default/cdt/mgmt-01/stage", json={"package": "jhf.tgz"})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert transport.puts[0][1] == "/var/log/upload/jhf.tgz"
    assert transport.puts[1][1] == "/opt/CPcdt/CentralDeploymentTool.xml"

    resp = client.post("/api/env/default/cdt/mgmt-01/generate")
    assert resp.status_code == 202
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_cdt_endpoints_locked_without_credentials(client: TestClient) -> None:
    # No credential set assigned to the host → 409 with a clear message.
    resp = client.post("/api/env/default/cdt/mgmt-01/status")
    assert resp.status_code == 409
    assert "no credential assigned" in resp.json()["detail"]


# -- storage-disabled environments (inline credentials per operation) --------------


def _disabled_env_with_server(
    client: TestClient, env: str = "dmz", server: str = "mgmt-01"
) -> None:
    assert client.post("/api/environments", json={"name": env}).status_code == 201
    job = _add_server(client, env, name=server, address="192.0.2.10", role="management")
    assert job["status"] == "succeeded", job["error"]


def test_storage_disabled_job_requires_inline_credentials(client: TestClient) -> None:
    _disabled_env_with_server(client)
    _upload_package(client)

    # No credentials in the body → 400 with a clear message.
    resp = client.post("/api/env/dmz/servers/mgmt-01/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 400
    assert "does not store credentials" in resp.json()["detail"]

    # Inline credentials → the job runs to completion.
    resp = client.post(
        "/api/env/dmz/servers/mgmt-01/import",
        json={"package": "jhf.tgz", "credentials": _SSH_CREDS_WITH_EXPERT},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_storage_disabled_state_query_requires_inline_credentials(client: TestClient) -> None:
    _disabled_env_with_server(client)
    # Live-state query with no credentials → 400.
    assert client.post("/api/env/dmz/servers/mgmt-01/state").status_code == 400
    # With inline credentials it works, one-shot.
    resp = client.post("/api/env/dmz/servers/mgmt-01/state", json={"credentials": _SSH_CREDS})
    assert resp.status_code == 200, resp.text
    assert resp.json()["agent_build"] == DA_BUILD


def test_storage_disabled_env_works_without_master_key(
    tmp_path: Path, transport: FakeTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A storage-disabled environment never touches the credential store, so it
    # operates even with no master key set (the store stays locked).
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    app = create_app(_config(tmp_path), client_factory=make_factory(transport))
    with TestClient(app) as c:
        assert c.get("/api/status").json()["credentials_unlocked"] is False
        c.post("/api/environments", json={"name": "dmz"})
        job = _add_server(c, "dmz", name="mgmt-01", address="192.0.2.10", role="management")
        assert job["status"] == "succeeded", job["error"]
        resp = c.post("/api/env/dmz/servers/mgmt-01/state", json={"credentials": _SSH_CREDS})
        assert resp.status_code == 200, resp.text
        assert resp.json()["agent_build"] == DA_BUILD


# -- provisioning -----------------------------------------------------------------


def test_provision_renders_commands_without_plaintext(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "svc-patch", "password": "s3cret-pw!"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["commands"][3] == "set user svc-patch gid 100"
    assert "s3cret-pw!" not in resp.text  # only the salted hash is echoed
    assert any("clish" in n for n in body["notes"])
    # Management API provisioning is a separate step now (Connect to Primary) —
    # this endpoint only renders the Gaia clish commands.
    assert "api_commands" not in body


def test_provision_rejects_bad_input(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "BAD NAME", "password": "longenough"})
    assert resp.status_code == 400
    assert "invalid username" in resp.json()["detail"]


# -- connect to primary (SSH-executed Management API provisioning) ----------------


def test_connect_primary_preview_renders_commands(client: TestClient) -> None:
    resp = client.get(
        "/api/environments/default/connect-primary/preview", params={"username": "svc-patch"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert any('authentication-method "api key"' in c for c in body["commands"])
    assert any("add api-key admin-name svc-patch" in c for c in body["commands"])


def test_connect_primary_preview_rejects_bad_username(client: TestClient) -> None:
    resp = client.get(
        "/api/environments/default/connect-primary/preview", params={"username": "Bad Name"}
    )
    assert resp.status_code == 400
    assert "invalid username" in resp.json()["detail"]


def test_connect_primary_captures_and_stores_key(client: TestClient) -> None:
    _enable_storage(client, "default")
    _put_set(client, "default", "primary", ssh_username="svc-patch")
    resp = client.post(
        "/api/environments/default/connect-primary",
        json={
            "name": "mgmt-01",
            "address": "192.0.2.10",
            "role": "primary_sms",
            "ssh_user": "svc-patch",
            "ssh_port": 22,
            "credential_set": "primary",
        },
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    # Auto-persisted to the credential set.
    sets = client.get("/api/env/default/credentials").json()
    primary = next(s for s in sets if s["name"] == "primary")
    assert primary["has_api"] is True

    # Pop-once reveal: present once, null on the second call.
    reveal = client.post(f"/api/jobs/{job['id']}/reveal-api-key")
    assert reveal.status_code == 200, reveal.text
    assert reveal.json()["api_key"] == "generated-key-xyz"
    reveal_again = client.post(f"/api/jobs/{job['id']}/reveal-api-key")
    assert reveal_again.json()["api_key"] is None


def test_reveal_api_key_unknown_job_returns_null(client: TestClient) -> None:
    resp = client.post("/api/jobs/no-such-job/reveal-api-key")
    assert resp.status_code == 200, resp.text
    assert resp.json()["api_key"] is None


# -- Management API accessibility diagnose/repair (SSH) — 403 follow-up -----------


def _primary_with_ssh(client: TestClient) -> None:
    """A Primary SMS with an assigned SSH credential set — what
    ApiAccessService.diagnose/submit_repair need to reach `mgmt-01` at all."""
    _enable_storage(client, "default")
    job = _add_server(client, name="mgmt-01", address="192.0.2.10", role="primary_sms")
    assert job["status"] == "succeeded", job["error"]
    _add_ssh_credential(client, "mgmt-01")


def test_diagnose_api_access_reports_restricted_to_local(
    client: TestClient, transport: FakeTransport
) -> None:
    _primary_with_ssh(client)
    transport.responses["api status"] = (
        0,
        "Overall API Status: Started\nAccessibility: require local\n",
    )
    resp = client.post("/api/environments/default/api-access/diagnose")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["error"] is None
    assert body["overall_started"] is True
    assert body["restricted_to_local"] is True


def test_diagnose_api_access_no_primary_returns_error(client: TestClient) -> None:
    resp = client.post("/api/environments/default/api-access/diagnose")
    assert resp.status_code == 200, resp.text
    assert resp.json()["error"] is not None


def test_api_access_repair_preview_renders_commands(client: TestClient) -> None:
    _primary_with_ssh(client)
    resp = client.get("/api/environments/default/api-access/repair-preview")
    assert resp.status_code == 200, resp.text
    commands = resp.json()["commands"]
    assert any("set api-settings accepted-api-calls-from" in c for c in commands)
    assert commands[-1] == "api restart"


def test_api_access_repair_widens_accessibility(
    client: TestClient, transport: FakeTransport
) -> None:
    _primary_with_ssh(client)
    transport.responses["api status"] = (
        0,
        "Overall API Status: Started\nAccessibility: require local\n",
    )
    resp = client.post("/api/environments/default/api-access/repair", json={"confirmed": True})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert any("set api-settings accepted-api-calls-from" in c for c in transport.commands)
    assert "api restart" in transport.commands


# -- firewall credential bootstrap (Firewalls panel auth-failure recovery) --------


def test_firewall_bootstrap_credentials_preview_renders_commands(client: TestClient) -> None:
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    resp = client.post("/api/env/default/firewalls/fw-x/credential", json={"set": "primary"})
    assert resp.status_code == 200, resp.text

    resp = client.get("/api/env/default/firewalls/fw-x/bootstrap-credentials/preview")
    assert resp.status_code == 200, resp.text
    commands = resp.json()["commands"]
    assert commands[0] == "add user admin uid 0 homedir /home/admin"
    # No real hash over the wire — this GET is open to every authenticated user
    # and a 5000-round sha512_crypt hash is offline-crackable.
    assert not any("$6$" in c for c in commands)
    assert "password-hash" in commands[1]


def test_firewall_bootstrap_credentials_preview_rejects_key_only_set(client: TestClient) -> None:
    _put_set(
        client, name="keyset", ssh_username="admin", ssh_password=None, ssh_private_key="KEYDATA"
    )
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/credential", json={"set": "keyset"})

    resp = client.get("/api/env/default/firewalls/fw-x/bootstrap-credentials/preview")
    assert resp.status_code == 409, resp.text
    assert "private key, not a" in resp.json()["detail"]


def test_firewall_bootstrap_credentials_preview_requires_assigned_credential(
    client: TestClient,
) -> None:
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    resp = client.get("/api/env/default/firewalls/fw-x/bootstrap-credentials/preview")
    assert resp.status_code == 409, resp.text
    assert "no credential assigned" in resp.json()["detail"]


def test_firewall_bootstrap_credentials_submit_queues_a_job(client: TestClient) -> None:
    # Full run-script execution against a real Management API is covered at
    # the service layer (test_firewall_bootstrap.py, with a fake mgmt client) —
    # this only confirms the endpoint queues the right job kind/target.
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/credential", json={"set": "primary"})

    resp = client.post(
        "/api/env/default/firewalls/fw-x/bootstrap-credentials", json={"confirmed": True}
    )
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["kind"] == "cred.bootstrap"
    assert job["target"] == "fw-x"


def test_firewall_bootstrap_credentials_submit_rejects_unknown_firewall(
    client: TestClient,
) -> None:
    resp = client.post(
        "/api/env/default/firewalls/nope/bootstrap-credentials", json={"confirmed": True}
    )
    assert resp.status_code == 404, resp.text


def test_firewall_bootstrap_credentials_preview_rejects_spark_firewall(
    client: TestClient,
) -> None:
    # Spark uses a different clish command family (add administrator) — see
    # the spark-bootstrap-admin/preview route below.
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.get("/api/env/default/firewalls/spark-x/bootstrap-credentials/preview")
    assert resp.status_code == 400, resp.text
    assert "Spark firewall" in resp.json()["detail"]


def test_firewall_bootstrap_credentials_submit_rejects_spark_firewall(
    client: TestClient,
) -> None:
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.post(
        "/api/env/default/firewalls/spark-x/bootstrap-credentials", json={"confirmed": True}
    )
    assert resp.status_code == 400, resp.text
    assert "Spark firewall" in resp.json()["detail"]


def test_firewall_spark_bootstrap_admin_preview_renders_add_administrator(
    client: TestClient,
) -> None:
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.get("/api/env/default/firewalls/spark-x/spark-bootstrap-admin/preview")
    assert resp.status_code == 200, resp.text
    commands = resp.json()["commands"]
    assert len(commands) == 1
    assert commands[0].startswith("add administrator username admin password-hash $6$")


def test_firewall_spark_bootstrap_admin_preview_rejects_non_spark_firewall(
    client: TestClient,
) -> None:
    _put_set(client, name="primary", ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/credential", json={"set": "primary"})

    resp = client.get("/api/env/default/firewalls/fw-x/spark-bootstrap-admin/preview")
    assert resp.status_code == 400, resp.text
    assert "not a Spark firewall" in resp.json()["detail"]


# -- Spark firmware patching (services/spark_patching.py) -------------------------


def test_firewall_spark_test_credentials_succeeds(client: TestClient) -> None:
    # FakeTransport's default expert_password ("expert-pw") matches this set.
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.post("/api/env/default/firewalls/spark-x/spark-test-credentials")
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_cannot_create_a_credential_set_without_an_expert_password(
    client: TestClient,
) -> None:
    """Every credential set requires an expert-mode password now (see
    CredentialStore.put_set), so a Spark firewall — which always needs one to
    patch — can no longer end up assigned to a set that lacks one, the way it
    could under the old Spark-only opt-in require_expert flag. The failure
    now shows up right here, not deep inside a later spark-test-credentials
    job."""
    resp = client.put(
        "/api/env/default/credentials",
        json={"name": "primary", "ssh_username": "admin", "ssh_password": "s3cret-pw!"},
    )
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["status"] == "failed"
    assert "expert-mode password" in (job["error"] or "")
    assert client.get("/api/env/default/credentials").json() == []


def test_firewall_spark_test_credentials_rejects_non_spark_firewall(client: TestClient) -> None:
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!")
    _add_firewall(client, name="fw-x", address="192.0.2.70", role="firewall")
    client.post("/api/env/default/firewalls/fw-x/credential", json={"set": "primary"})

    resp = client.post("/api/env/default/firewalls/fw-x/spark-test-credentials")
    assert resp.status_code == 400, resp.text
    assert "not a Spark firewall" in resp.json()["detail"]


def test_firewall_spark_import_rejects_non_image_package(client: TestClient) -> None:
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})
    _upload_package(client, name="jhf.tgz")

    resp = client.post(
        "/api/env/default/firewalls/spark-x/spark-import",
        json={"package": "jhf.tgz"},
    )
    assert resp.status_code == 400, resp.text
    assert "Spark firmware image" in resp.json()["detail"]


def test_firewall_install_dispatches_to_spark_requires_confirmation(client: TestClient) -> None:
    """The row-level Install button/endpoint is shared with CPUSE-patched
    firewalls (InstallRequest) — for a Spark row it must dispatch to
    SparkPatchingService.submit_install rather than the CPUSE path, and
    still gate on an explicit confirm since it reboots the device."""
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})
    _upload_package(client, name="spark.img", content=b"x" * 64)

    resp = client.post(
        "/api/env/default/firewalls/spark-x/install",
        json={"package_id": "spark.img", "confirmed": False},
    )
    assert resp.status_code == 400, resp.text
    assert "confirmation" in resp.json()["detail"]


def test_firewall_install_dispatches_to_spark_succeeds(
    client: TestClient, transport: FakeTransport
) -> None:
    # Install now verifies the post-reboot build via `fw ver` (operator-
    # directed 2026-08-20, see spark-firmware-patching.md) — the filename's
    # trailing digits (here "936") must match what `fw ver` reports back.
    image = "fw1_vx_dep_R81_10_17_996004936.img"
    transport.responses["fw ver"] = "This is Check Point's 1550 Appliance R81.10.17 - Build 936"
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.post(
        "/api/env/default/firewalls/spark-x/install",
        json={"package_id": image, "confirmed": True},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_firewall_state_spark_uses_fw_ver_not_cpuse(
    client: TestClient, transport: FakeTransport
) -> None:
    transport.responses["fw ver"] = "This is Check Point's 1550 Appliance R81.10.17 - Build 892"
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})

    resp = client.post("/api/env/default/firewalls/spark-x/state")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == "1550 Appliance R81.10.17 - Build 892"
    assert body["jhf"] is None
    assert body["agent_build"] is None
    assert body["packages"] == []
    assert not any("installer" in c or "cluster state" in c for c in transport.commands)


def test_firewall_spark_import_succeeds(client: TestClient) -> None:
    # sha1 of b"x" * 64 matches the transport fixture's canned `sha1sum` reply
    # regardless of filename (it hashes content, not the path echoed back).
    _put_set(client, ssh_username="admin", ssh_password="s3cret-pw!", expert_password="expert-pw")
    _add_firewall(client, name="spark-x", address="192.0.2.80", role="spark_firewall")
    client.post("/api/env/default/firewalls/spark-x/credential", json={"set": "primary"})
    _upload_package(client, name="spark.img", content=b"x" * 64)

    resp = client.post(
        "/api/env/default/firewalls/spark-x/spark-import",
        json={"package": "spark.img"},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    # Staged — listed as installable without a separate Refresh, and ready
    # for the row's Install button (see test_firewall_install_dispatches_to_spark_*).
    listing = client.get("/api/env/default/firewalls").json()
    spark_row = next(f for f in listing if f["name"] == "spark-x")
    assert spark_row["installable"] == ["spark.img"]


# -- jobs -------------------------------------------------------------------------


def test_unknown_job_is_404(client: TestClient) -> None:
    assert client.get("/api/jobs/nope").status_code == 404


# -- multiple independent environments ---------------------------------------------

INVENTORY_B_YAML = """\
sites:
  - name: other-site
    hosts:
      - name: mgmt-b1
        address: 192.0.2.50
        role: management
"""


def test_two_environments_are_isolated(
    tmp_path: Path, transport: FakeTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(MASTER_KEY_ENV, "api test master key")
    (tmp_path / "corp.yaml").write_text(INVENTORY_YAML, encoding="utf-8")
    (tmp_path / "dmz.yaml").write_text(INVENTORY_B_YAML, encoding="utf-8")
    cfg = _config(tmp_path)
    cfg.environments = [
        EnvironmentDef(name="corp", inventory=tmp_path / "corp.yaml"),
        EnvironmentDef(name="dmz", inventory=tmp_path / "dmz.yaml"),
    ]
    app = create_app(
        cfg,
        client_factory=make_factory(transport),
        authenticator=_fake_auth(),
        auth_settings=AUTH_SETTINGS,
    )
    with TestClient(app) as c:
        _login(c)
        # Both environments visible, each with its own inventory.
        envs = {e["name"]: e["management_servers"] for e in c.get("/api/environments").json()}
        assert envs == {"corp": 1, "dmz": 1}
        assert [s["name"] for s in c.get("/api/env/corp/servers").json()] == ["mgmt-01"]
        assert [s["name"] for s in c.get("/api/env/dmz/servers").json()] == ["mgmt-b1"]

        # A credential set in corp is invisible in dmz — and does not authorize
        # actions there.
        _put_set(c, "corp")
        _assign_set(c, "mgmt-01", env="corp")
        assert len(c.get("/api/env/corp/credentials").json()) == 1
        assert c.get("/api/env/dmz/credentials").json() == []

        state = c.post("/api/env/dmz/servers/mgmt-b1/state")
        assert state.status_code == 409  # no set assigned in dmz
        assert "no credential assigned" in state.json()["detail"]

        # Jobs record which environment they belong to.
        _upload_package(c)
        job = c.post("/api/env/corp/servers/mgmt-01/import", json={"package": "jhf.tgz"})
        assert job.status_code == 202
        assert job.json()["environment"] == "corp"


# -- accept-host-key (H1) ----------------------------------------------------------
#
# Recovery path for a legitimately rebuilt Gaia host, whose changed SSH key
# otherwise fails every job closed. Confirm-gated because the same symptom is
# what an intercepted connection looks like. See transport/ssh.py.


def test_accept_host_key_requires_confirmation(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/default/hosts/mgmt-01/accept-host-key", json={"confirmed": False}
    )
    assert resp.status_code == 400
    assert "explicit confirmation" in resp.json()["detail"]


def test_accept_host_key_defaults_to_unconfirmed(client: TestClient) -> None:
    """An empty body must not be treated as consent."""
    resp = client.post("/api/environments/default/hosts/mgmt-01/accept-host-key", json={})
    assert resp.status_code == 400


def test_accept_host_key_succeeds_when_confirmed(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/default/hosts/mgmt-01/accept-host-key", json={"confirmed": True}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["host"] == "mgmt-01"
    assert body["address"] == "192.0.2.10"
    # Nothing was pinned in this test run, so there was no entry to clear —
    # still a success, so the operator isn't left with a confusing error.
    assert body["cleared"] is False


def test_accept_host_key_404s_for_an_unknown_host(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/default/hosts/nope/accept-host-key", json={"confirmed": True}
    )
    assert resp.status_code == 404


def test_accept_host_key_404s_for_an_unknown_environment(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/nosuchenv/hosts/mgmt-01/accept-host-key", json={"confirmed": True}
    )
    assert resp.status_code == 404


# -- retry with override (disk-space check now lives inside the import job) --------


def test_retry_with_override_route_rejects_a_job_that_did_not_fail_that_way(
    client: TestClient, transport: FakeTransport
) -> None:
    """The Jobs-tab link must not become a way to blanket-force any import."""
    _add_ssh_credential(client, "mgmt-01")
    _upload_package(client)
    transport.put_size = lambda local: 1  # fail on size mismatch, not disk space
    resp = client.post(
        "/api/env/default/servers/mgmt-01/import",
        json={"package": "jhf.tgz", "force_low_space": False},
    )
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]
    finished = _wait_for_job(client, job_id)
    assert finished["status"] == "failed"
    assert "size mismatch" in (finished["error"] or "")

    retry = client.post(f"/api/jobs/{job_id}/retry-import-with-override", json={})
    assert retry.status_code == 400
    assert "overridable disk-space shortfall" in retry.json()["detail"]


def test_disk_space_precheck_routes_are_gone(client: TestClient) -> None:
    """The check moved into the import job (operator-directed, 2026-08-26);
    the synchronous probes it replaced must not linger as a second path."""
    for kind in ("servers", "firewalls"):
        resp = client.post(
            f"/api/env/default/{kind}/mgmt-01/import/disk-space", json={"package": "jhf.tgz"}
        )
        # 405: the path no longer matches an API route and falls through to
        # the static mount, which serves GET only. Either way it is gone.
        assert resp.status_code in (404, 405), f"{kind}: {resp.status_code}"


# -- security headers (Phase 3) ----------------------------------------------------


def test_security_headers_present_on_api_and_static(client: TestClient) -> None:
    for path in ("/api/status", "/login.html"):
        resp = client.get(path)
        assert resp.headers["X-Frame-Options"] == "DENY", path
        assert resp.headers["X-Content-Type-Options"] == "nosniff", path
        assert resp.headers["Referrer-Policy"] == "no-referrer", path
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp, path
        assert "frame-ancestors 'none'" in csp, path
        assert "object-src 'none'" in csp, path


def test_security_headers_present_on_an_unauthenticated_401(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The auth guard returns 401s itself, so the headers have to be applied
    outside it or those responses go out bare."""
    monkeypatch.setenv(MASTER_KEY_ENV, "hdr test master key")
    app = create_app(_config(tmp_path), authenticator=_fake_auth(), auth_settings=AUTH_SETTINGS)
    with TestClient(app) as c:
        resp = c.get("/api/status")  # no login
        assert resp.status_code == 401
        assert resp.headers["X-Frame-Options"] == "DENY"


def test_hsts_only_over_https(client: TestClient) -> None:
    """Sending HSTS over plain HTTP is meaningless, and pinning a host to HTTPS
    it isn't serving would lock operators out."""
    assert "Strict-Transport-Security" not in client.get("/api/status").headers
    forwarded = client.get("/api/status", headers={"X-Forwarded-Proto": "https"})
    assert "max-age=" in forwarded.headers["Strict-Transport-Security"]


# -- upload limits (M7) ------------------------------------------------------------
#
# The filename used to be validated only inside submit_upload -> add_stream,
# i.e. after Starlette had spooled the whole body AND it had been copied again
# to a staging path — two full writes of a GB-scale file before a rejection.
# There was also no size ceiling anywhere in the stack and no free-space check,
# and /data holds the SQLite DB (jobs, sessions, encrypted credentials) and the
# job archive, so filling it breaks more than uploads.


def test_upload_rejects_a_bad_filename_before_writing_anything(
    client: TestClient, tmp_path: Path
) -> None:
    packages_dir = client.app.state.packages.directory
    before = set(packages_dir.iterdir())

    resp = client.post(
        "/api/packages", files={"file": ("../../etc/passwd", b"x" * 1024, "application/gzip")}
    )

    assert resp.status_code in (400, 404)
    assert set(packages_dir.iterdir()) == before  # nothing staged


def test_upload_rejects_an_oversized_content_length(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_app, "MAX_UPLOAD_BYTES", 512)
    resp = client.post(
        "/api/packages", files={"file": ("jhf.tgz", b"x" * 4096, "application/gzip")}
    )
    assert resp.status_code == 413
    assert "limit" in resp.json()["detail"]


def test_upload_within_the_limit_still_works(client: TestClient) -> None:
    resp = client.post(
        "/api/packages", files={"file": ("small.tgz", b"x" * 2048, "application/gzip")}
    )
    assert resp.status_code == 200, resp.text
