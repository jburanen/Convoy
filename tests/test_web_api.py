from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chkp_cpuse_orch.config import Config, EnvironmentDef, Paths
from chkp_cpuse_orch.credentials import MASTER_KEY_ENV
from chkp_cpuse_orch.web.app import create_app
from chkp_cpuse_orch.web.auth import AuthSettings

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
        role: gateway
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
    )
    with TestClient(app) as c:
        _login(c)
        yield c


def _enable_storage(client: TestClient, env: str) -> None:
    resp = client.post(f"/api/environments/{env}/credential-storage", json={"enabled": True})
    assert resp.status_code == 200, resp.text


def _put_set(
    client: TestClient, env: str = "default", name: str = "primary", **extra: object
) -> None:
    body: dict[str, object] = {"name": name, "ssh_username": "admin", "ssh_password": "pw"}
    body.update(extra)
    resp = client.put(f"/api/env/{env}/credentials", json=body)
    assert resp.status_code == 201, resp.text


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


def _upload_package(client: TestClient, name: str = "jhf.tgz", content: bytes = b"x" * 64) -> None:
    """Upload and block until the pkgs.upload job succeeds, so callers can
    assume the package exists the moment this returns — uploads run as a
    background job (see services/pkgs_ops.py), not synchronously."""
    resp = client.post("/api/packages", files={"file": (name, content)})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def _wait_for_job(client: TestClient, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("pending", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


# -- basics ----------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root_serves_static_ui(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "chkp-cpuse-orch" in resp.text


def test_status_reports_unlocked_and_counts(client: TestClient) -> None:
    body = client.get("/api/status").json()
    assert body["credentials_unlocked"] is True
    assert body["management_servers"] == 1  # fw-01 is a gateway, not counted
    assert body["environments"] == ["default"]
    assert body["job_archive_path"]  # Jobs tab points the operator here


def test_environments_endpoint(client: TestClient) -> None:
    envs = client.get("/api/environments").json()
    assert envs == [
        {
            "name": "default",
            "management_servers": 1,
            "credential_storage_enabled": True,
            "is_mds": False,
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
    assert resp.status_code == 201, resp.text
    sets = client.get("/api/env/default/credentials").json()
    assert len(sets) == 1  # merged into the same set, not a second one
    assert sets[0]["has_api"] is True
    assert sets[0]["ssh_auth"] == "password"  # SSH password preserved


def test_bootstrap_credentials_become_the_default(client: TestClient) -> None:
    # First set with default_if_none → becomes the environment default.
    resp = client.put(
        "/api/env/default/credentials",
        json={"name": "primary", "ssh_password": "pw", "default_if_none": True},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["is_default"] is True

    # A second set also asking default_if_none does NOT steal the default.
    client.put(
        "/api/env/default/credentials",
        json={"name": "backup", "ssh_password": "pw", "default_if_none": True},
    )
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
    client.post(
        "/api/environments/default/servers",
        json={"name": "m9", "address": "192.0.2.99", "role": "primary_sms"},
    )
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
    assert [s["name"] for s in servers] == ["mgmt-01"]  # fw-01 gateway not seeded
    assert servers[0]["role"] == "management"


def test_create_environment_and_add_server(client: TestClient) -> None:
    assert client.post("/api/environments", json={"name": "dmz"}).status_code == 201
    # It now shows up in the environment list.
    assert "dmz" in [e["name"] for e in client.get("/api/environments").json()]

    resp = client.post(
        "/api/environments/dmz/servers",
        json={"name": "mgmt-dmz", "address": "192.0.2.60", "role": "management"},
    )
    assert resp.status_code == 201, resp.text
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


def test_add_gateway_role_server_rejected(client: TestClient) -> None:
    resp = client.post(
        "/api/environments/default/servers",
        json={"name": "fw-x", "address": "192.0.2.70", "role": "gateway"},
    )
    assert resp.status_code == 400
    assert "not a management server role" in resp.json()["detail"]


def test_delete_environment_and_its_servers(client: TestClient) -> None:
    client.post("/api/environments", json={"name": "temp"})
    client.post(
        "/api/environments/temp/servers",
        json={"name": "m1", "address": "192.0.2.80", "role": "mds"},
    )
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
    client.post(
        "/api/environments/old name/servers",
        json={"name": "m1", "address": "192.0.2.85", "role": "management"},
    )
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
    client.post(
        "/api/environments/e1/servers",
        json={"name": "m1", "address": "192.0.2.90", "role": "management"},
    )
    assert client.delete("/api/environments/e1/servers/m1").json() == {"deleted": True}
    assert client.get("/api/environments/e1/servers").json() == []
    assert client.delete("/api/environments/e1/servers/m1").status_code == 404


# -- servers ---------------------------------------------------------------------


def test_servers_lists_management_only_with_assigned_set(client: TestClient) -> None:
    servers = client.get("/api/env/default/servers").json()
    assert [s["name"] for s in servers] == ["mgmt-01"]
    assert servers[0]["credential_set"] is None
    _add_ssh_credential(client)
    servers = client.get("/api/env/default/servers").json()
    assert servers[0]["credential_set"] == "primary"


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
    # The other package (imported, not installed) is the Install picker's option.
    assert body["installable"] == ["Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz"]


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
    assert after["installable"] == ["Check_Point_R81_20_JUMBO_HF_MAIN_Bundle_T89_FULL.tgz"]


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
    assert resp.json() == {"deleted": True}
    assert client.get("/api/env/default/credentials").json() == []


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


# -- packages ---------------------------------------------------------------------


def test_package_upload_list_delete(client: TestClient) -> None:
    _upload_package(client, content=b"payload-bytes")
    listing = client.get("/api/packages").json()
    assert listing[0]["filename"] == "jhf.tgz"
    assert listing[0]["size"] == len(b"payload-bytes")
    assert len(listing[0]["sha256"]) == 64

    resp = client.delete("/api/packages/jhf.tgz")
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert client.get("/api/packages").json() == []


def test_package_conflict_rejected(client: TestClient) -> None:
    _upload_package(client, content=b"original")
    # The name/content dedupe check only runs once the pkgs.upload job hashes
    # the staged file, so the conflict surfaces as a failed job, not an
    # immediate HTTP error (unlike retention/delete, which 404 synchronously
    # since PackageStore.get() is cheap to check before creating the job).
    resp = client.post("/api/packages", files={"file": ("jhf.tgz", b"different")})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "failed"
    assert "different content" in job["error"]


def test_uploaded_package_gets_default_expiry(client: TestClient) -> None:
    _upload_package(client)
    rec = client.get("/api/packages").json()[0]
    assert rec["expires_at"] is not None  # retention window applied by default


def test_package_retention_pin_and_unpin(client: TestClient) -> None:
    _upload_package(client)

    resp = client.post("/api/packages/jhf.tgz/retention", json={"pinned": True})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "pkgs.keep"
    assert client.get("/api/packages").json()[0]["expires_at"] is None  # kept indefinitely

    resp = client.post("/api/packages/jhf.tgz/retention", json={"pinned": False})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert job["kind"] == "pkgs.notkeep"
    assert client.get("/api/packages").json()[0]["expires_at"] is not None  # window reapplied


def test_package_retention_missing_is_404(client: TestClient) -> None:
    # Still an immediate 404 — submit_retention() checks existence before
    # creating a job, so an unknown filename never even reaches the runner.
    resp = client.post("/api/packages/ghost.tgz/retention", json={"pinned": True})
    assert resp.status_code == 404


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
    import_job = client.post(
        "/api/env/default/servers/mgmt-01/import", json={"package": "jhf.tgz"}
    ).json()
    cloud_job = client.post(
        "/api/env/default/servers/mgmt-01/import-cloud",
        json={"package_id": "Check_Point_R81.20_JHF_T99"},
    ).json()
    _wait_for_job(client, import_job["id"])
    _wait_for_job(client, cloud_job["id"])

    # Facets reflect every job, not just whatever a limited /api/jobs page shows.
    # _upload_package() also runs a pkgs.upload job (target: the filename), so
    # these check "at least" rather than an exact set/list.
    facets = client.get("/api/jobs/facets").json()
    assert {"cpuse.import", "cpuse.import_cloud"} <= set(facets["kinds"])
    assert {"mgmt-01"} <= set(facets["targets"])
    assert facets["environments"] == ["default"]
    assert facets["statuses"] == ["succeeded"]

    by_kind = client.get("/api/jobs", params={"kind": "cpuse.import"}).json()
    assert {j["id"] for j in by_kind} == {import_job["id"]}

    by_status = client.get("/api/jobs", params={"status": "succeeded"}).json()
    assert {j["id"] for j in by_status} >= {import_job["id"], cloud_job["id"]}

    none_match = client.get("/api/jobs", params={"kind": "cpuse.install"}).json()
    assert none_match == []

    bad_status = client.get("/api/jobs", params={"status": "not-a-real-status"})
    assert bad_status.status_code == 400


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


def test_import_against_gateway_not_in_inventory_is_404(client: TestClient) -> None:
    # Gateways are not seeded into an environment's management-server inventory
    # (only management/mds roles are), so a gateway name is simply unknown here.
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
    resp = client.post(
        f"/api/environments/{env}/servers",
        json={"name": server, "address": "192.0.2.10", "role": "management"},
    )
    assert resp.status_code == 201, resp.text


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
        json={"package": "jhf.tgz", "credentials": _SSH_CREDS},
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
        c.post(
            "/api/environments/dmz/servers",
            json={"name": "mgmt-01", "address": "192.0.2.10", "role": "management"},
        )
        resp = c.post("/api/env/dmz/servers/mgmt-01/state", json={"credentials": _SSH_CREDS})
        assert resp.status_code == 200, resp.text
        assert resp.json()["agent_build"] == DA_BUILD


# -- provisioning -----------------------------------------------------------------


def test_provision_renders_commands_without_plaintext(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "svc-patch", "password": "s3cret-pw!"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["commands"][3] == "set user svc-patch gid 100 shell /bin/bash"
    assert "s3cret-pw!" not in resp.text  # only the salted hash is echoed
    assert any("clish -c" in n for n in body["notes"])
    # Management API access is included by default (needed for auto-discovery).
    assert any('authentication-method "api key"' in c for c in body["api_commands"])


def test_provision_can_skip_mgmt_api(client: TestClient) -> None:
    resp = client.post(
        "/api/provision",
        json={"username": "svc-patch", "password": "s3cret-pw!", "mgmt_api": False},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["api_commands"] == []
    assert body["api_notes"] == []


def test_provision_rejects_bad_input(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "BAD NAME", "password": "longenough"})
    assert resp.status_code == 400
    assert "invalid username" in resp.json()["detail"]


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
