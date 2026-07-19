from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chkp_cpuse_orch.config import Config, Paths
from chkp_cpuse_orch.credentials import MASTER_KEY_ENV
from chkp_cpuse_orch.web.app import create_app

from .fakes import DA_BUILD, SHOW_PACKAGES_ALL, FakeTransport, make_factory

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
            inventory_path=tmp_path / "inventory.yaml",
        )
    )


CANDIDATES_CSV = "Object Name,IP,Upgrade Order\nfw-a1,192.0.2.31,1\nfw-a2,192.0.2.32,2\n"


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport(
        responses={
            "show installer packages": SHOW_PACKAGES_ALL,
            "show installer status build": DA_BUILD,
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
    app = create_app(_config(tmp_path), client_factory=make_factory(transport))
    with TestClient(app) as c:
        yield c


def _add_ssh_credential(client: TestClient, host: str = "mgmt-01") -> None:
    resp = client.put(
        "/api/credentials",
        json={"host": host, "kind": "ssh_password", "username": "admin", "secret": "pw"},
    )
    assert resp.status_code == 201, resp.text


def _upload_package(client: TestClient, name: str = "jhf.tgz", content: bytes = b"x" * 64) -> None:
    resp = client.post("/api/packages", files={"file": (name, content)})
    assert resp.status_code == 201, resp.text


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


# -- servers ---------------------------------------------------------------------


def test_servers_lists_management_only_with_credential_summary(client: TestClient) -> None:
    servers = client.get("/api/servers").json()
    assert [s["name"] for s in servers] == ["mgmt-01"]
    assert servers[0]["credentials"] == []
    _add_ssh_credential(client)
    servers = client.get("/api/servers").json()
    assert servers[0]["credentials"] == ["ssh_password"]


def test_server_state_detects_live_packages(client: TestClient) -> None:
    _add_ssh_credential(client)
    state = client.get("/api/servers/mgmt-01/state")
    assert state.status_code == 200, state.text
    body = state.json()
    assert body["agent_build"] == DA_BUILD
    assert body["packages"][0]["is_imported"] is True
    assert body["packages"][1]["is_installed"] is True


def test_server_state_without_credentials_is_409(client: TestClient) -> None:
    resp = client.get("/api/servers/mgmt-01/state")
    assert resp.status_code == 409
    assert "no SSH credential" in resp.json()["detail"]


# -- credentials ------------------------------------------------------------------


def test_credentials_roundtrip_never_echoes_secret(client: TestClient) -> None:
    _add_ssh_credential(client)
    listing = client.get("/api/credentials").json()
    assert listing == [{"host": "mgmt-01", "kind": "ssh_password", "username": "admin"}]
    assert "pw" not in str(listing)
    resp = client.delete("/api/credentials/mgmt-01/ssh_password")
    assert resp.json() == {"deleted": True}
    assert client.get("/api/credentials").json() == []


def test_locked_credential_store_returns_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    app = create_app(_config(tmp_path))
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200  # app still boots
        resp = c.get("/api/credentials")
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
    assert client.delete("/api/packages/jhf.tgz").json() == {"deleted": True}
    assert client.get("/api/packages").json() == []


def test_package_conflict_rejected(client: TestClient) -> None:
    _upload_package(client, content=b"original")
    resp = client.post("/api/packages", files={"file": ("jhf.tgz", b"different")})
    assert resp.status_code == 400
    assert "different content" in resp.json()["detail"]


# -- import / install jobs through the API ----------------------------------------


def test_import_flow_end_to_end(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    _upload_package(client)

    resp = client.post("/api/servers/mgmt-01/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]

    events = client.get(f"/api/jobs/{job['id']}/events").json()
    assert any("import finished" in e["message"] for e in events)
    assert transport.puts[0][1] == "/var/log/upload/jhf.tgz"


def test_install_requires_confirmation_flag(client: TestClient) -> None:
    _add_ssh_credential(client)
    resp = client.post(
        "/api/servers/mgmt-01/install",
        json={"package_id": "Check_Point_R81_20_T89", "confirmed": False},
    )
    assert resp.status_code == 400
    assert "confirmation" in resp.json()["detail"]


def test_install_flow_end_to_end(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    resp = client.post(
        "/api/servers/mgmt-01/install",
        json={"package_id": "Check_Point_R81_20_T89", "confirmed": True},
    )
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert any("installer install" in c for c in transport.commands)


def test_import_against_gateway_is_rejected(client: TestClient) -> None:
    _add_ssh_credential(client, host="fw-01")
    _upload_package(client)
    resp = client.post("/api/servers/fw-01/import", json={"package": "jhf.tgz"})
    assert resp.status_code == 400
    assert "patched via CDT" in resp.json()["detail"]


# -- CDT --------------------------------------------------------------------------


def test_cdt_status_endpoint(client: TestClient) -> None:
    _add_ssh_credential(client)
    body = client.get("/api/cdt/mgmt-01/status").json()
    assert body == {"available": True, "running": False, "brief": ""}


def test_cdt_candidates_get_and_put(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    cands = client.get("/api/cdt/mgmt-01/candidates").json()
    assert cands["header"][0] == "Object Name"
    assert len(cands["rows"]) == 2

    # Reverse the order and save — this is the blast-radius edit.
    resp = client.put(
        "/api/cdt/mgmt-01/candidates",
        json={"header": cands["header"], "rows": list(reversed(cands["rows"]))},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"rows": 2}
    assert transport.puts[-1][1] == "/opt/CPcdt/orch_candidates.csv"


def test_cdt_execute_requires_confirmation(client: TestClient) -> None:
    _add_ssh_credential(client)
    resp = client.post("/api/cdt/mgmt-01/execute", json={"confirmed": False})
    assert resp.status_code == 400
    assert "confirmation" in resp.json()["detail"]


def test_cdt_stage_and_generate_flow(client: TestClient, transport: FakeTransport) -> None:
    _add_ssh_credential(client)
    _upload_package(client)
    transport.responses["stat -c %s"] = (1, "")  # package not staged yet

    resp = client.post("/api/cdt/mgmt-01/stage", json={"package": "jhf.tgz"})
    assert resp.status_code == 202, resp.text
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]
    assert transport.puts[0][1] == "/var/log/upload/jhf.tgz"
    assert transport.puts[1][1] == "/opt/CPcdt/CentralDeploymentTool.xml"

    resp = client.post("/api/cdt/mgmt-01/generate")
    assert resp.status_code == 202
    job = _wait_for_job(client, resp.json()["id"])
    assert job["status"] == "succeeded", job["error"]


def test_cdt_endpoints_locked_without_credentials(client: TestClient) -> None:
    # No SSH credential stored for the host → 409 with a clear message.
    resp = client.get("/api/cdt/mgmt-01/status")
    assert resp.status_code == 409
    assert "no SSH credential" in resp.json()["detail"]


# -- provisioning -----------------------------------------------------------------


def test_provision_renders_commands_without_plaintext(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "svc-patch", "password": "s3cret-pw!"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["commands"][1] == "set user svc-patch gid 100 shell /bin/bash"
    assert "s3cret-pw!" not in resp.text  # only the salted hash is echoed
    assert any("clish -c" in n for n in body["notes"])


def test_provision_rejects_bad_input(client: TestClient) -> None:
    resp = client.post("/api/provision", json={"username": "BAD NAME", "password": "longenough"})
    assert resp.status_code == 400
    assert "invalid username" in resp.json()["detail"]


# -- jobs -------------------------------------------------------------------------


def test_unknown_job_is_404(client: TestClient) -> None:
    assert client.get("/api/jobs/nope").status_code == 404
