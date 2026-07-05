import os
import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from ops.ingest import server as ingest_server

CLIENT = TestClient(ingest_server.app)


@pytest.fixture(autouse=True)
def clear_env(monkeypatch, tmp_path):
    # default API key for tests
    monkeypatch.setenv("INGEST_API_KEY", "lab-secret")
    monkeypatch.setenv("REQUIRE_MTLS", "false")
    # point endpoint file to temp path
    tmp_file = tmp_path / "endpoint.json"
    ingest_server.ENDPOINT_FILE = tmp_file
    if tmp_file.exists():
        tmp_file.unlink()
    return tmp_file


def read_events(path: Path):
    if not path.exists():
        return []
    return json.loads(path.read_text())


def test_ingest_success_no_mtls(clear_env):
    hdr = {"X-API-Key": "lab-secret", "Content-Type": "application/json"}
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "test", "msg": "hello"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == 1
    evs = read_events(ingest_server.ENDPOINT_FILE)
    assert len(evs) == 1
    assert evs[0]["type"] == "test"


def test_ingest_fail_bad_api_key(clear_env):
    hdr = {"X-API-Key": "wrong", "Content-Type": "application/json"}
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "test"})
    assert resp.status_code == 401


def test_ingest_require_mtls_success(clear_env, monkeypatch):
    monkeypatch.setenv("REQUIRE_MTLS", "true")
    hdr = {
        "X-API-Key": "lab-secret",
        "X-SSL-CLIENT-VERIFY": "SUCCESS",
        "X-SSL-CLIENT-S-DN": "CN=agent-01,OU=Agents,O=Example",
        "Content-Type": "application/json",
    }
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "proc", "name": "cmd"})
    assert resp.status_code == 200
    evs = read_events(ingest_server.ENDPOINT_FILE)
    assert evs and evs[-1].get("_client_identity") == "agent-01"


def test_ingest_require_mtls_fail_missing_verify(clear_env, monkeypatch):
    monkeypatch.setenv("REQUIRE_MTLS", "true")
    hdr = {
        "X-API-Key": "lab-secret",
        # missing X-SSL-CLIENT-VERIFY -> should fail
        "X-SSL-CLIENT-S-DN": "CN=agent-01,OU=Agents",
        "Content-Type": "application/json",
    }
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "proc"})
    assert resp.status_code == 403
