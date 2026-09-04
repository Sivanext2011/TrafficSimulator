"""API endpoint tests using FastAPI TestClient. No cluster needed (endpoints
that would dial the cluster are not exercised here)."""
import pytest

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_settings_roundtrip():
    r = client.post("/api/settings", json={"_lastProtocol": "gy", "gy": {"msisdn": "123"}})
    assert r.status_code == 200 and r.json()["status"] == "saved"
    r2 = client.get("/api/settings")
    assert r2.status_code == 200
    assert r2.json().get("_lastProtocol") == "gy"


def test_profiles_crud():
    # save
    r = client.post("/api/profiles/testprof", json={"gy": {"msisdn": "999"}})
    assert r.json()["status"] == "saved"
    # list
    assert "testprof" in client.get("/api/profiles").json()["profiles"]
    # get
    assert client.get("/api/profiles/testprof").json()["gy"]["msisdn"] == "999"
    # delete
    assert client.delete("/api/profiles/testprof").json()["status"] == "deleted"
    assert "testprof" not in client.get("/api/profiles").json()["profiles"]


def test_profile_get_missing():
    assert "error" in client.get("/api/profiles/does-not-exist").json()


def test_log_level_get_and_set():
    assert "level" in client.get("/api/logs/level").json()
    r = client.post("/api/logs/level", json={"level": "INFO"})
    assert r.json()["level"] == "INFO"
    bad = client.post("/api/logs/level", json={"level": "NOPE"})
    assert "error" in bad.json()


def test_log_events():
    r = client.get("/api/logs/events?limit=5")
    assert r.status_code == 200
    assert "events" in r.json()


def test_metrics_shape():
    m = client.get("/api/metrics").json()
    for k in ("total_requests", "successful", "failed",
              "latency_p50_ms", "latency_p95_ms", "result_codes"):
        assert k in m


def test_diameter_status_and_messages():
    assert "peers" in client.get("/api/diameter/status").json()
    assert "messages" in client.get("/api/diameter/messages?limit=5").json()


def test_manual_create_bad_protocol():
    # Unknown protocol should return an error dict, not crash
    r = client.post("/api/manual/create", json={"protocol": "bogus", "fqdn": "x"})
    assert r.status_code == 200
    assert "error" in r.json()
