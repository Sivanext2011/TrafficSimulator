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


def test_last_traffic_config_persistence_roundtrip():
    """The full integration config saved on traffic-start must survive a
    'restart' (simulated by reloading the JSON via the helper/endpoint)."""
    from app.main import (
        TrafficConfig, EndpointConfig, SubscriberConfig,
        _save_last_traffic_config, _load_last_traffic_config,
    )

    cfg = TrafficConfig(
        protocol="gy",
        endpoint=EndpointConfig(protocol="gy", fqdn="10.163.238.25", port=3868, secure=False),
        subscriber=SubscriberConfig(msisdn="975009993", imsi="97500999311223",
                                    mcc="466", mnc="92"),
        rating_groups=[1000],
        diameter_host="10.163.238.25",
        diameter_port=3868,
        origin_host="telecom-simulator.local",
        origin_realm="simulator.realm",
        destination_host="10.163.238.25",
        destination_realm="ccaf.epc.mnc092.mcc466.3gppnetwork.org",
        service_context_id="EricssonCharging-Ro-Gy",
        auth_app_id=4,
    )

    # Save (what start_traffic does) then load fresh from disk (what startup does).
    _save_last_traffic_config(cfg)
    loaded = _load_last_traffic_config()
    assert loaded is not None
    assert loaded["service_context_id"] == "EricssonCharging-Ro-Gy"
    assert loaded["diameter_host"] == "10.163.238.25"
    assert loaded["subscriber"]["msisdn"] == "975009993"
    assert loaded["auth_app_id"] == 4

    # And the GET endpoint returns the same persisted blob.
    r = client.get("/api/traffic/last-config")
    assert r.status_code == 200
    body = r.json()
    assert body["origin_realm"] == "simulator.realm"
    assert body["destination_realm"] == "ccaf.epc.mnc092.mcc466.3gppnetwork.org"
