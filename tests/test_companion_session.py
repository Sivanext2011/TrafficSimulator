"""Tests for the CHF + companion (N28/eN28/Sy/eSy) session feature.

These exercise the config model, the Diameter Sy eSy AVP construction, and
the /api/traffic/start-full endpoint's companion branching. They do NOT dial a
real cluster — the background orchestration task is immediately stopped.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.main import app, FullSessionConfig, stop_full_session_internal
from app.protocols.diameter_stack import (
    DiameterSyClient, SLRequestType, SY_APPLICATION_ID, ERICSSON_ESY_APPLICATION_ID,
    CommandCode, decode_avps, AVPCode, ERICSSON_VENDOR_ID, TGPP_VENDOR_ID,
)

client = TestClient(app)


def test_companion_default_is_en28():
    cfg = FullSessionConfig(chf_fqdn="chf.example.com")
    assert cfg.companion == "en28"


def test_companion_accepts_all_modes():
    for mode in ("none", "n28", "en28", "sy", "esy"):
        cfg = FullSessionConfig(chf_fqdn="x", companion=mode)
        assert cfg.companion == mode


def _sy_slr_codes(client_obj, sl_type):
    client_obj._session_id = "s1"
    blob = b"".join(client_obj._build_slr_avps(sl_type))
    return blob, decode_avps(blob)


def test_real_sy_uses_correct_command_and_app_id():
    assert int(CommandCode.SLR) == 8388635
    assert SY_APPLICATION_ID == 16777302


def test_real_sy_slr_has_required_avps():
    sy = DiameterSyClient(
        host="10.0.0.9", port=3868,
        origin_host="sim.local", origin_realm="sim.realm",
        destination_realm="ocs.realm",
        subscriber={"msisdn": "123", "imsi": "456"},
        policy_counter_ids=["1", "2"],
    )
    _, decoded = _sy_slr_codes(sy, SLRequestType.INITIAL)
    codes = [a["code"] for a in decoded]
    assert AVPCode.SESSION_ID in codes
    assert AVPCode.SL_REQUEST_TYPE in codes
    assert AVPCode.VENDOR_SPECIFIC_APP_ID in codes
    # Two policy counters requested
    assert sum(1 for a in decoded if a["code"] == AVPCode.POLICY_COUNTER_IDENTIFIER) == 2


def test_standard_sy_uses_3gpp_vendor_esy_uses_ericsson():
    std = DiameterSyClient(host="x", port=3868, origin_host="o", origin_realm="r",
                           destination_realm="d", enable_esy=False)
    esy = DiameterSyClient(host="x", port=3868, origin_host="o", origin_realm="r",
                           destination_realm="d", enable_esy=True)
    assert std.app_vendor_id == TGPP_VENDOR_ID
    assert esy.app_vendor_id == ERICSSON_VENDOR_ID
    # Standard 3GPP Sy uses app-id 16777302; Ericsson ESy uses 16777304.
    assert std.app_id == SY_APPLICATION_ID
    assert esy.app_id == ERICSSON_ESY_APPLICATION_ID


def _start_then_stop(payload):
    """Call the start-full handler and stop it within a SINGLE event loop.

    Using TestClient here would create a fresh loop per request, so the
    background orchestration task created during start would belong to a
    different loop than stop — a test-harness artifact, not a product bug.
    Driving both in one asyncio.run() avoids that.
    """
    from app.main import start_full_session

    async def _run():
        cfg = FullSessionConfig(**payload)
        body = await start_full_session(cfg)
        # Cancel/clean up the background orchestration task in this same loop.
        await stop_full_session_internal()
        return body

    return asyncio.run(_run())


def test_start_full_sy_companion_reports_sy():
    body = _start_then_stop({
        "chf_fqdn": "127.0.0.1",
        "chf_port": 65530,  # unreachable on purpose; orchestration runs in bg
        "chf_secure": False,
        "companion": "sy",
        "sy_fqdn": "127.0.0.1",
        "sy_port": 65531,
        "policy_counter_ids": ["1"],
    })
    assert "error" not in body, body
    assert body["companion"] == "sy"
    # Real Diameter Sy endpoint string, not an HTTP path.
    assert body["companion_endpoint"].startswith("diameter://")
    assert "8388635" in body["companion_endpoint"]


def test_start_full_esy_companion_reports_esy():
    body = _start_then_stop({
        "chf_fqdn": "127.0.0.1",
        "chf_port": 65530,
        "chf_secure": False,
        "companion": "esy",
        "sy_fqdn": "127.0.0.1",
        "sy_port": 65531,
    })
    assert "error" not in body, body
    assert body["companion"] == "esy"
    assert body["companion_endpoint"].startswith("diameter://")
    assert "eSy vendor 193" in body["companion_endpoint"]


def test_start_full_en28_companion_reports_en28():
    body = _start_then_stop({
        "chf_fqdn": "127.0.0.1",
        "chf_port": 65530,
        "chf_secure": False,
        "companion": "en28",
        "policy_counter_ids": ["1"],
    })
    assert "error" not in body, body
    assert body["companion"] == "en28"


def test_start_full_none_companion_runs_chf_only():
    body = _start_then_stop({
        "chf_fqdn": "127.0.0.1",
        "chf_port": 65530,
        "chf_secure": False,
        "companion": "none",
    })
    assert "error" not in body, body
    assert body["companion"] == "none"
    assert body["companion_endpoint"] is None


def test_start_full_backward_compat_enable_en28():
    """Legacy callers set enable_en28 without companion -> should become en28."""
    body = _start_then_stop({
        "chf_fqdn": "127.0.0.1",
        "chf_port": 65530,
        "chf_secure": False,
        "companion": "none",
        "enable_en28": True,
    })
    assert body["companion"] == "en28"
