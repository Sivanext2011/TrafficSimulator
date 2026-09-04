"""
Permanent unit tests for the Diameter Gy/Ro stack and quota handling.

Offline only — no cluster or network required. Run with:  pytest -q
"""
import struct

from app.protocols.diameter_stack import (
    AVPCode, CommandCode, CCRequestType,
    DiameterCCClient,
    encode_avp, encode_utf8_avp, encode_uint32_avp, encode_uint64_avp,
    encode_grouped_avp, decode_avps,
    encode_diameter_message, decode_diameter_header,
    ERICSSON_VENDOR_ID,
)


def _make_client(auth_app_id=4):
    return DiameterCCClient(
        host="127.0.0.1", port=3868,
        origin_host="telecom-simulator.local", origin_realm="simulator.realm",
        destination_host="", destination_realm="ccaf.epc.mnc092.mcc466.3gppnetwork.org",
        auth_app_id=auth_app_id,
        subscriber={"msisdn": "975009991", "imsi": "97500999111122",
                    "apn": "internet", "mcc": "466", "mnc": "92"},
    )


# ── AVP encode / decode round-trips ─────────────────────────────────────────

def test_uint32_avp_roundtrip():
    b = encode_uint32_avp(AVPCode.CC_REQUEST_TYPE, 1)
    avps = decode_avps(b)
    assert len(avps) == 1
    assert avps[0]["code"] == AVPCode.CC_REQUEST_TYPE
    assert struct.unpack("!I", avps[0]["data"][:4])[0] == 1


def test_uint64_avp_roundtrip():
    b = encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, 10 * 1024 * 1024)
    avps = decode_avps(b)
    assert struct.unpack("!Q", avps[0]["data"][:8])[0] == 10 * 1024 * 1024


def test_utf8_avp_roundtrip():
    b = encode_utf8_avp(AVPCode.SERVICE_CONTEXT_ID, "32251@3GPP.org")
    avps = decode_avps(b)
    assert avps[0]["data"].decode("utf-8") == "32251@3GPP.org"


def test_grouped_avp_roundtrip():
    inner = [encode_uint32_avp(AVPCode.RATING_GROUP, 1000),
             encode_uint32_avp(AVPCode.RESULT_CODE, 2001)]
    b = encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, inner)
    top = decode_avps(b)
    assert top[0]["code"] == AVPCode.MULTIPLE_SERVICES_CC
    sub = decode_avps(top[0]["data"])
    codes = {a["code"] for a in sub}
    assert AVPCode.RATING_GROUP in codes and AVPCode.RESULT_CODE in codes


def test_vendor_avp_has_vendor_flag():
    b = encode_uint32_avp(AVPCode.TGPP_RAT_TYPE, 6, ERICSSON_VENDOR_ID)
    avps = decode_avps(b)
    assert avps[0]["vendor_id"] == ERICSSON_VENDOR_ID


# ── Diameter message header round-trip ──────────────────────────────────────

def test_message_header_flags():
    msg = encode_diameter_message(CommandCode.CCR, 4, 1, 2,
                                  [encode_uint32_avp(AVPCode.CC_REQUEST_TYPE, 1)],
                                  is_request=True, proxiable=True)
    h = decode_diameter_header(msg[:20])
    assert h["command_code"] == CommandCode.CCR
    assert h["is_request"] is True
    assert h["is_proxyable"] is True
    assert h["application_id"] == 4


# ── Client config (Gy defaults) ─────────────────────────────────────────────

def test_gy_client_defaults():
    c = _make_client(4)
    assert int(c.cc_command) == 272
    assert c.cc_app_id == 4
    assert c.service_context_id == "32251@3GPP.org"


def test_subscription_id_has_msisdn_and_imsi():
    c = _make_client()
    subid = c._build_subscription_id()
    assert len(subid) == 2  # E164 + IMSI


def test_mscc_initial_has_rsu_and_rating_group():
    c = _make_client()
    mscc = c._build_mscc([1000], CCRequestType.INITIAL)
    assert len(mscc) == 1
    inner = decode_avps(decode_avps(mscc[0])[0]["data"]) if False else decode_avps(mscc[0])[0]
    # decode the grouped MSCC
    sub = decode_avps(mscc[0])[0]
    parts = decode_avps(sub["data"])
    codes = {a["code"] for a in parts}
    assert AVPCode.RATING_GROUP in codes
    assert AVPCode.REQUESTED_SERVICE_UNIT in codes


# ── CCA MSCC / grant / FUI parsing ──────────────────────────────────────────

def _mscc(rg, rc, total=None, time_=None, validity=None, final=False, fua=None):
    inner = [encode_uint32_avp(AVPCode.RATING_GROUP, rg),
             encode_uint32_avp(AVPCode.RESULT_CODE, rc)]
    if total is not None or time_ is not None:
        gsu = []
        if total is not None:
            gsu.append(encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, total))
        if time_ is not None:
            gsu.append(encode_uint32_avp(AVPCode.CC_TIME, time_))
        inner.append(encode_grouped_avp(AVPCode.GRANTED_SERVICE_UNIT, gsu))
    if validity is not None:
        inner.append(encode_uint32_avp(AVPCode.VALIDITY_TIME, validity))
    if final:
        fui_inner = []
        if fua is not None:
            fui_inner.append(encode_uint32_avp(AVPCode.FINAL_UNIT_ACTION, fua))
        inner.append(encode_grouped_avp(AVPCode.FINAL_UNIT_INDICATION,
                                        fui_inner or [encode_uint32_avp(AVPCode.FINAL_UNIT_ACTION, 0)]))
    return encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, inner)


def test_parse_answer_mscc_grant():
    c = _make_client()
    raw = _mscc(1000, 2001, total=5 * 1024 * 1024, time_=300, validity=1800)
    parsed = c._parse_answer_mscc(decode_avps(raw))
    assert len(parsed) == 1
    m = parsed[0]
    assert m["rating_group"] == 1000
    assert m["result_code"] == 2001
    assert m["granted_total_octets"] == 5 * 1024 * 1024
    assert m["granted_time"] == 300
    assert m["validity_time"] == 1800
    assert m["final"] is False


def test_parse_answer_mscc_final_unit():
    c = _make_client()
    raw = _mscc(1000, 2001, total=0, final=True, fua=0)
    parsed = c._parse_answer_mscc(decode_avps(raw))
    m = parsed[0]
    assert m["final"] is True
    assert m["final_unit_action"] == 0


# ── Quota tracking / exhaustion ─────────────────────────────────────────────

def test_quota_tracking_and_remaining():
    c = _make_client()
    c._update_quota({"rating_group": 1000, "result_code": 2001,
                     "granted_total_octets": 1000, "granted_time": 60,
                     "validity_time": 60, "final": False, "final_unit_action": None},
                    CCRequestType.INITIAL)
    assert c.remaining_quota(1000) == 1000
    c.record_usage(1000, 400)
    assert c.remaining_quota(1000) == 600
    assert c.is_exhausted(1000) is False


def test_final_unit_exhaustion():
    c = _make_client()
    # granted final quota of 500
    c._update_quota({"rating_group": 1000, "result_code": 2001,
                     "granted_total_octets": 500, "granted_time": None,
                     "validity_time": None, "final": True, "final_unit_action": 0},
                    CCRequestType.UPDATE)
    assert c.is_final(1000) is True
    c.record_usage(1000, 500)
    assert c.is_exhausted(1000) is True


def test_zero_final_grant_is_exhausted():
    c = _make_client()
    c._update_quota({"rating_group": 1000, "result_code": 2001,
                     "granted_total_octets": 0, "granted_time": None,
                     "validity_time": None, "final": True, "final_unit_action": 0},
                    CCRequestType.UPDATE)
    assert c.is_exhausted(1000) is True
