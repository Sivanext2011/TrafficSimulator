"""Tests for DiameterSessionHandler grant parsing (real CCA -> multipleUnitInformation)."""
from app.protocols.diameter_stack import (
    AVPCode, DiameterCCClient,
    encode_uint32_avp, encode_uint64_avp, encode_grouped_avp, decode_avps,
)
from app.main import DiameterSessionHandler


def _handler(rgs=(1000,)):
    c = DiameterCCClient(
        host="127.0.0.1", port=3868, origin_host="sim.local", origin_realm="sim.realm",
        destination_host="", destination_realm="op.com", auth_app_id=4, subscriber={},
    )
    h = DiameterSessionHandler(c)
    h._rating_groups = list(rgs)
    return h


def _cca(mscc_bytes):
    return {"result_code": 2001, "answer": {"avps": decode_avps(mscc_bytes)}}


def test_parse_real_grant():
    h = _handler()
    gsu = encode_grouped_avp(AVPCode.GRANTED_SERVICE_UNIT, [
        encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, 2 * 1024 * 1024),
        encode_uint32_avp(AVPCode.CC_TIME, 120),
    ])
    mscc = encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, [
        encode_uint32_avp(AVPCode.RATING_GROUP, 1000),
        encode_uint32_avp(AVPCode.RESULT_CODE, 2001),
        encode_uint32_avp(AVPCode.VALIDITY_TIME, 900),
        gsu,
    ])
    parsed = h._parse_diameter_grants(_cca(mscc))
    u = parsed["multipleUnitInformation"][0]
    assert u["ratingGroup"] == 1000
    assert u["resultCode"] == "SUCCESS"
    assert u["grantedUnit"]["totalVolume"] == 2 * 1024 * 1024
    assert u["grantedUnit"]["time"] == 120
    assert u["validityTime"] == 900
    assert u["finalUnitIndication"] is False


def test_parse_final_unit_indication():
    h = _handler()
    fui = encode_grouped_avp(AVPCode.FINAL_UNIT_INDICATION, [
        encode_uint32_avp(AVPCode.FINAL_UNIT_ACTION, 0),
    ])
    gsu = encode_grouped_avp(AVPCode.GRANTED_SERVICE_UNIT, [
        encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, 500),
    ])
    mscc = encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, [
        encode_uint32_avp(AVPCode.RATING_GROUP, 1000),
        encode_uint32_avp(AVPCode.RESULT_CODE, 2001),
        gsu, fui,
    ])
    parsed = h._parse_diameter_grants(_cca(mscc))
    u = parsed["multipleUnitInformation"][0]
    assert u["finalUnitIndication"] is True
    assert u["grantedUnit"]["totalVolume"] == 500


def test_parse_rating_failed_zero_grant():
    h = _handler()
    mscc = encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, [
        encode_uint32_avp(AVPCode.RATING_GROUP, 1000),
        encode_uint32_avp(AVPCode.RESULT_CODE, 5031),
    ])
    parsed = h._parse_diameter_grants(_cca(mscc))
    u = parsed["multipleUnitInformation"][0]
    assert u["resultCode"] == "5031"
    assert u["grantedUnit"]["totalVolume"] == 0


def test_parse_no_mscc_reports_toplevel_failure():
    h = _handler()
    parsed = h._parse_diameter_grants({"result_code": 5031, "answer": {"avps": []}})
    u = parsed["multipleUnitInformation"][0]
    assert u["resultCode"] == "5031"
    assert u["grantedUnit"]["totalVolume"] == 0
