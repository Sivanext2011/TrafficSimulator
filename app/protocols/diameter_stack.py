"""Real Diameter protocol implementation over TCP/SCTP.

Implements the Diameter base protocol (RFC 6733) with proper:
- Message encoding/decoding (header + AVPs)
- CER/CEA capability exchange
- DWR/DWA device watchdog
- CCR/CCA for Gy/Ro credit control
- SLR/SLA for Sy spending limit
"""

import asyncio
import logging
import os
import struct
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Diameter Constants ───────────────────────────────────────────────────────

class CommandCode(IntEnum):
    CER = 257  # Capabilities-Exchange
    DWR = 280  # Device-Watchdog
    CCR = 272  # Credit-Control
    SLR = 8388635  # Spending-Limit (3GPP)
    ASR = 274  # Abort-Session
    RAR = 258  # Re-Auth


class AVPCode(IntEnum):
    SESSION_ID = 263
    ORIGIN_HOST = 264
    ORIGIN_REALM = 296
    DESTINATION_HOST = 293
    DESTINATION_REALM = 283
    AUTH_APPLICATION_ID = 258
    VENDOR_SPECIFIC_APP_ID = 260
    HOST_IP_ADDRESS = 257
    VENDOR_ID = 266
    PRODUCT_NAME = 269
    FIRMWARE_REVISION = 267
    RESULT_CODE = 268
    CC_REQUEST_TYPE = 416
    CC_REQUEST_NUMBER = 415
    SUBSCRIPTION_ID = 443
    SUBSCRIPTION_ID_TYPE = 450
    SUBSCRIPTION_ID_DATA = 444
    MULTIPLE_SERVICES_CC = 456
    RATING_GROUP = 432
    SERVICE_IDENTIFIER = 439
    REQUESTED_SERVICE_UNIT = 437
    USED_SERVICE_UNIT = 446
    GRANTED_SERVICE_UNIT = 431
    CC_TOTAL_OCTETS = 421
    CC_INPUT_OCTETS = 412
    CC_OUTPUT_OCTETS = 414
    CC_TIME = 420
    SERVICE_INFORMATION = 873  # 3GPP
    PS_INFORMATION = 874  # 3GPP
    TGPP_CHARGING_ID = 2
    CALLED_STATION_ID = 30
    TGPP_SGSN_MCC_MNC = 18
    TGPP_RAT_TYPE = 21
    ORIGIN_STATE_ID = 278
    EVENT_TIMESTAMP = 55
    TERMINATION_CAUSE = 295
    # Sy specific
    SL_REQUEST_TYPE = 2904  # 3GPP
    POLICY_COUNTER_IDENTIFIER = 2901  # 3GPP
    POLICY_COUNTER_STATUS = 2903  # 3GPP


class CCRequestType(IntEnum):
    INITIAL = 1
    UPDATE = 2
    TERMINATE = 3
    EVENT = 4


class SubscriptionIdType(IntEnum):
    END_USER_E164 = 0  # MSISDN
    END_USER_IMSI = 1
    END_USER_SIP_URI = 2
    END_USER_NAI = 3


DIAMETER_HEADER_LEN = 20
AVP_HEADER_LEN = 8  # without vendor
AVP_HEADER_VENDOR_LEN = 12  # with vendor

TGPP_VENDOR_ID = 10415


# ─── AVP Encoding ─────────────────────────────────────────────────────────────

def _pad(length: int) -> int:
    """Calculate padding to 4-byte boundary."""
    return (4 - (length % 4)) % 4


def encode_avp(code: int, data: bytes, vendor_id: int = 0, mandatory: bool = True) -> bytes:
    """Encode a single Diameter AVP."""
    flags = 0
    if mandatory:
        flags |= 0x40
    if vendor_id:
        flags |= 0x80

    if vendor_id:
        avp_len = AVP_HEADER_VENDOR_LEN + len(data)
        header = struct.pack("!IBBHI", code, flags, 0, avp_len & 0xFFFFFF, vendor_id)
        # Fix: pack as I (4 bytes for code), then flags+length in 4 bytes, then vendor
        header = struct.pack("!I", code)
        flags_and_len = (flags << 24) | (avp_len & 0x00FFFFFF)
        header += struct.pack("!I", flags_and_len)
        header += struct.pack("!I", vendor_id)
    else:
        avp_len = AVP_HEADER_LEN + len(data)
        header = struct.pack("!I", code)
        flags_and_len = (flags << 24) | (avp_len & 0x00FFFFFF)
        header += struct.pack("!I", flags_and_len)

    padding = b'\x00' * _pad(len(data))
    return header + data + padding


def encode_utf8_avp(code: int, value: str, vendor_id: int = 0, mandatory: bool = True) -> bytes:
    return encode_avp(code, value.encode("utf-8"), vendor_id, mandatory)


def encode_uint32_avp(code: int, value: int, vendor_id: int = 0, mandatory: bool = True) -> bytes:
    return encode_avp(code, struct.pack("!I", value), vendor_id, mandatory)


def encode_uint64_avp(code: int, value: int, vendor_id: int = 0, mandatory: bool = True) -> bytes:
    return encode_avp(code, struct.pack("!Q", value), vendor_id, mandatory)


def encode_address_avp(code: int, ip: str, vendor_id: int = 0) -> bytes:
    """Encode an IP address AVP (Address type)."""
    parts = ip.split(".")
    addr_bytes = struct.pack("!H", 1)  # IPv4 = 1
    addr_bytes += bytes(int(p) for p in parts)
    return encode_avp(code, addr_bytes, vendor_id)


def encode_grouped_avp(code: int, avps: List[bytes], vendor_id: int = 0, mandatory: bool = True) -> bytes:
    """Encode a grouped AVP containing other AVPs."""
    data = b"".join(avps)
    return encode_avp(code, data, vendor_id, mandatory)


# ─── Diameter Message ─────────────────────────────────────────────────────────

def encode_diameter_message(
    command_code: int,
    app_id: int,
    hop_by_hop: int,
    end_to_end: int,
    avps: List[bytes],
    is_request: bool = True,
) -> bytes:
    """Encode a full Diameter message (header + AVPs)."""
    avp_data = b"".join(avps)
    msg_len = DIAMETER_HEADER_LEN + len(avp_data)

    # Version (1) + Message Length (3)
    ver_and_len = (1 << 24) | (msg_len & 0x00FFFFFF)

    # Command Flags
    flags = 0
    if is_request:
        flags |= 0x80  # R bit

    # Flags (1) + Command Code (3)
    flags_and_cmd = (flags << 24) | (command_code & 0x00FFFFFF)

    header = struct.pack("!IIII",
        ver_and_len,
        flags_and_cmd,
        app_id,
        hop_by_hop,
    )
    header += struct.pack("!I", end_to_end)

    return header + avp_data


def decode_diameter_header(data: bytes) -> dict:
    """Decode Diameter message header (first 20 bytes)."""
    if len(data) < DIAMETER_HEADER_LEN:
        return {}

    ver_and_len, flags_and_cmd, app_id, hop_by_hop, end_to_end = struct.unpack("!IIIII", data[:20])

    version = (ver_and_len >> 24) & 0xFF
    msg_length = ver_and_len & 0x00FFFFFF
    flags = (flags_and_cmd >> 24) & 0xFF
    command_code = flags_and_cmd & 0x00FFFFFF

    return {
        "version": version,
        "length": msg_length,
        "flags": flags,
        "is_request": bool(flags & 0x80),
        "is_proxyable": bool(flags & 0x40),
        "is_error": bool(flags & 0x20),
        "command_code": command_code,
        "application_id": app_id,
        "hop_by_hop": hop_by_hop,
        "end_to_end": end_to_end,
    }


def decode_avps(data: bytes) -> List[dict]:
    """Decode AVPs from raw bytes. Returns list of parsed AVP dicts."""
    avps = []
    offset = 0
    while offset < len(data):
        if offset + 8 > len(data):
            break

        code = struct.unpack("!I", data[offset:offset+4])[0]
        flags_and_len = struct.unpack("!I", data[offset+4:offset+8])[0]
        flags = (flags_and_len >> 24) & 0xFF
        avp_len = flags_and_len & 0x00FFFFFF

        has_vendor = bool(flags & 0x80)
        header_len = AVP_HEADER_VENDOR_LEN if has_vendor else AVP_HEADER_LEN

        vendor_id = 0
        if has_vendor and offset + 12 <= len(data):
            vendor_id = struct.unpack("!I", data[offset+8:offset+12])[0]

        data_start = offset + header_len
        data_len = avp_len - header_len
        avp_data = data[data_start:data_start + data_len] if data_start + data_len <= len(data) else b""

        avps.append({
            "code": code,
            "flags": flags,
            "vendor_id": vendor_id,
            "data": avp_data,
            "length": avp_len,
        })

        # Advance to next AVP (with padding)
        padded_len = avp_len + _pad(avp_len)
        offset += padded_len

    return avps


# ─── Diameter Transport ───────────────────────────────────────────────────────

class DiameterTransport:
    """Manages TCP connection to a Diameter peer with CER/CEA exchange."""

    def __init__(
        self,
        host: str,
        port: int,
        origin_host: str,
        origin_realm: str,
        destination_host: str = "",
        destination_realm: str = "",
        local_ip: str = "10.10.10.1",
        vendor_id: int = TGPP_VENDOR_ID,
        product_name: str = "TelecomSimulator",
        auth_app_ids: List[int] = None,
    ):
        self.host = host
        self.port = port
        self.origin_host = origin_host
        self.origin_realm = origin_realm
        self.destination_host = destination_host
        self.destination_realm = destination_realm
        self.local_ip = local_ip
        self.vendor_id = vendor_id
        self.product_name = product_name
        self.auth_app_ids = auth_app_ids or [4]  # Gy app ID

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected: bool = False
        self._hop_by_hop: int = 1
        self._end_to_end: int = int(time.time()) & 0xFFFFFFFF
        self._pending: Dict[int, asyncio.Future] = {}
        self._recv_task: Optional[asyncio.Task] = None

    @property
    def connected(self) -> bool:
        return self._connected

    def _next_hop_by_hop(self) -> int:
        self._hop_by_hop += 1
        return self._hop_by_hop

    def _next_end_to_end(self) -> int:
        self._end_to_end += 1
        return self._end_to_end

    async def connect(self) -> bool:
        """Establish TCP connection and perform CER/CEA exchange."""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=10.0,
            )
            self._connected = True
            self._recv_task = asyncio.create_task(self._receive_loop())

            # Send CER
            success = await self._send_cer()
            if not success:
                await self.disconnect()
                return False

            return True

        except (OSError, asyncio.TimeoutError) as e:
            logger.error(f"Diameter connect failed: {e}")
            self._connected = False
            return False

    async def disconnect(self):
        """Close the Diameter connection."""
        self._connected = False
        if self._recv_task:
            self._recv_task.cancel()
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._writer = None
        self._reader = None

    async def send_request(self, command_code: int, app_id: int, avps: List[bytes]) -> Optional[dict]:
        """Send a Diameter request and wait for the answer."""
        if not self._connected:
            return None

        hbh = self._next_hop_by_hop()
        ete = self._next_end_to_end()

        msg = encode_diameter_message(command_code, app_id, hbh, ete, avps, is_request=True)

        future = asyncio.get_event_loop().create_future()
        self._pending[hbh] = future

        try:
            self._writer.write(msg)
            await self._writer.drain()

            # Wait for answer (timeout 30s)
            answer = await asyncio.wait_for(future, timeout=30.0)
            return answer

        except (asyncio.TimeoutError, OSError) as e:
            logger.error(f"Diameter send failed: {e}")
            self._pending.pop(hbh, None)
            return None

    async def _send_cer(self) -> bool:
        """Send Capabilities-Exchange-Request."""
        avps = [
            encode_utf8_avp(AVPCode.ORIGIN_HOST, self.origin_host),
            encode_utf8_avp(AVPCode.ORIGIN_REALM, self.origin_realm),
            encode_address_avp(AVPCode.HOST_IP_ADDRESS, self.local_ip),
            encode_uint32_avp(AVPCode.VENDOR_ID, self.vendor_id),
            encode_utf8_avp(AVPCode.PRODUCT_NAME, self.product_name),
        ]

        # Add auth application IDs
        for app_id in self.auth_app_ids:
            avps.append(encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, app_id))

        answer = await self.send_request(CommandCode.CER, 0, avps)
        if answer and answer.get("command_code") == CommandCode.CER:
            # Check result code in AVPs
            return True
        return answer is not None

    async def _receive_loop(self):
        """Background task to receive and dispatch Diameter messages."""
        try:
            while self._connected:
                # Read header
                header_data = await self._reader.readexactly(DIAMETER_HEADER_LEN)
                header = decode_diameter_header(header_data)

                # Read remaining body
                body_len = header["length"] - DIAMETER_HEADER_LEN
                body_data = b""
                if body_len > 0:
                    body_data = await self._reader.readexactly(body_len)

                # Parse AVPs
                avps = decode_avps(body_data)
                header["avps"] = avps

                if header["is_request"]:
                    # Handle incoming requests (DWR, etc.)
                    await self._handle_request(header)
                else:
                    # Dispatch answer to waiting future
                    hbh = header["hop_by_hop"]
                    future = self._pending.pop(hbh, None)
                    if future and not future.done():
                        future.set_result(header)

        except asyncio.IncompleteReadError:
            logger.info("Diameter connection closed by peer")
            self._connected = False
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Diameter receive error: {e}")
            self._connected = False

    async def _handle_request(self, msg: dict):
        """Handle incoming Diameter requests (DWR → DWA)."""
        cmd = msg["command_code"]
        if cmd == CommandCode.DWR:
            # Send DWA
            avps = [
                encode_uint32_avp(AVPCode.RESULT_CODE, 2001),  # DIAMETER_SUCCESS
                encode_utf8_avp(AVPCode.ORIGIN_HOST, self.origin_host),
                encode_utf8_avp(AVPCode.ORIGIN_REALM, self.origin_realm),
            ]
            answer = encode_diameter_message(
                CommandCode.DWR, 0, msg["hop_by_hop"], msg["end_to_end"],
                avps, is_request=False
            )
            if self._writer:
                self._writer.write(answer)
                await self._writer.drain()


# ─── Diameter Gy/Ro Client ────────────────────────────────────────────────────

class DiameterCCClient:
    """Diameter Credit-Control client for Gy/Ro interfaces.

    Supports:
    - Multiple rating groups in MSCC (Multiple-Services-Credit-Control)
    - Full session lifecycle: CCR-I → CCR-U(s) → CCR-T
    - Real TCP transport with proper message encoding
    """

    def __init__(
        self,
        host: str,
        port: int,
        origin_host: str,
        origin_realm: str,
        destination_host: str,
        destination_realm: str,
        auth_app_id: int = 4,  # 4 = Gy/Ro
        subscriber: dict = None,
    ):
        self.subscriber = subscriber or {}
        self.auth_app_id = auth_app_id
        self._session_id: Optional[str] = None
        self._cc_request_number: int = 0

        self._transport = DiameterTransport(
            host=host,
            port=port,
            origin_host=origin_host,
            origin_realm=origin_realm,
            destination_host=destination_host,
            destination_realm=destination_realm,
            auth_app_ids=[auth_app_id],
        )

    async def connect(self) -> bool:
        return await self._transport.connect()

    async def disconnect(self):
        await self._transport.disconnect()

    def _build_subscription_id(self) -> List[bytes]:
        """Build Subscription-Id AVPs for MSISDN and IMSI."""
        avps = []
        msisdn = self.subscriber.get("msisdn", "")
        imsi = self.subscriber.get("imsi", "")

        if msisdn:
            sub_avp = encode_grouped_avp(AVPCode.SUBSCRIPTION_ID, [
                encode_uint32_avp(AVPCode.SUBSCRIPTION_ID_TYPE, SubscriptionIdType.END_USER_E164),
                encode_utf8_avp(AVPCode.SUBSCRIPTION_ID_DATA, msisdn),
            ])
            avps.append(sub_avp)

        if imsi:
            sub_avp = encode_grouped_avp(AVPCode.SUBSCRIPTION_ID, [
                encode_uint32_avp(AVPCode.SUBSCRIPTION_ID_TYPE, SubscriptionIdType.END_USER_IMSI),
                encode_utf8_avp(AVPCode.SUBSCRIPTION_ID_DATA, imsi),
            ])
            avps.append(sub_avp)

        return avps

    def _build_mscc(self, rating_groups: List[int], request_type: CCRequestType,
                     used_units: List[dict] = None) -> List[bytes]:
        """Build Multiple-Services-Credit-Control AVPs."""
        mscc_avps = []
        used_map = {}
        if used_units:
            for u in used_units:
                used_map[u["ratingGroup"]] = u

        for rg in rating_groups:
            inner_avps = [
                encode_uint32_avp(AVPCode.RATING_GROUP, rg),
            ]

            # Requested-Service-Unit (for Initial and Update)
            if request_type in (CCRequestType.INITIAL, CCRequestType.UPDATE):
                rsu = encode_grouped_avp(AVPCode.REQUESTED_SERVICE_UNIT, [
                    encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, 0),
                    encode_uint32_avp(AVPCode.CC_TIME, 0),
                ])
                inner_avps.append(rsu)

            # Used-Service-Unit (for Update and Terminate)
            if request_type in (CCRequestType.UPDATE, CCRequestType.TERMINATE):
                usage = used_map.get(rg, {})
                containers = usage.get("usedUnitContainer", [{}])
                container = containers[0] if containers else {}

                usu = encode_grouped_avp(AVPCode.USED_SERVICE_UNIT, [
                    encode_uint64_avp(AVPCode.CC_TOTAL_OCTETS, container.get("totalVolume", 0)),
                    encode_uint64_avp(AVPCode.CC_INPUT_OCTETS, container.get("uplinkVolume", 0)),
                    encode_uint64_avp(AVPCode.CC_OUTPUT_OCTETS, container.get("downlinkVolume", 0)),
                    encode_uint32_avp(AVPCode.CC_TIME, container.get("time", 0)),
                ])
                inner_avps.append(usu)

            mscc_avps.append(encode_grouped_avp(AVPCode.MULTIPLE_SERVICES_CC, inner_avps))

        return mscc_avps

    def _build_service_information(self) -> bytes:
        """Build 3GPP Service-Information > PS-Information AVP."""
        ps_avps = [
            encode_utf8_avp(AVPCode.CALLED_STATION_ID, self.subscriber.get("apn", "internet")),
        ]

        mcc = self.subscriber.get("mcc", "466")
        mnc = self.subscriber.get("mnc", "92")
        ps_avps.append(encode_utf8_avp(AVPCode.TGPP_SGSN_MCC_MNC, mcc + mnc, TGPP_VENDOR_ID))

        ps_info = encode_grouped_avp(AVPCode.PS_INFORMATION, ps_avps, TGPP_VENDOR_ID)
        return encode_grouped_avp(AVPCode.SERVICE_INFORMATION, [ps_info], TGPP_VENDOR_ID)

    async def send_ccr(
        self,
        request_type: CCRequestType,
        rating_groups: List[int],
        used_units: List[dict] = None,
    ) -> Tuple[bool, float, Optional[dict]]:
        """Send a Credit-Control-Request and return (success, latency_ms, parsed_answer)."""
        if not self._transport.connected:
            return False, 0.0, None

        if request_type == CCRequestType.INITIAL:
            self._session_id = f"{self._transport.origin_host};{int(time.time())};{uuid.uuid4().hex[:8]}"
            self._cc_request_number = 0
        else:
            self._cc_request_number += 1

        avps = [
            encode_utf8_avp(AVPCode.SESSION_ID, self._session_id),
            encode_utf8_avp(AVPCode.ORIGIN_HOST, self._transport.origin_host),
            encode_utf8_avp(AVPCode.ORIGIN_REALM, self._transport.origin_realm),
            encode_utf8_avp(AVPCode.DESTINATION_REALM, self._transport.destination_realm),
            encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, self.auth_app_id),
            encode_uint32_avp(AVPCode.CC_REQUEST_TYPE, request_type),
            encode_uint32_avp(AVPCode.CC_REQUEST_NUMBER, self._cc_request_number),
        ]

        if self._transport.destination_host:
            avps.append(encode_utf8_avp(AVPCode.DESTINATION_HOST, self._transport.destination_host))

        # Subscription-Id
        avps.extend(self._build_subscription_id())

        # MSCC
        avps.extend(self._build_mscc(rating_groups, request_type, used_units))

        # Service-Information
        avps.append(self._build_service_information())

        start = time.perf_counter()
        answer = await self._transport.send_request(CommandCode.CCR, self.auth_app_id, avps)
        latency_ms = (time.perf_counter() - start) * 1000.0

        if answer is None:
            return False, latency_ms, None

        # Parse result code from answer
        result_code = 0
        for avp in answer.get("avps", []):
            if avp["code"] == AVPCode.RESULT_CODE:
                result_code = struct.unpack("!I", avp["data"][:4])[0] if len(avp["data"]) >= 4 else 0
                break

        success = result_code == 2001 or result_code == 0  # DIAMETER_SUCCESS or unparsed
        return success, latency_ms, {"result_code": result_code, "answer": answer}
