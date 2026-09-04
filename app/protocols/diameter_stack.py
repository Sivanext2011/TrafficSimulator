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
from collections import deque, Counter

logger = logging.getLogger(__name__)


class DiameterDiagnostics:
    """Process-wide diagnostics for Diameter: a ring buffer of recent messages
    (decoded + hex) and per-peer health/connection status. Consumed by the
    /api/diameter/* endpoints so operators can see wire activity and state
    without reading pod logs."""

    def __init__(self, capacity: int = 200):
        self.messages: deque = deque(maxlen=capacity)
        self.health: Dict[str, dict] = {}   # peer_key -> status dict
        self.result_codes: Counter = Counter()

    # ---- capture ----
    def record_message(self, direction: str, peer: str, header: dict,
                       avps_decoded=None, raw: bytes = b""):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "direction": direction,               # "TX" or "RX"
            "peer": peer,
            "command_code": header.get("command_code"),
            "is_request": header.get("is_request"),
            "application_id": header.get("application_id"),
            "hop_by_hop": header.get("hop_by_hop"),
            "length": header.get("length"),
            "avps": avps_decoded or [],
            "hex": raw.hex() if raw else "",
        }
        self.messages.append(entry)

    def get_messages(self, limit: int = 50, peer: str = None):
        items = list(self.messages)
        if peer:
            items = [m for m in items if m["peer"] == peer]
        return items[-limit:]

    # ---- health ----
    def _peer(self, key: str) -> dict:
        return self.health.setdefault(key, {
            "peer": key, "state": "idle", "cer_result": None,
            "peer_origin_host": None, "peer_origin_realm": None,
            "last_error": None, "reconnect_count": 0,
            "dwr_received": 0, "dwa_sent": 0,
            "last_tx": None, "last_rx": None, "connected": False,
        })

    def set_state(self, key, state, **kw):
        p = self._peer(key); p["state"] = state
        for k, v in kw.items():
            p[k] = v

    def note_reconnect(self, key):
        self._peer(key)["reconnect_count"] += 1

    def note_error(self, key, err):
        self._peer(key)["last_error"] = str(err)

    def note_result_code(self, code):
        if code is not None:
            self.result_codes[str(code)] += 1

    def get_status(self):
        return {"peers": list(self.health.values()),
                "result_codes": dict(self.result_codes)}


# Process-wide singleton
DIAG = DiameterDiagnostics()



# ─── Diameter Constants ───────────────────────────────────────────────────────

class CommandCode(IntEnum):
    CER = 257  # Capabilities-Exchange
    DWR = 280  # Device-Watchdog
    CCR = 272  # Credit-Control (standard 3GPP DCCA)
    ERICSSON_CC = 16777214  # Ericsson CIP Credit-Control command (CBEV Gy via SDP)
    SLR = 8388635  # Spending-Limit (3GPP)
    ASR = 274  # Abort-Session
    RAR = 258  # Re-Auth


# Ericsson AB Diameter vendor id and CIP charging application id.
ERICSSON_VENDOR_ID = 193
ERICSSON_CHARGING_CIP_APP_ID = 16777232


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
    MULTIPLE_SERVICES_INDICATOR = 455
    RATING_GROUP = 432
    SERVICE_IDENTIFIER = 439
    REQUESTED_SERVICE_UNIT = 437
    USED_SERVICE_UNIT = 446
    GRANTED_SERVICE_UNIT = 431
    CC_TOTAL_OCTETS = 421
    CC_INPUT_OCTETS = 412
    CC_OUTPUT_OCTETS = 414
    CC_TIME = 420
    VALIDITY_TIME = 448
    FINAL_UNIT_INDICATION = 430
    FINAL_UNIT_ACTION = 449
    SERVICE_INFORMATION = 873  # 3GPP
    PS_INFORMATION = 874  # 3GPP
    SERVICE_CONTEXT_ID = 461  # Selects the charging service context (e.g. Gy: 32251@3gpp.org)
    TGPP_CHARGING_ID = 2
    CALLED_STATION_ID = 30
    TGPP_SGSN_MCC_MNC = 18
    TGPP_RAT_TYPE = 21
    TGPP_USER_LOCATION_INFO = 22  # 3GPP-User-Location-Info (OctetString)
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
    proxiable: bool = False,
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
    if proxiable:
        flags |= 0x40  # P bit (message may be proxied/relayed/redirected)

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

    @property
    def peer_key(self) -> str:
        return f"{self.host}:{self.port}#{self.origin_host}"

    def _next_hop_by_hop(self) -> int:
        self._hop_by_hop += 1
        return self._hop_by_hop

    def _next_end_to_end(self) -> int:
        self._end_to_end += 1
        return self._end_to_end

    async def connect(self) -> bool:
        """Establish TCP connection and perform CER/CEA exchange."""
        # Drop any stale/half-open association before opening a fresh one.
        if self._writer is not None or self._recv_task is not None:
            await self.disconnect()
        DIAG.set_state(self.peer_key, "connecting", connected=False)
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
                DIAG.set_state(self.peer_key, "cer_failed", cer_result="failed", connected=False)
                await self.disconnect()
                return False

            DIAG.set_state(self.peer_key, "connected", cer_result="ok", connected=True)
            return True

        except (OSError, asyncio.TimeoutError) as e:
            logger.error(f"Diameter connect failed: {e}")
            DIAG.note_error(self.peer_key, e)
            DIAG.set_state(self.peer_key, "connect_failed", connected=False)
            await self.disconnect()
            return False

    async def ensure_connected(self) -> bool:
        """Return True if a live association exists, otherwise (re)connect.

        This detects a wedged/half-open socket left behind by a previous call
        (e.g. after a WinError 64 / peer RST) and re-establishes a fresh
        CER/CEA association instead of reusing a dead transport.
        """
        if self._connected and self._writer is not None and not self._writer.is_closing():
            return True
        return await self.connect()

    def _fail_pending(self, exc: Exception) -> None:
        """Resolve all in-flight request futures so callers fail fast instead
        of waiting for the 30s timeout when the connection dies."""
        pending, self._pending = self._pending, {}
        for fut in pending.values():
            if not fut.done():
                fut.set_exception(exc)

    async def disconnect(self):
        """Close the Diameter connection and release all resources."""
        self._connected = False
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except (asyncio.CancelledError, Exception):
                pass
            self._recv_task = None
        # Unblock any callers still waiting on an answer.
        self._fail_pending(ConnectionError("Diameter connection closed"))
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._writer = None
        self._reader = None

    async def send_request(self, command_code: int, app_id: int, avps: List[bytes],
                           proxiable: bool = False) -> Optional[dict]:
        """Send a Diameter request and wait for the answer.

        proxiable: set the P-bit. Required for application messages (e.g. Gy/Ro
        CCR) that must be relayed by the CHA Diameter Load Balancer to the
        charging function. Base-protocol messages (CER, DWR) must NOT set it.
        """
        if not self._connected or self._writer is None or self._writer.is_closing():
            logger.error("Diameter send skipped: no live connection")
            return None

        hbh = self._next_hop_by_hop()
        ete = self._next_end_to_end()

        msg = encode_diameter_message(command_code, app_id, hbh, ete, avps,
                                      is_request=True, proxiable=proxiable)

        future = asyncio.get_event_loop().create_future()
        self._pending[hbh] = future

        try:
            self._writer.write(msg)
            await self._writer.drain()
            DIAG.record_message("TX", self.peer_key,
                                {"command_code": command_code, "is_request": True,
                                 "application_id": app_id, "hop_by_hop": hbh, "length": len(msg)},
                                avps_decoded=[{"code": a["code"], "vendor_id": a.get("vendor_id", 0),
                                               "len": len(a.get("data", b""))} for a in decode_avps(b"".join(avps))],
                                raw=msg)
            DIAG.set_state(self.peer_key, "connected", last_tx=time.strftime("%H:%M:%S", time.gmtime()))

            # Wait for answer (timeout 30s)
            answer = await asyncio.wait_for(future, timeout=30.0)
            return answer

        except asyncio.TimeoutError:
            logger.error(f"Diameter request timed out (cmd={command_code}): no answer within 30s")
            self._pending.pop(hbh, None)
            # A timeout means the association is unhealthy; tear it down so the
            # next call reconnects instead of reusing a wedged socket.
            await self.disconnect()
            return None
        except (OSError, ConnectionError) as e:
            logger.error(f"Diameter send failed: {e}")
            self._pending.pop(hbh, None)
            await self.disconnect()
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

        # Add auth application IDs. Standard app-ids (<= 0xFFFFFF and not vendor)
        # go as plain Auth-Application-Id; Ericsson vendor app-ids (e.g. 16777232)
        # must be advertised via Vendor-Specific-Application-Id { Vendor-Id 193, ... }.
        for app_id in self.auth_app_ids:
            if app_id >= 16777216:  # vendor-specific application id
                avps.append(encode_grouped_avp(AVPCode.VENDOR_SPECIFIC_APP_ID, [
                    encode_uint32_avp(AVPCode.VENDOR_ID, ERICSSON_VENDOR_ID),
                    encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, app_id),
                ]))
            else:
                avps.append(encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, app_id))

        answer = await self.send_request(CommandCode.CER, 0, avps)
        # A valid CEA is command 257 with the R-bit cleared (is_request False).
        # Reject anything else so a wedged/misparsed response fails connect()
        # instead of being treated as success.
        if not answer:
            return False
        if answer.get("command_code") != CommandCode.CER or answer.get("is_request"):
            logger.error(
                f"Unexpected CER answer: cmd={answer.get('command_code')} "
                f"is_request={answer.get('is_request')}"
            )
            return False
        # Log the peer's advertised identity so we know the correct routing target.
        try:
            _peer = []
            _oh = _orl = None
            for avp in answer.get("avps", []):
                if avp["code"] == AVPCode.ORIGIN_HOST:
                    _oh = avp["data"].decode("utf-8", "replace")
                    _peer.append(f"ORIGIN_HOST={_oh}")
                elif avp["code"] == AVPCode.ORIGIN_REALM:
                    _orl = avp["data"].decode("utf-8", "replace")
                    _peer.append(f"ORIGIN_REALM={_orl}")
            DIAG.set_state(self.peer_key, "connected",
                           peer_origin_host=_oh, peer_origin_realm=_orl)
            logger.debug(f"CEA peer identity: {', '.join(_peer)}")
        except Exception:
            pass
        return True

    async def _receive_loop(self):
        """Background task to receive and dispatch Diameter messages."""
        exc: Optional[Exception] = None
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

                DIAG.record_message("RX", self.peer_key, header,
                                    avps_decoded=[{"code": a["code"], "vendor_id": a.get("vendor_id", 0),
                                                   "len": len(a.get("data", b""))} for a in avps],
                                    raw=header_data + body_data)
                DIAG.set_state(self.peer_key, "connected", last_rx=time.strftime("%H:%M:%S", time.gmtime()))
                # Track result code on answers
                if not header["is_request"]:
                    for a in avps:
                        if a["code"] == AVPCode.RESULT_CODE and len(a["data"]) >= 4:
                            DIAG.note_result_code(struct.unpack("!I", a["data"][:4])[0])
                            break

                logger.debug(
                    f"RX cmd={header['command_code']} is_request={header['is_request']} "
                    f"hbh={header['hop_by_hop']} len={header['length']} navps={len(avps)}"
                )

                if header["is_request"]:
                    # Handle incoming requests (DWR, etc.)
                    await self._handle_request(header)
                else:
                    # Dispatch answer to waiting future
                    hbh = header["hop_by_hop"]
                    future = self._pending.pop(hbh, None)
                    if future and not future.done():
                        future.set_result(header)

        except asyncio.IncompleteReadError as e:
            logger.info("Diameter connection closed by peer")
            exc = ConnectionError("connection closed by peer")
        except asyncio.CancelledError:
            # disconnect() cancelled us; it handles cleanup itself.
            raise
        except Exception as e:
            logger.error(f"Diameter receive error: {e}")
            exc = e
        finally:
            # Any exit other than an explicit cancel means the association is
            # dead: mark disconnected AND unblock in-flight requests so callers
            # fail fast instead of waiting for the 30s timeout.
            self._connected = False
            if exc:
                DIAG.note_error(self.peer_key, exc)
            DIAG.set_state(self.peer_key, "disconnected", connected=False)
            self._fail_pending(exc or ConnectionError("Diameter receive loop ended"))

    async def _handle_request(self, msg: dict):
        """Handle incoming Diameter requests (DWR -> DWA)."""
        cmd = msg["command_code"]
        logger.debug(f"Incoming request cmd={cmd} hbh={msg['hop_by_hop']}")
        if cmd == CommandCode.DWR:
            DIAG._peer(self.peer_key)["dwr_received"] += 1
            # DWA is command 280 (same as DWR) with the R-bit cleared.
            avps = [
                encode_uint32_avp(AVPCode.RESULT_CODE, 2001),  # DIAMETER_SUCCESS
                encode_utf8_avp(AVPCode.ORIGIN_HOST, self.origin_host),
                encode_utf8_avp(AVPCode.ORIGIN_REALM, self.origin_realm),
            ]
            answer = encode_diameter_message(
                CommandCode.DWR, 0, msg["hop_by_hop"], msg["end_to_end"],
                avps, is_request=False
            )
            if self._writer and not self._writer.is_closing():
                try:
                    self._writer.write(answer)
                    await self._writer.drain()
                    DIAG._peer(self.peer_key)["dwa_sent"] += 1
                except (OSError, ConnectionError) as e:
                    # Failing to answer the watchdog means the peer will drop
                    # us; surface it and let the association be torn down.
                    logger.error(f"Failed to send DWA: {e}")
                    self._connected = False


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
        # The ACTIVE CHA Gy service context (EricssonCharging-Ro-Gy, internal
        # charging) matches Service-Context-Id CONTAINING "32251@3GPP.org"
        # (note the UPPERCASE "3GPP"). Lowercase "3gpp.org" yields "No matching
        # service context" -> 5031/5012. Standard CCR (272), Auth-Application-Id 4.
        self.cc_command = CommandCode.CCR
        self.cc_app_id = auth_app_id  # 4 for Gy
        self.service_context_id = "32251@3GPP.org" if auth_app_id == 4 else "32260@3gpp.org"
        self._session_id: Optional[str] = None
        self._cc_request_number: int = 0
        # Per-rating-group quota tracking: rg -> {granted_total, used_total,
        # validity_time, final, final_unit_action, last_result_code}
        self._quota: Dict[int, dict] = {}

        self._transport = DiameterTransport(
            host=host,
            port=port,
            origin_host=origin_host,
            origin_realm=origin_realm,
            destination_host=destination_host,
            destination_realm=destination_realm,
            auth_app_ids=[self.cc_app_id],
        )

    async def connect(self) -> bool:
        # Detects and replaces a wedged/half-open transport instead of reusing it.
        return await self._transport.ensure_connected()

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

        # 3GPP-RAT-Type (OctetString, vendor 10415). 6 = EUTRAN (matches production).
        ps_avps.append(encode_avp(AVPCode.TGPP_RAT_TYPE, bytes([6]), TGPP_VENDOR_ID))

        # 3GPP-User-Location-Info (OctetString, vendor 10415). The GyData
        # enrichments normalize this for zone/roaming rating input. Build a
        # minimal ECGI-type ULI: geoType(0x82=ECGI) + MCC/MNC (BCD) + ECI(4B).
        def _bcd_plmn(mcc_s, mnc_s):
            mcc_s = (mcc_s + "000")[:3]
            mnc_s = (mnc_s + "00")[:3] if len(mnc_s) >= 3 else (mnc_s + "0")[:2]
            d = mcc_s + ("f" if len(mnc_s) == 2 else "") + mnc_s
            # nibble-swap per octet
            out = bytearray()
            for i in range(0, len(d), 2):
                hi = d[i]; lo = d[i+1] if i + 1 < len(d) else 'f'
                out.append((int(lo, 16) << 4) | int(hi, 16))
            return bytes(out)
        uli = bytes([0x82]) + _bcd_plmn(mcc, mnc) + bytes([0x00, 0x00, 0x00, 0x01])
        ps_avps.append(encode_avp(AVPCode.TGPP_USER_LOCATION_INFO, uli, TGPP_VENDOR_ID))

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
            self._quota = {}  # fresh quota tracking per session
        else:
            self._cc_request_number += 1

        # A vendor-specific Application-Id (16777232, Ericsson) MUST be advertised
        # via a grouped Vendor-Specific-Application-Id AVP { Vendor-Id 193,
        # Auth-Application-Id }, not a bare Auth-Application-Id — otherwise CHA
        # rejects with 5012 (Failed-AVP: Auth-Application-Id). Matches production capture.
        if self.cc_app_id != 4:
            app_id_avp = encode_grouped_avp(AVPCode.VENDOR_SPECIFIC_APP_ID, [
                encode_uint32_avp(AVPCode.VENDOR_ID, ERICSSON_VENDOR_ID),
                encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, self.cc_app_id),
            ])
        else:
            app_id_avp = encode_uint32_avp(AVPCode.AUTH_APPLICATION_ID, self.cc_app_id)

        # AVP order verified against OnlineRo_Gy dictionary (strict, ignoreMandatoryFlag=false):
        # Session-Id, Origin-Host, Origin-Realm, Destination-Realm, (Vendor-Specific-)App-Id,
        # Service-Context-Id, CC-Request-Number, CC-Request-Type, ...
        avps = [
            encode_utf8_avp(AVPCode.SESSION_ID, self._session_id),
            encode_utf8_avp(AVPCode.ORIGIN_HOST, self._transport.origin_host),
            encode_utf8_avp(AVPCode.ORIGIN_REALM, self._transport.origin_realm),
            encode_utf8_avp(AVPCode.DESTINATION_REALM, self._transport.destination_realm),
            app_id_avp,
            encode_utf8_avp(AVPCode.SERVICE_CONTEXT_ID, self.service_context_id),
            encode_uint32_avp(AVPCode.CC_REQUEST_NUMBER, self._cc_request_number),
            encode_uint32_avp(AVPCode.CC_REQUEST_TYPE, request_type),
        ]

        if self._transport.destination_host:
            avps.append(encode_utf8_avp(AVPCode.DESTINATION_HOST, self._transport.destination_host))

        # Multiple-Services-Indicator = MULTIPLE_SERVICES_SUPPORTED (1), sent when MSCC is used.
        if request_type in (CCRequestType.INITIAL, CCRequestType.UPDATE):
            avps.append(encode_uint32_avp(AVPCode.MULTIPLE_SERVICES_INDICATOR, 1))

        # Subscription-Id (MSISDN + IMSI)
        avps.extend(self._build_subscription_id())

        # Event-Timestamp (seconds since 1900 per RFC 3588 time format)
        avps.append(encode_uint32_avp(AVPCode.EVENT_TIMESTAMP, (int(time.time()) + 2208988800) & 0xFFFFFFFF))

        # MSCC
        avps.extend(self._build_mscc(rating_groups, request_type, used_units))

        # Service-Information
        avps.append(self._build_service_information())

        start = time.perf_counter()
        logger.debug(f"TX CCR type={int(request_type)} cmd={int(self.cc_command)} appid={self.cc_app_id} navps={len(avps)} scid={self.service_context_id} dest_realm={self._transport.destination_realm}")
        answer = await self._transport.send_request(self.cc_command, self.cc_app_id, avps,
                                                     proxiable=True)
        latency_ms = (time.perf_counter() - start) * 1000.0

        if answer is None:
            return False, latency_ms, None

        # Parse top-level Result-Code from answer
        result_code = 0
        for avp in answer.get("avps", []):
            if avp["code"] == AVPCode.RESULT_CODE:
                result_code = struct.unpack("!I", avp["data"][:4])[0] if len(avp["data"]) >= 4 else 0
                break

        # Parse each MSCC into structured grant details (result code, granted
        # volume/time, validity-time, final-unit-indication/action).
        mscc_list = self._parse_answer_mscc(answer.get("avps", []))
        mscc_codes = [m["result_code"] for m in mscc_list if m["result_code"] is not None]

        # Update per-rating-group quota tracking and detect final/exhaustion.
        for m in mscc_list:
            self._update_quota(m, request_type)

        top_ok = result_code in (2001, 0)
        mscc_ok = all(c == 2001 for c in mscc_codes) if mscc_codes else True
        success = top_ok and mscc_ok
        logger.debug(f"CCA result_code={result_code} mscc={mscc_list} success={success}")
        return success, latency_ms, {
            "result_code": result_code,
            "mscc_result_codes": mscc_codes,
            "mscc": mscc_list,
            "quota": self.get_quota_state(),
            "final": self.is_final(),
            "answer": answer,
        }

    # ── Grant / quota / Final-Unit-Indication handling ──────────────────────

    def _parse_answer_mscc(self, top_avps: List[dict]) -> List[dict]:
        """Parse each Multiple-Services-Credit-Control in the CCA into a dict:
        {rating_group, result_code, granted_total_octets, granted_time,
         validity_time, final, final_unit_action}."""
        out = []
        for avp in top_avps:
            if avp.get("code") != AVPCode.MULTIPLE_SERVICES_CC:
                continue
            rg = rc = gtot = gtime = validity = fua = None
            final = False
            for iavp in decode_avps(avp["data"]):
                c = iavp["code"]; d = iavp["data"]
                if c == AVPCode.RATING_GROUP and len(d) >= 4:
                    rg = struct.unpack("!I", d[:4])[0]
                elif c == AVPCode.RESULT_CODE and len(d) >= 4:
                    rc = struct.unpack("!I", d[:4])[0]
                elif c == AVPCode.VALIDITY_TIME and len(d) >= 4:
                    validity = struct.unpack("!I", d[:4])[0]
                elif c == AVPCode.GRANTED_SERVICE_UNIT:
                    for g in decode_avps(d):
                        if g["code"] == AVPCode.CC_TOTAL_OCTETS and len(g["data"]) >= 8:
                            gtot = struct.unpack("!Q", g["data"][:8])[0]
                        elif g["code"] == AVPCode.CC_TIME and len(g["data"]) >= 4:
                            gtime = struct.unpack("!I", g["data"][:4])[0]
                elif c == AVPCode.FINAL_UNIT_INDICATION:
                    final = True
                    for f in decode_avps(d):
                        if f["code"] == AVPCode.FINAL_UNIT_ACTION and len(f["data"]) >= 4:
                            fua = struct.unpack("!I", f["data"][:4])[0]
            out.append({
                "rating_group": rg,
                "result_code": rc,
                "granted_total_octets": gtot,
                "granted_time": gtime,
                "validity_time": validity,
                "final": final,
                "final_unit_action": fua,
            })
        return out

    def _update_quota(self, mscc: dict, request_type: "CCRequestType") -> None:
        """Update per-rating-group quota tracking from a parsed MSCC."""
        rg = mscc.get("rating_group")
        if rg is None:
            return
        q = self._quota.setdefault(rg, {
            "granted_total": 0, "used_total": 0, "validity_time": None,
            "final": False, "final_unit_action": None, "last_result_code": None,
            "exhausted": False,
        })
        q["last_result_code"] = mscc.get("result_code")
        if mscc.get("validity_time") is not None:
            q["validity_time"] = mscc["validity_time"]
        if mscc.get("final"):
            q["final"] = True
            q["final_unit_action"] = mscc.get("final_unit_action")
        gt = mscc.get("granted_total_octets")
        if gt is not None:
            # A new grant of 0 octets on a final indication means exhausted.
            q["granted_total"] += gt
            if gt == 0 and q["final"]:
                q["exhausted"] = True

    def record_usage(self, rating_group: int, used_octets: int) -> None:
        """Record consumed octets for a rating group (drives CCR-U used units)."""
        q = self._quota.setdefault(rating_group, {
            "granted_total": 0, "used_total": 0, "validity_time": None,
            "final": False, "final_unit_action": None, "last_result_code": None,
            "exhausted": False,
        })
        q["used_total"] += max(0, int(used_octets))
        if q["granted_total"] and q["used_total"] >= q["granted_total"] and q["final"]:
            q["exhausted"] = True

    def remaining_quota(self, rating_group: int) -> Optional[int]:
        """Remaining granted octets for a rating group (None if never granted)."""
        q = self._quota.get(rating_group)
        if not q or not q["granted_total"]:
            return None
        return max(0, q["granted_total"] - q["used_total"])

    def is_final(self, rating_group: Optional[int] = None) -> bool:
        """True if a Final-Unit-Indication was received (for a specific RG or any)."""
        if rating_group is not None:
            q = self._quota.get(rating_group)
            return bool(q and q["final"])
        return any(q.get("final") for q in self._quota.values())

    def is_exhausted(self, rating_group: Optional[int] = None) -> bool:
        """True if quota is exhausted (final grant consumed / zero final grant)."""
        if rating_group is not None:
            q = self._quota.get(rating_group)
            return bool(q and q["exhausted"])
        return any(q.get("exhausted") for q in self._quota.values())

    def get_quota_state(self) -> dict:
        """Snapshot of per-rating-group quota state for reporting/UI."""
        return {rg: dict(q) for rg, q in self._quota.items()}
