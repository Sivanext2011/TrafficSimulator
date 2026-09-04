import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.consumption_engine import ConsumptionEngine
from app.protocols.diameter_stack import DiameterCCClient, CCRequestType, decode_avps, DIAG
from app.protocols.chf import ChfProtocol
from app.protocols.pcf import PcfProtocol
from app.protocols.diameter_gy import DiameterGyProtocol
from app.protocols.diameter_sy import DiameterSyProtocol
from app.protocols.spending_limit import SpendingLimitClient

# ─── Logging Setup ────────────────────────────────────────────────────────────
from logging.handlers import RotatingFileHandler

LOG_DIR = Path("/app/logs") if os.path.exists("/app") else Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "simulator.log"

file_handler = RotatingFileHandler(
    LOG_FILE, mode="a", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
console_handler.setLevel(logging.INFO)


class RingLogHandler(logging.Handler):
    """Keeps the last N log records in memory for the /api/logs/events endpoint."""
    def __init__(self, capacity: int = 500):
        super().__init__()
        from collections import deque
        self.records = deque(maxlen=capacity)

    def emit(self, record):
        try:
            self.records.append({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            })
        except Exception:
            pass


ring_handler = RingLogHandler(500)
ring_handler.setLevel(logging.DEBUG)
ring_handler.setFormatter(logging.Formatter("%(message)s"))

logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console_handler, ring_handler])

from app.protocols.diameter_ro import DiameterRoProtocol
from app.protocols.scapv2 import ScapV2Protocol

import httpx

logger = logging.getLogger(__name__)

app = FastAPI(title="Telecom Traffic Simulator", version="2.0.0")

CERT_DIR = Path("/app/certs")
CERT_DIR.mkdir(parents=True, exist_ok=True)

# Global state
consumption_engine = ConsumptionEngine()
connected_clients: List[WebSocket] = []

# eN28 notification storage
en28_notifications: List[dict] = []
en28_spending_limit_client: Optional[SpendingLimitClient] = None
full_session_task: Optional[asyncio.Task] = None

# Persistent Diameter clients, keyed by peer identity. The Diameter peer (DLB)
# permits only ONE association per Origin-Host, so we must REUSE a single
# connection across manual/create calls instead of opening a new one each time
# (a second CER with the same Origin-Host is rejected as a duplicate peer,
# causing the socket to be reset -> "Failed to connect to Diameter peer").
_diameter_clients: dict = {}
_diameter_clients_lock: Optional[asyncio.Lock] = None


def _get_diameter_lock() -> asyncio.Lock:
    global _diameter_clients_lock
    if _diameter_clients_lock is None:
        _diameter_clients_lock = asyncio.Lock()
    return _diameter_clients_lock


async def get_shared_diameter_client(
    host, port, origin_host, origin_realm,
    destination_host, destination_realm, auth_app_id, subscriber,
    service_context_id=None,
):
    """Return a connected DiameterCCClient for this peer, reusing the existing
    association if it is still alive, otherwise (re)connecting once."""
    key = (host, int(port), origin_host, origin_realm, auth_app_id)
    async with _get_diameter_lock():
        client = _diameter_clients.get(key)
        if client is not None:
            # Keep subscriber current for this call, then verify liveness.
            client.subscriber = subscriber or {}
            if service_context_id:
                client.service_context_id = service_context_id
            if await client._transport.ensure_connected():
                return client
            # Stale/dead: drop it and fall through to create a fresh one.
            _diameter_clients.pop(key, None)

        client = DiameterCCClient(
            host=host, port=port,
            origin_host=origin_host, origin_realm=origin_realm,
            destination_host=destination_host, destination_realm=destination_realm,
            auth_app_id=auth_app_id, subscriber=subscriber,
        )
        # Allow an explicit Service-Context-Id override from the caller/UI.
        if service_context_id:
            client.service_context_id = service_context_id
        if not await client.connect():
            return None
        _diameter_clients[key] = client
        return client


# ─── Session Handler Wrappers ─────────────────────────────────────────────────

class ChfSessionHandler:
    """Adapts the ChfProtocol to the ConsumptionEngine's session interface.

    The consumption engine expects:
      - create_session(rating_groups) -> (bool, float, response_dict)
      - update_session(sequence, used_units) -> (bool, float, response_dict)
      - release_session(sequence, used_units) -> (bool, float, response_dict)
      - get_session_ref() -> str
    """

    def __init__(
        self,
        fqdn: str,
        port: int,
        base_path: str = "",
        cert_path: str = None,
        key_path: str = None,
        ca_path: str = None,
        subscriber: dict = None,
        secure: bool = True,
        verify_ssl: bool = False,
    ):
        self.fqdn = fqdn
        self.port = port
        self.base_path = (base_path or "").rstrip("/")
        self.subscriber = subscriber or {}
        self.secure = secure
        self.verify_ssl = verify_ssl
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path

        scheme = "https" if self.secure else "http"
        self._base_url = f"{scheme}://{self.fqdn}:{self.port}{self.base_path}"
        self._charging_data_ref: Optional[str] = None
        self._charging_id: int = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            if not self.secure:
                self._client = httpx.AsyncClient(
                    verify=False,
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
            elif self.cert_path and self.key_path:
                self._client = httpx.AsyncClient(
                    verify=False,
                    cert=(self.cert_path, self.key_path),
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
            else:
                self._client = httpx.AsyncClient(
                    verify=False,
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
        return self._client

    def _build_create_payload(self, rating_groups: List[int]) -> dict:
        sub = self.subscriber
        mcc = sub.get("mcc", "466")
        mnc = sub.get("mnc", "01")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        charging_id = int(time.time()) % 4294967295
        self._charging_id = charging_id

        return {
            "subscriberIdentifier": sub.get("supi", f"imsi-{sub.get('imsi', '001010000000001')}"),
            "nfConsumerIdentification": {
                "nFName": sub.get("nf_name", "423e4567-e89b-12d3-a456-426655440001"),
                "nFIPv4Address": sub.get("nf_ip", "192.168.0.1"),
                "nFPLMNID": {
                    "mcc": mcc,
                    "mnc": mnc,
                },
                "nodeFunctionality": "SMF",
            },
            "invocationTimeStamp": timestamp,
            "invocationSequenceNumber": 0,
            "serviceSpecificationInfo": "32255_Dec-2020_Rel_16",
            "multipleUnitUsage": [
                {
                    "ratingGroup": rg,
                    "requestedUnit": {},
                    "uPFID": sub.get("upf_id", "123e4567-e89b-12d3-a456-426655440001"),
                }
                for rg in rating_groups
            ],
            "pDUSessionChargingInformation": {
                "chargingId": charging_id,
                "homeProvidedChargingId": charging_id,
                "userLocationinfo": {
                    "nrLocation": {
                        "tai": {
                            "plmnId": {"mcc": mcc, "mnc": mnc},
                            "tac": sub.get("tac", "000001"),
                        },
                        "ncgi": {
                            "plmnId": {"mcc": mcc, "mnc": mnc},
                            "nrCellId": sub.get("nr_cell_id", "000000001"),
                        },
                    }
                },
                "pduSessionInformation": {
                    "pduSessionID": int(sub.get("pdu_session_id", 1)),
                    "pduType": "IPV4",
                    "dnnId": sub.get("dnn", "internet"),
                    "ratType": "NR",
                    "startTime": timestamp,
                    "sscMode": "SSC_MODE_1",
                    "chargingCharacteristicsSelectionMode": "HOME_DEFAULT",
                    "hPlmnId": {"mcc": mcc, "mnc": mnc},
                    "servingCNPlmnId": {"mcc": mcc, "mnc": mnc},
                    "networkSlicingInfo": {
                        "sNSSAI": {
                            "sst": sub.get("slice_sst", 1),
                            "sd": sub.get("slice_sd", "000001"),
                        }
                    },
                    "authorizedQoSInformation": {
                        "5qi": int(sub.get("5qi", 9)),
                        "arp": {
                            "preemptCap": "MAY_PREEMPT",
                            "preemptVuln": "PREEMPTABLE",
                            "priorityLevel": 12,
                        },
                    },
                    "pduAddress": {
                        "pduIPv4Address": sub.get("pdu_ipv4", "10.20.30.40"),
                    },
                },
                "uetimeZone": sub.get("timezone", "+08:00"),
                "userInformation": {
                    "servedGPSI": sub.get("gpsi", f"msisdn-{sub.get('msisdn', '12125551234')}"),
                    "servedPEI": sub.get("pei", "imei-3577300601111100"),
                    "unauthenticatedFlag": False,
                },
            },
        }

    def _build_update_payload(self, sequence: int, used_units: List[dict]) -> dict:
        sub = self.subscriber
        mcc = sub.get("mcc", "466")
        mnc = sub.get("mnc", "01")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        mscc_list = []
        for u in used_units:
            containers = u.get("usedUnitContainer", [])
            enriched_containers = []
            for c in containers:
                enriched_containers.append({
                    "totalVolume": c.get("totalVolume", 0),
                    "downlinkVolume": c.get("downlinkVolume", 0),
                    "uplinkVolume": c.get("uplinkVolume", 0),
                    "localSequenceNumber": c.get("localSequenceNumber", sequence),
                    "quotaManagementIndicator": "ONLINE_CHARGING",
                    "serviceId": int(sub.get("service_id", 100)),
                    "triggerTimestamp": timestamp,
                    "triggers": [
                        {
                            "triggerCategory": "IMMEDIATE_REPORT",
                            "triggerType": "VOLUME_LIMIT",
                        }
                    ],
                })

            mscc_list.append({
                "ratingGroup": u["ratingGroup"],
                "UsedUnitContainer": enriched_containers,
                "requestedUnit": {},
                "uPFID": sub.get("upf_id", "123e4567-e89b-12d3-a456-426655440001"),
            })

        return {
            "invocationSequenceNumber": sequence,
            "invocationTimeStamp": timestamp,
            "serviceSpecificationInfo": "32255_Dec-2020_Rel_16",
            "multipleUnitUsage": mscc_list,
            "nfConsumerIdentification": {
                "nFIPv4Address": sub.get("nf_ip", "192.168.0.1"),
                "nFName": sub.get("nf_name", "423e4567-e89b-12d3-a456-426655440001"),
                "nFPLMNID": {
                    "mcc": mcc,
                    "mnc": mnc,
                },
                "nodeFunctionality": "SMF",
            },
            "pDUSessionChargingInformation": {
                "chargingId": int(sub.get("charging_id", self._charging_id)),
                "homeProvidedChargingId": int(sub.get("charging_id", self._charging_id)),
                "userLocationinfo": {
                    "nrLocation": {
                        "tai": {
                            "plmnId": {"mcc": mcc, "mnc": mnc},
                            "tac": sub.get("tac", "000001"),
                        },
                        "ncgi": {
                            "plmnId": {"mcc": mcc, "mnc": mnc},
                            "nrCellId": sub.get("nr_cell_id", "000000001"),
                        },
                    }
                },
                "uetimeZone": sub.get("timezone", "+08:00"),
            },
            "subscriberIdentifier": sub.get("supi", f"imsi-{sub.get('imsi', '001010000000001')}"),
        }

    def _build_release_payload(self, sequence: int, used_units: List[dict]) -> dict:
        sub = self.subscriber
        mcc = sub.get("mcc", "466")
        mnc = sub.get("mnc", "01")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        mscc_list = []
        for u in used_units:
            containers = u.get("usedUnitContainer", [])
            enriched_containers = []
            for c in containers:
                enriched_containers.append({
                    "totalVolume": c.get("totalVolume", 0),
                    "downlinkVolume": c.get("downlinkVolume", 0),
                    "uplinkVolume": c.get("uplinkVolume", 0),
                    "localSequenceNumber": c.get("localSequenceNumber", sequence),
                    "quotaManagementIndicator": "ONLINE_CHARGING",
                    "serviceId": int(sub.get("service_id", 100)),
                    "triggerTimestamp": timestamp,
                    "triggers": [
                        {
                            "triggerCategory": "IMMEDIATE_REPORT",
                            "triggerType": "FINAL",
                        }
                    ],
                })

            mscc_list.append({
                "ratingGroup": u["ratingGroup"],
                "UsedUnitContainer": enriched_containers,
                "uPFID": sub.get("upf_id", "123e4567-e89b-12d3-a456-426655440001"),
            })

        return {
            "invocationSequenceNumber": sequence,
            "invocationTimeStamp": timestamp,
            "serviceSpecificationInfo": "32255_Dec-2020_Rel_16",
            "multipleUnitUsage": mscc_list,
            "nfConsumerIdentification": {
                "nFIPv4Address": sub.get("nf_ip", "192.168.0.1"),
                "nFName": sub.get("nf_name", "423e4567-e89b-12d3-a456-426655440001"),
                "nFPLMNID": {
                    "mcc": mcc,
                    "mnc": mnc,
                },
                "nodeFunctionality": "SMF",
            },
            "subscriberIdentifier": sub.get("supi", f"imsi-{sub.get('imsi', '001010000000001')}"),
        }

    async def create_session(self, rating_groups: List[int]):
        """Create a CHF session. Returns (success, latency_ms, response_dict)."""
        client = await self._get_client()
        url = f"{self._base_url}/chargingdata"
        payload = self._build_create_payload(rating_groups)

        logger.info(f">>> CHF CREATE REQUEST: URL={url}")
        logger.info(f">>> PAYLOAD: {json.dumps(payload, indent=2)}")

        start = time.perf_counter()
        try:
            response = await client.post(url, json=payload)
            latency_ms = (time.perf_counter() - start) * 1000.0

            logger.info(f"<<< CHF CREATE RESPONSE: status={response.status_code}, latency={latency_ms:.1f}ms")
            logger.info(f"<<< HEADERS: {dict(response.headers)}")
            logger.info(f"<<< BODY: {response.text[:1000]}")

            if response.status_code in (200, 201):
                location = response.headers.get("location", "")
                if location:
                    self._charging_data_ref = location.rstrip("/").split("/")[-1]
                else:
                    body = response.json()
                    self._charging_data_ref = body.get("chargingDataRef", str(int(time.time())))

                response_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                return True, latency_ms, response_data
            else:
                return False, latency_ms, {}
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000.0
            logger.error(f"CHF create_session error: {e}")
            return False, latency_ms, {}

    async def update_session(self, sequence: int, used_units: List[dict]):
        """Update a CHF session. Returns (success, latency_ms, response_dict)."""
        client = await self._get_client()
        url = f"{self._base_url}/chargingdata/{self._charging_data_ref}/update"
        payload = self._build_update_payload(sequence, used_units)

        logger.info(f">>> CHF UPDATE REQUEST: URL={url}, seq={sequence}")
        logger.info(f">>> PAYLOAD: {json.dumps(payload, indent=2)}")

        start = time.perf_counter()
        try:
            response = await client.post(url, json=payload)
            latency_ms = (time.perf_counter() - start) * 1000.0

            logger.info(f"<<< CHF UPDATE RESPONSE: status={response.status_code}, latency={latency_ms:.1f}ms")
            logger.info(f"<<< BODY: {response.text[:1000]}")

            if response.status_code == 200:
                response_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                return True, latency_ms, response_data
            else:
                return False, latency_ms, {}
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000.0
            logger.error(f"CHF update_session error: {e}")
            return False, latency_ms, {}

    async def release_session(self, sequence: int, used_units: List[dict]):
        """Release a CHF session. Returns (success, latency_ms, response_dict)."""
        client = await self._get_client()
        url = f"{self._base_url}/chargingdata/{self._charging_data_ref}/release"
        payload = self._build_release_payload(sequence, used_units)

        logger.info(f">>> CHF RELEASE REQUEST: URL={url}, seq={sequence}")
        logger.info(f">>> PAYLOAD: {json.dumps(payload, indent=2)}")

        start = time.perf_counter()
        try:
            response = await client.post(url, json=payload)
            latency_ms = (time.perf_counter() - start) * 1000.0

            logger.info(f"<<< CHF RELEASE RESPONSE: status={response.status_code}, latency={latency_ms:.1f}ms")
            logger.info(f"<<< BODY: {response.text[:500]}")

            if response.status_code in (200, 204):
                return True, latency_ms, {}
            else:
                return False, latency_ms, {}
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000.0
            logger.error(f"CHF release_session error: {e}")
            return False, latency_ms, {}

    def get_session_ref(self) -> str:
        return self._charging_data_ref or ""

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class PcfSessionHandler:
    """Adapts PCF (Npcf_SMPolicyControl) to the ConsumptionEngine interface.

    Endpoints:
      - POST /npcf-smpolicycontrol/v1/sm-policies (create)
      - POST /npcf-smpolicycontrol/v1/sm-policies/{id}/update (update)
      - POST /npcf-smpolicycontrol/v1/sm-policies/{id}/delete (release)
    """

    def __init__(self, fqdn, port, base_path="", cert_path=None, key_path=None,
                 ca_path=None, subscriber=None, secure=True, verify_ssl=False):
        self.fqdn = fqdn
        self.port = port
        self.base_path = (base_path or "/npcf-smpolicycontrol/v1").rstrip("/")
        self.subscriber = subscriber or {}
        self.secure = secure
        self.verify_ssl = verify_ssl
        self.cert_path = cert_path
        self.key_path = key_path
        self._sm_policy_id: str = ""
        self._client = None

        scheme = "https" if secure else "http"
        self._base_url = f"{scheme}://{fqdn}:{port}{self.base_path}"

    async def _get_client(self):
        if self._client is None or self._client.is_closed:
            kwargs = {"verify": False, "timeout": 30.0}
            if self.secure and self.cert_path and self.key_path:
                kwargs["cert"] = (self.cert_path, self.key_path)
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def create_session(self, rating_groups: List[int]):
        sub = self.subscriber
        payload = {
            "supi": f"imsi-{sub.get('imsi', '001010000000001')}",
            "gpsi": f"msisdn-{sub.get('msisdn', '12125551234')}",
            "pduSessionId": 5,
            "pduSessionType": "IPV4",
            "dnn": sub.get("dnn", "internet"),
            "notificationUri": "http://smf:8080/callback",
            "sliceInfo": {
                "sst": sub.get("slice_sst", 1),
                "sd": sub.get("slice_sd", "000001"),
            },
            "ipv4Address": "10.20.30.40",
            "servingNetwork": {
                "mcc": sub.get("mcc", "466"),
                "mnc": sub.get("mnc", "92"),
            },
            "ratType": "NR",
            "accessType": "3GPP_ACCESS",
        }

        client = await self._get_client()
        url = f"{self._base_url}/sm-policies"
        start = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            latency = (time.perf_counter() - start) * 1000.0
            success = resp.status_code in (200, 201)
            if success:
                location = resp.headers.get("location", "")
                self._sm_policy_id = location.rstrip("/").split("/")[-1] if location else ""
                if not self._sm_policy_id:
                    body = resp.json() if resp.text else {}
                    self._sm_policy_id = body.get("smPolicyId", str(int(time.time())))
            return success, latency, resp.json() if resp.text else {}
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return False, latency, None

    async def update_session(self, sequence: int = 0, used_units: List[dict] = None):
        if not self._sm_policy_id:
            return False, 0.0, None

        payload = {
            "repPolicyCtrlReqTriggers": ["RES_MO_RE"],
            "accuUsageReports": [
                {
                    "refUmIds": str(u.get("ratingGroup", "")),
                    "volUsage": u.get("usedUnitContainer", [{}])[0].get("totalVolume", 0),
                    "volUsageUplink": u.get("usedUnitContainer", [{}])[0].get("uplinkVolume", 0),
                    "volUsageDownlink": u.get("usedUnitContainer", [{}])[0].get("downlinkVolume", 0),
                }
                for u in (used_units or [])
            ],
        }

        client = await self._get_client()
        url = f"{self._base_url}/sm-policies/{self._sm_policy_id}/update"
        start = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            latency = (time.perf_counter() - start) * 1000.0
            return resp.status_code in (200, 204), latency, resp.json() if resp.text else {}
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return False, latency, None

    async def release_session(self, sequence: int = 0, used_units: List[dict] = None):
        if not self._sm_policy_id:
            return False, 0.0, None

        payload = {
            "accuUsageReports": [
                {
                    "refUmIds": str(u.get("ratingGroup", "")),
                    "volUsage": u.get("usedUnitContainer", [{}])[0].get("totalVolume", 0),
                }
                for u in (used_units or [])
            ],
        }

        client = await self._get_client()
        url = f"{self._base_url}/sm-policies/{self._sm_policy_id}/delete"
        start = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            latency = (time.perf_counter() - start) * 1000.0
            return resp.status_code in (200, 204), latency, None
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return False, latency, None

    def get_session_ref(self) -> str:
        return self._sm_policy_id

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class DiameterSessionHandler:
    """Adapts DiameterCCClient to the ConsumptionEngine's session interface.

    The consumption engine expects:
      - create_session(rating_groups) -> (bool, float, response_dict)
      - update_session(sequence, used_units) -> (bool, float, response_dict)
      - release_session(sequence, used_units) -> (bool, float, response_dict)
      - get_session_ref() -> str
    """

    def __init__(self, client: DiameterCCClient):
        self._client = client
        self._rating_groups: List[int] = []
        self._session_ref: str = ""

    async def create_session(self, rating_groups: List[int]):
        """Send CCR-Initial. Returns (success, latency_ms, response_dict)."""
        self._rating_groups = rating_groups
        success, latency_ms, response_data = await self._client.send_ccr(
            request_type=CCRequestType.INITIAL,
            rating_groups=rating_groups,
        )
        if success and self._client._session_id:
            self._session_ref = self._client._session_id

        # Convert Diameter answer to a format the engine can parse grants from
        parsed = self._parse_diameter_grants(response_data)
        return success, latency_ms, parsed

    async def update_session(self, sequence: int, used_units: List[dict]):
        """Send CCR-Update. Returns (success, latency_ms, response_dict)."""
        success, latency_ms, response_data = await self._client.send_ccr(
            request_type=CCRequestType.UPDATE,
            rating_groups=self._rating_groups,
            used_units=used_units,
        )
        parsed = self._parse_diameter_grants(response_data)
        return success, latency_ms, parsed

    async def release_session(self, sequence: int, used_units: List[dict]):
        """Send CCR-Terminate. Returns (success, latency_ms, response_dict)."""
        success, latency_ms, response_data = await self._client.send_ccr(
            request_type=CCRequestType.TERMINATE,
            rating_groups=self._rating_groups,
            used_units=used_units,
        )
        # Return a JSON-serializable summary. The raw diameter answer contains
        # AVP payloads as bytes which FastAPI cannot serialize; expose only the
        # result code and a clean grant summary (as update/create do).
        result_code = response_data.get("result_code") if response_data else None
        parsed = self._parse_diameter_grants(response_data)
        parsed["resultCode"] = result_code
        return success, latency_ms, parsed

    def get_session_ref(self) -> str:
        return self._session_ref

    def _parse_diameter_grants(self, response_data: Optional[dict]) -> dict:
        """Convert a Diameter CCA into the multipleUnitInformation format the
        engine expects, parsing the REAL Granted-Service-Unit AVPs from the
        answer (not a hardcoded grant), so failed/zero grants are reported
        truthfully instead of always showing a 10 MB success."""
        if not response_data:
            return {"multipleUnitInformation": []}

        answer = response_data.get("answer") or {}
        top_avps = answer.get("avps", []) if isinstance(answer, dict) else []

        import struct as _struct

        def _u32(b):
            return _struct.unpack("!I", b[:4])[0] if len(b) >= 4 else 0

        def _u64(b):
            return _struct.unpack("!Q", b[:8])[0] if len(b) >= 8 else 0

        multi_unit_info = []
        # AVP codes: MSCC 456, Rating-Group 432, Result-Code 268,
        # Granted-Service-Unit 431, CC-Total-Octets 421, CC-Time 420.
        for avp in top_avps:
            if avp.get("code") != 456:  # Multiple-Services-Credit-Control
                continue
            inner = decode_avps(avp.get("data", b""))
            rg = rc = total_vol = time_grant = validity = None
            final = False
            for iavp in inner:
                c = iavp["code"]; d = iavp["data"]
                if c == 432:
                    rg = _u32(d)
                elif c == 268:
                    rc = _u32(d)
                elif c == 448:  # Validity-Time
                    validity = _u32(d)
                elif c == 430:  # Final-Unit-Indication (grouped)
                    final = True
                elif c == 431:  # Granted-Service-Unit (grouped)
                    for g in decode_avps(d):
                        if g["code"] == 421:
                            total_vol = _u64(g["data"])
                        elif g["code"] == 420:
                            time_grant = _u32(g["data"])
            multi_unit_info.append({
                "ratingGroup": rg if rg is not None else (self._rating_groups[0] if self._rating_groups else 0),
                "resultCode": "SUCCESS" if (rc in (None, 2001)) else str(rc),
                "grantedUnit": {
                    "totalVolume": total_vol if total_vol is not None else 0,
                    "time": time_grant if time_grant is not None else 0,
                },
                "validityTime": validity if validity is not None else 0,
                "finalUnitIndication": final,
            })

        # No MSCC/grant in the CCA -> report a zero grant with the top-level
        # result code so the UI reflects reality (accepted but nothing granted).
        if not multi_unit_info:
            top_rc = response_data.get("result_code")
            for rg in self._rating_groups:
                multi_unit_info.append({
                    "ratingGroup": rg,
                    "resultCode": "SUCCESS" if top_rc in (None, 2001) else str(top_rc),
                    "grantedUnit": {"totalVolume": 0, "time": 0},
                })

        return {"multipleUnitInformation": multi_unit_info}


# ─── Models ───────────────────────────────────────────────────────────────────

class EndpointConfig(BaseModel):
    protocol: str  # chf, pcf, gy, sy, ro, scapv2
    fqdn: str
    port: int = 443
    base_path: Optional[str] = None
    secure: bool = True
    verify_ssl: bool = False


class SubscriberConfig(BaseModel):
    msisdn: str = "886912345678"
    imsi: str = "466010000000001"
    rating_group: int = 1
    slice_sst: int = 1
    slice_sd: str = "000001"
    dnn: str = "internet"
    apn: str = "internet"
    mcc: str = "466"
    mnc: str = "01"


class TrafficConfig(BaseModel):
    protocol: str
    endpoint: EndpointConfig
    subscriber: SubscriberConfig = SubscriberConfig()
    speed_mbps: float = 10.0
    rating_groups: List[int] = [1000]
    session_duration_sec: int = 300
    num_sessions: int = 1
    # Diameter-specific fields
    diameter_host: Optional[str] = None
    diameter_port: int = 3868
    origin_host: Optional[str] = None
    origin_realm: Optional[str] = None
    destination_host: Optional[str] = None
    destination_realm: Optional[str] = None
    service_context_id: Optional[str] = None
    auth_app_id: Optional[int] = None


class SpeedUpdate(BaseModel):
    speed_mbps: float


class ControlCommand(BaseModel):
    action: str
    protocol: Optional[str] = None
    tps: Optional[float] = None


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check endpoint for Docker HEALTHCHECK."""
    return {"status": "ok", "version": app.version}


# ─── Server-side Settings Persistence ─────────────────────────────────────────
SETTINGS_DIR = Path("/app/config") if os.path.exists("/app") else Path("config")
SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = SETTINGS_DIR / "settings.json"


@app.get("/api/settings")
async def get_settings():
    """Retrieve all saved settings from server-side storage."""
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


@app.post("/api/settings")
async def save_settings(request: Request):
    """Save settings to server-side storage (persists across container restarts)."""
    data = await request.json()
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"status": "saved"}


# ── Named integration profiles (multi-environment) ───────────────────────────
PROFILES_DIR = SETTINGS_DIR / "profiles"


def _safe_profile_name(name: str) -> str:
    keep = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c for c in (name or "") if c in keep)[:64]


@app.get("/api/profiles")
async def list_profiles():
    """List saved integration profile names."""
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    names = sorted(p.stem for p in PROFILES_DIR.glob("*.json"))
    return {"profiles": names}


@app.get("/api/profiles/{name}")
async def get_profile(name: str):
    """Get a named profile's settings blob."""
    f = PROFILES_DIR / f"{_safe_profile_name(name)}.json"
    if not f.exists():
        return {"error": f"profile not found: {name}"}
    return json.loads(f.read_text(encoding="utf-8"))


@app.post("/api/profiles/{name}")
async def save_profile(name: str, request: Request):
    """Save/overwrite a named profile (settings JSON in the body)."""
    safe = _safe_profile_name(name)
    if not safe:
        return {"error": "invalid profile name"}
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    (PROFILES_DIR / f"{safe}.json").write_text(
        json.dumps(await request.json(), indent=2), encoding="utf-8")
    return {"status": "saved", "profile": safe}


@app.delete("/api/profiles/{name}")
async def delete_profile(name: str):
    """Delete a named profile."""
    f = PROFILES_DIR / f"{_safe_profile_name(name)}.json"
    if f.exists():
        f.unlink()
        return {"status": "deleted", "profile": name}
    return {"error": f"profile not found: {name}"}


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "static" / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.post("/api/certs/upload")
async def upload_certs(
    client_cert: UploadFile = File(...),
    client_key: UploadFile = File(...),
    ca_cert: Optional[UploadFile] = File(None),
    profile_name: str = Form("default")
):
    profile_dir = CERT_DIR / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)

    cert_path = profile_dir / "client.crt"
    key_path = profile_dir / "client.key"

    with open(cert_path, "wb") as f:
        shutil.copyfileobj(client_cert.file, f)
    with open(key_path, "wb") as f:
        shutil.copyfileobj(client_key.file, f)

    ca_path = None
    if ca_cert:
        ca_path = profile_dir / "ca.crt"
        with open(ca_path, "wb") as f:
            shutil.copyfileobj(ca_cert.file, f)

    return {
        "status": "ok",
        "profile": profile_name,
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "ca_path": str(ca_path) if ca_path else None,
    }


@app.get("/api/certs/profiles")
async def list_cert_profiles():
    profiles = []
    if CERT_DIR.exists():
        for d in CERT_DIR.iterdir():
            if d.is_dir():
                files = [f.name for f in d.iterdir()]
                profiles.append({"name": d.name, "files": files})
    return {"profiles": profiles}


@app.post("/api/traffic/start")
async def start_traffic(config: TrafficConfig):
    try:
        protocol_name = config.protocol.lower()
        sbi_protocols = {"chf", "pcf", "scapv2"}
        diameter_protocols = {"gy", "ro", "sy"}

        # Strip http:// or https:// from FQDN if user accidentally included it
        fqdn = config.endpoint.fqdn.strip()
        if fqdn.startswith("http://"):
            fqdn = fqdn[7:]
        elif fqdn.startswith("https://"):
            fqdn = fqdn[8:]
        fqdn = fqdn.rstrip("/")
        config.endpoint.fqdn = fqdn

        if protocol_name not in sbi_protocols and protocol_name not in diameter_protocols:
            return {"error": f"Unknown protocol: {config.protocol}"}

        # Resolve cert paths
        cert_profile = CERT_DIR / "default"
        cert_path = str(cert_profile / "client.crt") if (cert_profile / "client.crt").exists() else None
        key_path = str(cert_profile / "client.key") if (cert_profile / "client.key").exists() else None
        ca_path = str(cert_profile / "ca.crt") if (cert_profile / "ca.crt").exists() else None

        if protocol_name in sbi_protocols:
            if protocol_name == "chf":
                handler = ChfSessionHandler(
                    fqdn=config.endpoint.fqdn,
                    port=config.endpoint.port,
                    base_path=config.endpoint.base_path or "/nchf-convergedcharging/v3",
                    cert_path=cert_path,
                    key_path=key_path,
                    ca_path=ca_path,
                    subscriber=config.subscriber.model_dump(),
                    secure=config.endpoint.secure,
                    verify_ssl=config.endpoint.verify_ssl,
                )
            elif protocol_name == "pcf":
                handler = PcfSessionHandler(
                    fqdn=config.endpoint.fqdn,
                    port=config.endpoint.port,
                    base_path=config.endpoint.base_path or "/npcf-smpolicycontrol/v1",
                    cert_path=cert_path,
                    key_path=key_path,
                    ca_path=ca_path,
                    subscriber=config.subscriber.model_dump(),
                    secure=config.endpoint.secure,
                    verify_ssl=config.endpoint.verify_ssl,
                )
            elif protocol_name == "scapv2":
                handler = ChfSessionHandler(
                    fqdn=config.endpoint.fqdn,
                    port=config.endpoint.port,
                    base_path=config.endpoint.base_path or "/scapv2/charging/v1",
                    cert_path=cert_path,
                    key_path=key_path,
                    ca_path=ca_path,
                    subscriber=config.subscriber.model_dump(),
                    secure=config.endpoint.secure,
                    verify_ssl=config.endpoint.verify_ssl,
                )

        elif protocol_name in diameter_protocols:
            diameter_host = config.diameter_host or config.endpoint.fqdn
            diameter_port = config.diameter_port or 3868
            origin_host = config.origin_host or "telecom-simulator.local"
            origin_realm = config.origin_realm or "simulator.local"
            destination_host = config.destination_host or diameter_host
            destination_realm = config.destination_realm or "operator.com"

            auth_app_id = config.auth_app_id or (16777302 if protocol_name == "sy" else 4)

            # Reuse the shared, persistent association (the DLB rejects a duplicate
            # connection from the same Origin-Host) and honor the Service-Context-Id
            # override so traffic uses the same working parameters as manual mode.
            diameter_client = await get_shared_diameter_client(
                host=diameter_host, port=diameter_port,
                origin_host=origin_host, origin_realm=origin_realm,
                destination_host=destination_host, destination_realm=destination_realm,
                auth_app_id=auth_app_id, subscriber=config.subscriber.model_dump(),
                service_context_id=config.service_context_id,
            )
            if diameter_client is None:
                return {"error": f"Failed to connect to Diameter peer at {diameter_host}:{diameter_port}"}

            handler = DiameterSessionHandler(diameter_client)

        # Start consumption engine
        await consumption_engine.start(
            protocol=handler,
            speed_mbps=config.speed_mbps,
            num_sessions=config.num_sessions,
            rating_groups=config.rating_groups,
            session_duration_sec=config.session_duration_sec,
            metrics_callback=broadcast_metrics,
        )

        return {
            "status": "started",
            "protocol": config.protocol,
            "speed_mbps": config.speed_mbps,
            "num_sessions": config.num_sessions,
            "rating_groups": config.rating_groups,
        }
    except Exception as e:
        import traceback
        logger.error(f"start_traffic error: {traceback.format_exc()}")
        return {"error": str(e)}


@app.post("/api/traffic/stop")
async def stop_traffic():
    await consumption_engine.stop()
    return {"status": "stopped"}


@app.get("/api/diameter/messages")
async def diameter_messages(limit: int = 50, peer: Optional[str] = None):
    """Recent Diameter messages (TX/RX) with decoded AVP summary + hex."""
    return {"messages": DIAG.get_messages(limit=limit, peer=peer)}


@app.get("/api/diameter/status")
async def diameter_status():
    """Per-peer Diameter connection/health status and result-code breakdown."""
    return DIAG.get_status()


@app.get("/api/logs/events")
async def log_events(limit: int = 100, level: Optional[str] = None):
    """Return the last N structured log events (optionally filtered by level)."""
    items = list(ring_handler.records)
    if level:
        lv = level.upper()
        items = [r for r in items if r["level"] == lv]
    return {"events": items[-limit:]}


@app.get("/api/logs/level")
async def get_log_level():
    """Get the current effective root log level."""
    return {"level": logging.getLevelName(logging.getLogger().getEffectiveLevel())}


@app.post("/api/logs/level")
async def set_log_level(request: Request):
    """Set the root/console log level at runtime (DEBUG/INFO/WARNING/ERROR)."""
    data = await request.json()
    level_name = str(data.get("level", "INFO")).upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        return {"error": f"invalid level: {level_name}"}
    logging.getLogger().setLevel(level)
    console_handler.setLevel(level)
    logger.info(f"Log level set to {level_name}")
    return {"status": "ok", "level": level_name}


@app.post("/api/traffic/speed")
async def update_speed(update: SpeedUpdate):
    """Update the simulated download speed in real time (slider changes)."""
    consumption_engine.set_speed(update.speed_mbps)
    return {"status": "ok", "speed_mbps": update.speed_mbps}


@app.post("/api/traffic/tps")
async def update_tps(cmd: ControlCommand):
    """Legacy TPS update endpoint (kept for backward compatibility)."""
    if cmd.tps is not None:
        consumption_engine.set_speed(cmd.tps)
    return {"status": "ok", "tps": cmd.tps}


@app.get("/api/metrics")
async def get_metrics():
    m = consumption_engine.get_metrics()
    # Latency percentiles from the engine's recent samples
    lat = sorted(getattr(consumption_engine, "_latencies", []) or [])
    def _pct(p):
        if not lat:
            return 0.0
        i = min(len(lat) - 1, int(round((p / 100.0) * (len(lat) - 1))))
        return round(lat[i], 2)
    m["latency_p50_ms"] = _pct(50)
    m["latency_p95_ms"] = _pct(95)
    m["latency_p99_ms"] = _pct(99)
    # Diameter result-code breakdown (from diagnostics)
    m["result_codes"] = DIAG.get_status().get("result_codes", {})
    return m


@app.post("/api/metrics/reset")
async def reset_metrics():
    """Reset all metrics counters to zero."""
    consumption_engine._metrics = {
        "total_requests": 0,
        "successful": 0,
        "failed": 0,
        "active_sessions": 0,
        "current_tps": 0.0,
        "avg_latency_ms": 0.0,
        "speed_mbps": consumption_engine._speed_mbps,
        "total_volume_consumed_mb": 0.0,
        "state": "idle",
        "protocol": None,
    }
    consumption_engine._latencies.clear()
    consumption_engine._request_times.clear()
    return {"status": "metrics reset"}


# ─── Manual Step-by-Step Session Mode ─────────────────────────────────────────
# Allows sending Initial/Update/Release one at a time for trace capture

# Store active manual sessions keyed by session_id
manual_sessions: Dict[str, dict] = {}


class ManualSessionCreate(BaseModel):
    """Config to create a manual step-by-step session."""
    protocol: str  # chf, pcf, gy, ro, sy, scapv2
    fqdn: str
    port: int = 443
    base_path: Optional[str] = None
    secure: bool = True
    verify_ssl: bool = False
    subscriber: SubscriberConfig = SubscriberConfig()
    rating_groups: List[int] = [1000]
    # Diameter-specific
    diameter_host: Optional[str] = None
    diameter_port: int = 3868
    origin_host: Optional[str] = None
    origin_realm: Optional[str] = None
    destination_host: Optional[str] = None
    destination_realm: Optional[str] = None
    service_context_id: Optional[str] = None
    auth_app_id: Optional[int] = None


class ManualSessionUpdate(BaseModel):
    """Config for sending an update in manual mode."""
    session_id: str
    used_units: Optional[List[dict]] = None  # Optional custom used units
    total_volume: int = 1048576  # 1MB default per RG
    uplink_volume: int = 314572  # ~30%
    downlink_volume: int = 734003  # ~70%


class ManualSessionRelease(BaseModel):
    """Config for sending a release in manual mode."""
    session_id: str
    used_units: Optional[List[dict]] = None
    total_volume: int = 524288  # 512KB default final
    uplink_volume: int = 157286
    downlink_volume: int = 367001


@app.post("/api/manual/create")
async def manual_create_session(config: ManualSessionCreate):
    """Step 1: Send Initial/Create request. Returns full response with granted units/policy."""
    try:
        protocol_name = config.protocol.lower()

        # Strip protocol prefix from FQDN
        fqdn = config.fqdn.strip()
        if fqdn.startswith("http://"):
            fqdn = fqdn[7:]
        elif fqdn.startswith("https://"):
            fqdn = fqdn[8:]
        fqdn = fqdn.rstrip("/")

        # Resolve cert paths
        cert_profile = CERT_DIR / "default"
        cert_path = str(cert_profile / "client.crt") if (cert_profile / "client.crt").exists() else None
        key_path = str(cert_profile / "client.key") if (cert_profile / "client.key").exists() else None

        if protocol_name in ("chf", "scapv2"):
            base_path = config.base_path or ("/nchf-convergedcharging/v2" if protocol_name == "chf" else "/scapv2/charging/v1")
            handler = ChfSessionHandler(
                fqdn=fqdn, port=config.port, base_path=base_path,
                cert_path=cert_path, key_path=key_path, ca_path=None,
                subscriber=config.subscriber.model_dump(),
                secure=config.secure, verify_ssl=config.verify_ssl,
            )
        elif protocol_name == "pcf":
            base_path = config.base_path or "/npcf-smpolicycontrol/v1"
            handler = PcfSessionHandler(
                fqdn=fqdn, port=config.port, base_path=base_path,
                cert_path=cert_path, key_path=key_path, ca_path=None,
                subscriber=config.subscriber.model_dump(),
                secure=config.secure, verify_ssl=config.verify_ssl,
            )
        elif protocol_name in ("gy", "ro", "sy"):
            diameter_host = config.diameter_host or fqdn
            auth_app_id = config.auth_app_id or (16777302 if protocol_name == "sy" else 4)
            diameter_client = await get_shared_diameter_client(
                host=diameter_host,
                port=config.diameter_port or 3868,
                origin_host=config.origin_host or "telecom-simulator.local",
                origin_realm=config.origin_realm or "simulator.local",
                destination_host=config.destination_host or diameter_host,
                destination_realm=config.destination_realm or "operator.com",
                auth_app_id=auth_app_id,
                subscriber=config.subscriber.model_dump(),
                service_context_id=config.service_context_id,
            )
            if diameter_client is None:
                return {"error": f"Failed to connect to Diameter peer at {diameter_host}:{config.diameter_port}"}
            handler = DiameterSessionHandler(diameter_client)
        else:
            return {"error": f"Unknown protocol: {protocol_name}"}

        # Send CREATE
        start_time = time.perf_counter()
        success, latency_ms, response_data = await handler.create_session(config.rating_groups)
        session_ref = handler.get_session_ref()

        # Feed dashboard metrics (manual mode counts toward success/failure too)
        consumption_engine.record_manual(success, latency_ms)
        try:
            await broadcast_metrics(consumption_engine.get_metrics())
        except Exception:
            pass

        # Generate session ID
        session_id = f"manual_{protocol_name}_{int(time.time())}_{id(handler) % 10000}"

        # Store the session
        manual_sessions[session_id] = {
            "handler": handler,
            "protocol": protocol_name,
            "session_ref": session_ref,
            "sequence": 0,
            "rating_groups": config.rating_groups,
            "state": "created" if success else "failed",
            "history": [],
        }

        # Record this step
        step_record = {
            "step": "CREATE",
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "response": response_data,
            "session_ref": session_ref,
        }
        manual_sessions[session_id]["history"].append(step_record)

        # Parse policy/grant info for display
        policy_info = _extract_policy_info(protocol_name, response_data)

        return {
            "status": "created" if success else "failed",
            "session_id": session_id,
            "session_ref": session_ref,
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "response": response_data,
            "policy_info": policy_info,
            "next_step": "update",
        }
    except Exception as e:
        import traceback
        logger.error(f"manual_create error: {traceback.format_exc()}")
        return {"error": str(e)}


@app.post("/api/manual/update")
async def manual_update_session(config: ManualSessionUpdate):
    """Step 2+: Send Update request. Can be called multiple times."""
    try:
        session = manual_sessions.get(config.session_id)
        if not session:
            return {"error": f"Session not found: {config.session_id}"}
        if session["state"] not in ("created", "updated"):
            return {"error": f"Session in invalid state for update: {session['state']}"}

        handler = session["handler"]
        session["sequence"] += 1
        sequence = session["sequence"]

        # Build used units
        if config.used_units:
            used_units = config.used_units
        else:
            used_units = []
            for rg in session["rating_groups"]:
                used_units.append({
                    "ratingGroup": rg,
                    "usedUnitContainer": [{
                        "totalVolume": config.total_volume,
                        "uplinkVolume": config.uplink_volume,
                        "downlinkVolume": config.downlink_volume,
                        "localSequenceNumber": sequence,
                    }],
                    "requestedUnit": {},
                })

        # Send UPDATE
        success, latency_ms, response_data = await handler.update_session(
            sequence=sequence, used_units=used_units
        )

        session["state"] = "updated" if success else "update_failed"
        consumption_engine.record_manual(success, latency_ms)
        try:
            await broadcast_metrics(consumption_engine.get_metrics())
        except Exception:
            pass

        # Record step
        step_record = {
            "step": f"UPDATE #{sequence}",
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "request_used_units": used_units,
            "response": response_data,
        }
        session["history"].append(step_record)

        # Parse policy/grant info
        policy_info = _extract_policy_info(session["protocol"], response_data)

        return {
            "status": "updated" if success else "update_failed",
            "session_id": config.session_id,
            "sequence": sequence,
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "response": response_data,
            "policy_info": policy_info,
            "next_step": "update or release",
        }
    except Exception as e:
        import traceback
        logger.error(f"manual_update error: {traceback.format_exc()}")
        return {"error": str(e)}


@app.post("/api/manual/release")
async def manual_release_session(config: ManualSessionRelease):
    """Step 3: Send Release/Terminate request. Ends the session."""
    try:
        session = manual_sessions.get(config.session_id)
        if not session:
            return {"error": f"Session not found: {config.session_id}"}
        if session["state"] in ("released", "failed"):
            return {"error": f"Session already in state: {session['state']}"}

        handler = session["handler"]
        session["sequence"] += 1
        sequence = session["sequence"]

        # Build final used units
        if config.used_units:
            used_units = config.used_units
        else:
            used_units = []
            for rg in session["rating_groups"]:
                used_units.append({
                    "ratingGroup": rg,
                    "usedUnitContainer": [{
                        "totalVolume": config.total_volume,
                        "uplinkVolume": config.uplink_volume,
                        "downlinkVolume": config.downlink_volume,
                        "localSequenceNumber": sequence,
                    }],
                })

        # Send RELEASE
        success, latency_ms, response_data = await handler.release_session(
            sequence=sequence, used_units=used_units
        )

        session["state"] = "released" if success else "release_failed"
        consumption_engine.record_manual(success, latency_ms)
        try:
            await broadcast_metrics(consumption_engine.get_metrics())
        except Exception:
            pass

        # Record step
        step_record = {
            "step": "RELEASE",
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "request_used_units": used_units,
            "response": response_data,
        }
        session["history"].append(step_record)

        # Cleanup handler
        if hasattr(handler, 'close'):
            await handler.close()

        return {
            "status": "released" if success else "release_failed",
            "session_id": config.session_id,
            "sequence": sequence,
            "success": success,
            "latency_ms": round(latency_ms, 2),
            "response": response_data,
            "history": session["history"],
            "next_step": "done",
        }
    except Exception as e:
        import traceback
        logger.error(f"manual_release error: {traceback.format_exc()}")
        return {"error": str(e)}


@app.get("/api/manual/sessions")
async def list_manual_sessions():
    """List all active manual sessions."""
    sessions_list = []
    for sid, session in manual_sessions.items():
        sessions_list.append({
            "session_id": sid,
            "protocol": session["protocol"],
            "session_ref": session["session_ref"],
            "state": session["state"],
            "sequence": session["sequence"],
            "steps_completed": len(session["history"]),
        })
    return {"sessions": sessions_list}


@app.get("/api/manual/session/{session_id}")
async def get_manual_session(session_id: str):
    """Get full history and state of a manual session."""
    session = manual_sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    return {
        "session_id": session_id,
        "protocol": session["protocol"],
        "session_ref": session["session_ref"],
        "state": session["state"],
        "sequence": session["sequence"],
        "rating_groups": session["rating_groups"],
        "history": session["history"],
    }


@app.delete("/api/manual/session/{session_id}")
async def delete_manual_session(session_id: str):
    """Delete/cleanup a manual session."""
    session = manual_sessions.pop(session_id, None)
    if not session:
        return {"error": "Session not found"}
    handler = session.get("handler")
    if handler and hasattr(handler, 'close'):
        try:
            await handler.close()
        except Exception:
            pass
    return {"status": "deleted"}


def _extract_policy_info(protocol: str, response_data: Optional[dict]) -> dict:
    """Extract and structure policy/charging info from response for display."""
    if not response_data:
        return {}

    info = {}

    if protocol == "pcf":
        # PCF SM Policy response contains PCC rules, QoS, usage monitoring
        if "pccRules" in response_data:
            info["pcc_rules"] = []
            pcc_rules = response_data["pccRules"]
            if isinstance(pcc_rules, dict):
                for rule_id, rule in pcc_rules.items():
                    info["pcc_rules"].append({
                        "rule_id": rule_id,
                        "precedence": rule.get("precedence"),
                        "flow_infos": rule.get("flowInfos", []),
                        "ref_qos_data": rule.get("refQosData", []),
                        "ref_chg_data": rule.get("refChgData", []),
                    })

        if "qosDecision" in response_data or "qosDecs" in response_data:
            qos = response_data.get("qosDecision") or response_data.get("qosDecs", {})
            info["qos_decisions"] = []
            if isinstance(qos, dict):
                for qos_id, qos_data in qos.items():
                    info["qos_decisions"].append({
                        "qos_id": qos_id,
                        "5qi": qos_data.get("5qi"),
                        "max_br_ul": qos_data.get("maxbrUl"),
                        "max_br_dl": qos_data.get("maxbrDl"),
                        "gbr_ul": qos_data.get("gbrUl"),
                        "gbr_dl": qos_data.get("gbrDl"),
                        "arp": qos_data.get("arp"),
                        "priority_level": qos_data.get("priorityLevel"),
                    })

        if "sessRules" in response_data:
            info["session_rules"] = []
            sess_rules = response_data["sessRules"]
            if isinstance(sess_rules, dict):
                for rule_id, rule in sess_rules.items():
                    info["session_rules"].append({
                        "rule_id": rule_id,
                        "sess_ambr": rule.get("authSessAmbr"),
                        "default_qos": rule.get("authDefQos"),
                    })

        if "umDecs" in response_data:
            info["usage_monitoring"] = []
            um_decs = response_data["umDecs"]
            if isinstance(um_decs, dict):
                for um_id, um_data in um_decs.items():
                    info["usage_monitoring"].append({
                        "um_id": um_id,
                        "volume_threshold": um_data.get("volumeThreshold"),
                        "volume_threshold_uplink": um_data.get("volumeThresholdUplink"),
                        "volume_threshold_downlink": um_data.get("volumeThresholdDownlink"),
                        "time_threshold": um_data.get("timeThreshold"),
                    })

        if "chgDecs" in response_data:
            info["charging_decisions"] = []
            chg_decs = response_data["chgDecs"]
            if isinstance(chg_decs, dict):
                for chg_id, chg_data in chg_decs.items():
                    info["charging_decisions"].append({
                        "chg_id": chg_id,
                        "online": chg_data.get("online"),
                        "offline": chg_data.get("offline"),
                        "rating_group": chg_data.get("ratingGroup"),
                        "service_id": chg_data.get("serviceId"),
                        "metering_method": chg_data.get("meteringMethod"),
                    })

        # Policy control request triggers
        if "policyCtrlReqTriggers" in response_data:
            info["triggers"] = response_data["policyCtrlReqTriggers"]

    elif protocol in ("chf", "scapv2"):
        # CHF response contains granted units, triggers, quotas
        if "multipleUnitInformation" in response_data:
            info["granted_units"] = []
            for unit in response_data["multipleUnitInformation"]:
                granted = unit.get("grantedUnit", {})
                info["granted_units"].append({
                    "rating_group": unit.get("ratingGroup"),
                    "result_code": unit.get("resultCode"),
                    "granted_total_volume": granted.get("totalVolume"),
                    "granted_time": granted.get("time"),
                    "volume_quota_threshold": unit.get("volumeQuotaThreshold"),
                    "validity_time": unit.get("validityTime"),
                    "quota_holding_time": unit.get("quotaHoldingTime"),
                })

        if "triggers" in response_data:
            info["session_triggers"] = response_data["triggers"]

    elif protocol in ("gy", "ro"):
        # Diameter CCA - granted units
        if "multipleUnitInformation" in response_data:
            info["granted_units"] = []
            for unit in response_data["multipleUnitInformation"]:
                granted = unit.get("grantedUnit", {})
                info["granted_units"].append({
                    "rating_group": unit.get("ratingGroup"),
                    "result_code": unit.get("resultCode"),
                    "granted_total_volume": granted.get("totalVolume"),
                    "granted_time": granted.get("time"),
                })

    return info


@app.get("/api/logs", response_class=PlainTextResponse)
async def get_logs(lines: int = 100):
    """View the last N lines of the application log."""
    if not LOG_FILE.exists():
        return "No logs yet."
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
    return "".join(all_lines[-lines:])


@app.post("/api/test-connection")
async def test_connection(config: EndpointConfig):
    """Test connectivity to the configured endpoint.

    For SBI protocols: attempts an HTTP HEAD/GET to the endpoint.
    For Diameter protocols: attempts a TCP connection.
    """
    import socket

    fqdn = config.fqdn.strip()
    if fqdn.startswith("http://"):
        fqdn = fqdn[7:]
    elif fqdn.startswith("https://"):
        fqdn = fqdn[8:]
    fqdn = fqdn.rstrip("/")

    protocol = config.protocol.lower()
    start = time.perf_counter()

    if protocol in ("gy", "ro", "sy"):
        # TCP connection test for Diameter
        try:
            sock = socket.create_connection((fqdn, config.port), timeout=5)
            latency_ms = (time.perf_counter() - start) * 1000
            sock.close()
            return {
                "status": "ok",
                "message": f"TCP connection to {fqdn}:{config.port} successful",
                "latency_ms": round(latency_ms, 1),
            }
        except socket.timeout:
            return {"status": "error", "message": f"Connection to {fqdn}:{config.port} timed out (5s)"}
        except socket.gaierror:
            return {"status": "error", "message": f"DNS resolution failed for {fqdn}"}
        except OSError as e:
            return {"status": "error", "message": f"Connection failed: {e}"}
    else:
        # HTTP connection test for SBI protocols
        scheme = "https" if config.secure else "http"
        base_path = (config.base_path or "").rstrip("/")
        url = f"{scheme}://{fqdn}:{config.port}{base_path}"

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(url)
                latency_ms = (time.perf_counter() - start) * 1000
                return {
                    "status": "ok",
                    "message": f"HTTP {resp.status_code} from {url}",
                    "latency_ms": round(latency_ms, 1),
                    "http_status": resp.status_code,
                }
        except httpx.ConnectTimeout:
            return {"status": "error", "message": f"Connection to {url} timed out (5s)"}
        except httpx.ConnectError as e:
            return {"status": "error", "message": f"Connection failed: {e}"}
        except Exception as e:
            return {"status": "error", "message": f"Error: {e}"}


@app.post("/api/logs/clear")
async def clear_logs():
    """Clear the log file."""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
    return {"status": "logs cleared"}


# ─── eN28 Notification Callback ───────────────────────────────────────────────

@app.post("/notifications/spendinglimit")
async def en28_notification_callback(request: Request):
    """Receive spending limit notifications from CHF (eN28).

    The CHF POSTs SpendingLimitStatus here when a policy counter status changes.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    notification = {
        "timestamp": timestamp,
        "body": body,
        "supi": body.get("supi", ""),
        "statusInfoList": [],
    }

    # Extract statusInfoList from various possible response formats
    spending_status = body.get("spendingLimitStatus", body)
    status_list = spending_status.get("statusInfoList", [])
    notification["statusInfoList"] = status_list

    en28_notifications.append(notification)
    # Keep last 100 notifications
    if len(en28_notifications) > 100:
        en28_notifications.pop(0)

    logger.info(f"<<< eN28 NOTIFICATION RECEIVED: {len(status_list)} counter(s)")
    for entry in status_list:
        counter_id = entry.get("policyCounterId", "unknown")
        current = entry.get("currentStatus", "unknown")
        previous = entry.get("previousStatus", "")
        logger.info(f"    Counter '{counter_id}': {previous} → {current}")

    # Broadcast to WebSocket clients
    await broadcast_metrics({
        "type": "en28_notification",
        "notification": notification,
    })

    return Response(status_code=204)


@app.get("/api/en28/notifications")
async def get_en28_notifications():
    """Get all received eN28 notifications."""
    return {"notifications": en28_notifications}


@app.delete("/api/en28/notifications")
async def clear_en28_notifications():
    """Clear all stored eN28 notifications."""
    en28_notifications.clear()
    return {"status": "cleared"}


# ─── Full Session Mode (eN28 + Nchf_ConvergedCharging) ───────────────────────

class FullSessionConfig(BaseModel):
    """Configuration for Full Session mode: eN28 Subscribe → CHF → Unsubscribe."""
    # CHF endpoint (Nchf_ConvergedCharging)
    chf_fqdn: str
    chf_port: int = 443
    chf_base_path: str = "/nchf-convergedcharging/v2"
    chf_secure: bool = True

    # eN28 endpoint (Nchf_SpendingLimitControl) - can be same or different host
    en28_fqdn: Optional[str] = None  # defaults to chf_fqdn if not set
    en28_port: Optional[int] = None  # defaults to chf_port if not set
    en28_base_path: str = "/nchf-spendinglimitcontrol/v1"
    en28_secure: bool = True

    # Callback URI for eN28 notifications (must be reachable from CHF)
    notif_uri: str = "http://localhost:8080/notifications/spendinglimit"

    # Subscriber
    subscriber: SubscriberConfig = SubscriberConfig()

    # Spending limit config
    policy_counter_ids: List[str] = ["counter01"]
    initial_retrieval: bool = True
    enable_en28: bool = False  # If True, use Ericsson E-N28 extension (vendorSpecific-000193) for Policy Groups

    # Charging session config
    rating_groups: List[int] = [1000]
    speed_mbps: float = 10.0
    session_duration_sec: int = 300
    num_sessions: int = 1


@app.post("/api/traffic/start-full")
async def start_full_session(config: FullSessionConfig):
    """Start a Full Session: eN28 Subscribe → CHF Create → Consume → Release → Unsubscribe."""
    global en28_spending_limit_client, full_session_task

    try:
        # Stop any existing session
        if full_session_task and not full_session_task.done():
            await stop_full_session_internal()

        # Clear previous notifications
        en28_notifications.clear()

        # Resolve cert paths
        cert_profile = CERT_DIR / "default"
        cert_path = str(cert_profile / "client.crt") if (cert_profile / "client.crt").exists() else None
        key_path = str(cert_profile / "client.key") if (cert_profile / "client.key").exists() else None

        # Resolve eN28 endpoint (defaults to CHF if not specified)
        en28_fqdn = config.en28_fqdn or config.chf_fqdn
        en28_port = config.en28_port or config.chf_port

        # Create spending limit client
        en28_spending_limit_client = SpendingLimitClient(
            fqdn=en28_fqdn,
            port=en28_port,
            base_path=config.en28_base_path,
            cert_path=cert_path,
            key_path=key_path,
            secure=config.en28_secure,
            verify_ssl=False,
        )

        # Create CHF session handler
        chf_fqdn = config.chf_fqdn.strip()
        if chf_fqdn.startswith("http://"):
            chf_fqdn = chf_fqdn[7:]
        elif chf_fqdn.startswith("https://"):
            chf_fqdn = chf_fqdn[8:]
        chf_fqdn = chf_fqdn.rstrip("/")

        chf_handler = ChfSessionHandler(
            fqdn=chf_fqdn,
            port=config.chf_port,
            base_path=config.chf_base_path,
            cert_path=cert_path,
            key_path=key_path,
            ca_path=None,
            subscriber=config.subscriber.model_dump(),
            secure=config.chf_secure,
            verify_ssl=False,
        )

        # Build subscriber identifiers
        sub = config.subscriber
        supi = f"imsi-{sub.imsi}"
        gpsi = f"msisdn-{sub.msisdn}"

        # Check notifUri reachability — warn if localhost
        notif_uri = config.notif_uri
        notif_uri_warning = None
        if "localhost" in notif_uri or "127.0.0.1" in notif_uri:
            # Try to detect a routable local IP
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((en28_fqdn, en28_port))
                local_ip = s.getsockname()[0]
                s.close()
                suggested_uri = notif_uri.replace("localhost", local_ip).replace("127.0.0.1", local_ip)
                notif_uri_warning = (
                    f"WARNING: notifUri uses localhost — CHF cannot reach your simulator. "
                    f"Suggested: {suggested_uri}"
                )
                logger.warning(notif_uri_warning)
            except Exception:
                notif_uri_warning = "WARNING: notifUri uses localhost — CHF cannot send notifications back to your simulator"
                logger.warning(notif_uri_warning)

            # Broadcast the warning to the UI
            await broadcast_metrics({
                "type": "full_session_warning",
                "message": notif_uri_warning,
            })

        # Start the full session orchestration as a background task
        full_session_task = asyncio.create_task(
            _run_full_session(
                slc_client=en28_spending_limit_client,
                chf_handler=chf_handler,
                supi=supi,
                gpsi=gpsi,
                notif_uri=config.notif_uri,
                policy_counter_ids=config.policy_counter_ids,
                initial_retrieval=config.initial_retrieval,
                enable_en28=config.enable_en28,
                rating_groups=config.rating_groups,
                speed_mbps=config.speed_mbps,
                session_duration_sec=config.session_duration_sec,
                num_sessions=config.num_sessions,
            )
        )

        response = {
            "status": "started",
            "mode": "full_session",
            "en28_endpoint": f"{'https' if config.en28_secure else 'http'}://{en28_fqdn}:{en28_port}{config.en28_base_path}",
            "chf_endpoint": f"{'https' if config.chf_secure else 'http'}://{chf_fqdn}:{config.chf_port}{config.chf_base_path}",
            "notif_uri": notif_uri,
            "policy_counter_ids": config.policy_counter_ids,
            "rating_groups": config.rating_groups,
        }
        if notif_uri_warning:
            response["warning"] = notif_uri_warning
        return response

    except Exception as e:
        import traceback
        logger.error(f"start_full_session error: {traceback.format_exc()}")
        return {"error": str(e)}


@app.post("/api/traffic/stop-full")
async def stop_full_session():
    """Stop the full session orchestration."""
    await stop_full_session_internal()
    return {"status": "stopped"}


async def stop_full_session_internal():
    """Internal helper to stop the full session."""
    global full_session_task, en28_spending_limit_client

    # Stop the consumption engine first
    await consumption_engine.stop()

    # Cancel the orchestration task
    if full_session_task and not full_session_task.done():
        full_session_task.cancel()
        try:
            await asyncio.wait_for(full_session_task, timeout=10.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        full_session_task = None

    # Unsubscribe from eN28 (only if still subscribed — avoids double-unsubscribe)
    if en28_spending_limit_client and en28_spending_limit_client.is_subscribed:
        try:
            success, latency = await en28_spending_limit_client.unsubscribe()
            logger.info(f"eN28 unsubscribe on stop: success={success}, latency={latency:.1f}ms")
        except Exception as e:
            logger.error(f"Failed to unsubscribe on stop: {e}")
    else:
        logger.info("eN28: already unsubscribed or no client — skipping")

    # Close the client
    if en28_spending_limit_client:
        await en28_spending_limit_client.close()
        en28_spending_limit_client = None


async def _run_full_session(
    slc_client: SpendingLimitClient,
    chf_handler,
    supi: str,
    gpsi: str,
    notif_uri: str,
    policy_counter_ids: List[str],
    initial_retrieval: bool,
    enable_en28: bool,
    rating_groups: List[int],
    speed_mbps: float,
    session_duration_sec: int,
    num_sessions: int,
):
    """Orchestrate the full session lifecycle:
    1. eN28 Subscribe (spending limit)
    2. CHF Create → Consume → Updates → Release
    3. eN28 Unsubscribe
    """
    try:
        # === PHASE 1: eN28 Subscribe ===
        logger.info("=" * 60)
        logger.info("FULL SESSION: Phase 1 — eN28 Subscribe")
        logger.info("=" * 60)

        success, latency, initial_status = await slc_client.subscribe(
            supi=supi,
            gpsi=gpsi,
            notif_uri=notif_uri,
            policy_counter_ids=policy_counter_ids,
            initial_retrieval=initial_retrieval,
            enable_en28=enable_en28,
        )

        # Broadcast subscription result
        await broadcast_metrics({
            "type": "en28_subscribe",
            "success": success,
            "latency_ms": latency,
            "subscription_id": slc_client.subscription_id,
            "initial_status": initial_status,
        })

        if not success:
            logger.warning("eN28 Subscribe failed — continuing with CHF session only (degraded mode)")

        # If initial status was returned, store as a notification
        # Handle three formats:
        #   Standard N28: {"statusInfos": {"counterId": {"policyCounterId": "x", "currentStatus": "y"}}}
        #   3GPP: {"spendingLimitStatus": {"statusInfoList": [...]}}
        #   E-N28: {"vendorSpecific-000193": {"policyCounters": [...], "policyGroups": {...}}}
        if initial_status:
            status_info_list = []
            policy_groups = {}
            policy_counters_en28 = []

            # Try E-N28 format: vendorSpecific-000193 with policyGroups and policyCounters
            vendor_block = initial_status.get("vendorSpecific-000193")
            if vendor_block and isinstance(vendor_block, dict):
                policy_counters_en28 = vendor_block.get("policyCounters", [])
                policy_groups = vendor_block.get("policyGroups", {})

                for pc in policy_counters_en28:
                    status_info_list.append({
                        "policyCounterId": pc.get("policyCounterIdentifier", ""),
                        "currentStatus": pc.get("policyCounterStatus", "UNKNOWN"),
                        "policyGroupName": pc.get("policyGroupName", ""),
                    })
                logger.info(f"    E-N28 Policy Counters: {policy_counters_en28}")
                logger.info(f"    E-N28 Policy Groups: {policy_groups}")

            # Try Ericsson CHA standard format: {"statusInfos": {"1": {...}, "2": {...}}}
            elif "statusInfos" in initial_status:
                status_infos = initial_status["statusInfos"]
                if isinstance(status_infos, dict):
                    for counter_id, info in status_infos.items():
                        status_info_list.append({
                            "policyCounterId": info.get("policyCounterId", counter_id),
                            "currentStatus": info.get("currentStatus", "UNKNOWN"),
                        })
                    logger.info(f"    Initial counter status (Ericsson format): {status_info_list}")

            # Try 3GPP standard format: {"spendingLimitStatus": {"statusInfoList": [...]}}
            elif "spendingLimitStatus" in initial_status:
                sls = initial_status["spendingLimitStatus"]
                if isinstance(sls, dict):
                    status_info_list = sls.get("statusInfoList", [])
                    logger.info(f"    Initial counter status (3GPP format): {status_info_list}")

            if status_info_list or policy_groups:
                notification_entry = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "body": initial_status,
                    "supi": supi,
                    "statusInfoList": status_info_list,
                    "policyGroups": policy_groups,
                    "source": "initial_retrieval",
                }
                en28_notifications.append(notification_entry)

                # Emit WebSocket event so UI shows it immediately
                await broadcast_metrics({
                    "type": "en28_notification",
                    "source": "initial_retrieval",
                    "supi": supi,
                    "statusInfoList": status_info_list,
                    "policyGroups": policy_groups,
                    "subscription_id": slc_client.subscription_id,
                })

        # === PHASE 2: CHF Charging Session ===
        logger.info("=" * 60)
        logger.info("FULL SESSION: Phase 2 — CHF Converged Charging")
        logger.info("=" * 60)

        await consumption_engine.start(
            protocol=chf_handler,
            speed_mbps=speed_mbps,
            num_sessions=num_sessions,
            rating_groups=rating_groups,
            session_duration_sec=session_duration_sec,
            metrics_callback=broadcast_metrics,
        )

        # Wait for the consumption engine to complete
        while consumption_engine._running:
            await asyncio.sleep(1.0)

        # === PHASE 3: eN28 Unsubscribe ===
        logger.info("=" * 60)
        logger.info("FULL SESSION: Phase 3 — eN28 Unsubscribe")
        logger.info("=" * 60)

        if slc_client.is_subscribed:
            success, latency = await slc_client.unsubscribe()
            await broadcast_metrics({
                "type": "en28_unsubscribe",
                "success": success,
                "latency_ms": latency,
            })

        logger.info("=" * 60)
        logger.info("FULL SESSION: Complete")
        logger.info("=" * 60)

        await broadcast_metrics({
            "type": "full_session_complete",
            "en28_notifications_received": len(en28_notifications),
        })

    except asyncio.CancelledError:
        logger.info("Full session cancelled — cleaning up")
        # Don't unsubscribe here — stop_full_session_internal() handles it
        # to avoid the double-unsubscribe race condition
        pass
    except Exception as e:
        logger.error(f"Full session error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        await broadcast_metrics({
            "type": "full_session_error",
            "error": str(e),
        })
    finally:
        await chf_handler.close()
        await slc_client.close()


# ─── WebSocket for live metrics ───────────────────────────────────────────────

@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


async def broadcast_metrics(metrics: dict):
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_json(metrics)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connected_clients.remove(ws)


# ─── Static files ─────────────────────────────────────────────────────────────

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
