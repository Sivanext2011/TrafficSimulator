import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.consumption_engine import ConsumptionEngine
from app.protocols.diameter_stack import DiameterCCClient, CCRequestType
from app.protocols.chf import ChfProtocol
from app.protocols.pcf import PcfProtocol
from app.protocols.diameter_gy import DiameterGyProtocol
from app.protocols.diameter_sy import DiameterSyProtocol

# ─── Logging Setup ────────────────────────────────────────────────────────────
LOG_DIR = Path("/app/logs") if os.path.exists("/app") else Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "simulator.log"

file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
console_handler.setLevel(logging.INFO)

logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console_handler])
from app.protocols.diameter_ro import DiameterRoProtocol
from app.protocols.scapv2 import ScapV2Protocol

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Telecom Traffic Simulator", version="2.0.0")

CERT_DIR = Path("/app/certs")
CERT_DIR.mkdir(parents=True, exist_ok=True)

# Global state
consumption_engine = ConsumptionEngine()
connected_clients: List[WebSocket] = []


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
                "chargingId": int(sub.get("charging_id", int(time.time()) % 4294967295)),
                "homeProvidedChargingId": int(sub.get("charging_id", int(time.time()) % 4294967295)),
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
        return success, latency_ms, response_data or {}

    def get_session_ref(self) -> str:
        return self._session_ref

    def _parse_diameter_grants(self, response_data: Optional[dict]) -> dict:
        """Convert Diameter CCA response to the multipleUnitInformation format
        the consumption engine expects for grant parsing."""
        if not response_data:
            return {}

        # The engine expects: {"multipleUnitInformation": [{ratingGroup, grantedUnit: {totalVolume, time}}]}
        # For now provide defaults since Diameter grant parsing from AVPs is complex
        multi_unit_info = []
        for rg in self._rating_groups:
            multi_unit_info.append({
                "ratingGroup": rg,
                "resultCode": "SUCCESS",
                "grantedUnit": {
                    "totalVolume": 10 * 1024 * 1024,  # 10 MB default
                    "time": 300,
                },
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


class SpeedUpdate(BaseModel):
    speed_mbps: float


class ControlCommand(BaseModel):
    action: str
    protocol: Optional[str] = None
    tps: Optional[float] = None


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "static" / "index.html"
    return html_path.read_text()


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

            auth_app_id = 4  # Default Gy/Ro
            if protocol_name == "sy":
                auth_app_id = 16777302

            diameter_client = DiameterCCClient(
                host=diameter_host,
                port=diameter_port,
                origin_host=origin_host,
                origin_realm=origin_realm,
                destination_host=destination_host,
                destination_realm=destination_realm,
                auth_app_id=auth_app_id,
                subscriber=config.subscriber.model_dump(),
            )

            connected = await diameter_client.connect()
            if not connected:
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
    return consumption_engine.get_metrics()


@app.get("/api/logs", response_class=PlainTextResponse)
async def get_logs(lines: int = 100):
    """View the last N lines of the application log."""
    if not LOG_FILE.exists():
        return "No logs yet."
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
    return "".join(all_lines[-lines:])


@app.get("/api/logs/clear")
async def clear_logs():
    """Clear the log file."""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
    return {"status": "logs cleared"}


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
