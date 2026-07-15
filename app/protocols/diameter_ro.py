"""Diameter Ro protocol simulation over HTTP (3GPP TS 32.299).

Simulates Ro Credit-Control (CCR/CCA) messages for IMS/VoLTE online charging
as HTTP REST calls with proper AVP structures represented as JSON.
"""

import time
import uuid
from typing import Tuple

from .base import BaseProtocol


class DiameterRoProtocol(BaseProtocol):
    """Diameter Ro protocol client (HTTP simulation).

    Simulates Credit-Control-Request (CCR) for IMS/VoLTE online charging:
    - CCR-I (CC-Request-Type=1): Initial (call setup)
    - CCR-U (CC-Request-Type=2): Update (mid-call quota refresh)
    - CCR-T (CC-Request-Type=3): Terminate (call end)

    Includes IMS-Information AVPs (Role-Of-Node, Node-Functionality,
    Calling-Party-Address, Called-Party-Address).
    """

    # CC-Request-Type values
    INITIAL_REQUEST = 1
    UPDATE_REQUEST = 2
    TERMINATION_REQUEST = 3

    # Role-Of-Node values
    ORIGINATING_ROLE = 0
    TERMINATING_ROLE = 1

    # Node-Functionality values
    S_CSCF = 0
    P_CSCF = 1
    I_CSCF = 2
    MRFC = 3
    MGCF = 4
    BGCF = 5
    AS = 6

    def __init__(
        self,
        fqdn: str,
        port: int,
        base_path: str = "",
        cert_path: str = None,
        key_path: str = None,
        ca_path: str = None,
        subscriber: dict = None,
        **kwargs,
    ):
        super().__init__(fqdn, port, base_path, cert_path, key_path, ca_path, subscriber or {}, **kwargs)
        self.session_id: str | None = None
        self._cc_request_number: int = 0
        self._origin_host: str = (subscriber or {}).get("origin_host", "scscf01.ims.mnc001.mcc001.3gppnetwork.org")
        self._origin_realm: str = (subscriber or {}).get("origin_realm", "ims.mnc001.mcc001.3gppnetwork.org")
        self._destination_host: str = (subscriber or {}).get("destination_host", "ocs01.ims.mnc001.mcc001.3gppnetwork.org")
        self._destination_realm: str = (subscriber or {}).get("destination_realm", "ims.mnc001.mcc001.3gppnetwork.org")

    def _generate_session_id(self) -> str:
        """Generate a Diameter-compliant Session-Id."""
        timestamp = int(time.time())
        unique = uuid.uuid4().hex[:8]
        return f"{self._origin_host};{timestamp};{unique}"

    def _build_subscription_id(self) -> list:
        """Build Subscription-Id AVP (MSISDN + IMSI)."""
        return [
            {
                "Subscription-Id-Type": 0,  # END_USER_E164 (MSISDN)
                "Subscription-Id-Data": self.subscriber.get("msisdn", "12125551234"),
            },
            {
                "Subscription-Id-Type": 1,  # END_USER_IMSI
                "Subscription-Id-Data": self.subscriber.get("imsi", "001010000000001"),
            },
            {
                "Subscription-Id-Type": 2,  # END_USER_SIP_URI
                "Subscription-Id-Data": self.subscriber.get(
                    "sip_uri",
                    f"sip:{self.subscriber.get('msisdn', '12125551234')}@ims.mnc001.mcc001.3gppnetwork.org",
                ),
            },
        ]

    def _build_ims_information(self) -> dict:
        """Build IMS-Information AVP for VoLTE charging."""
        calling = self.subscriber.get(
            "calling_party_address",
            f"tel:+{self.subscriber.get('msisdn', '12125551234')}",
        )
        called = self.subscriber.get(
            "called_party_address",
            f"tel:+{self.subscriber.get('called_msisdn', '12125559876')}",
        )

        return {
            "Event-Type": {
                "SIP-Method": "INVITE",
                "Event": "call",
            },
            "Role-Of-Node": self.subscriber.get("role_of_node", self.ORIGINATING_ROLE),
            "Node-Functionality": self.subscriber.get("node_functionality", self.S_CSCF),
            "User-Session-Id": str(uuid.uuid4()),
            "Calling-Party-Address": [calling],
            "Called-Party-Address": called,
            "Requested-Party-Address": [called],
            "Time-Stamps": {
                "SIP-Request-Timestamp": int(time.time()),
            },
            "Inter-Operator-Identifier": [
                {
                    "Originating-IOI": self._origin_realm,
                    "Terminating-IOI": self._destination_realm,
                }
            ],
            "IMS-Charging-Identifier": str(uuid.uuid4()),
            "SDP-Session-Description": [
                "v=0",
                f"o=- {int(time.time())} 0 IN IP4 10.0.0.1",
                "s=VoLTE Call",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0 8 97",
                "a=rtpmap:0 PCMU/8000",
                "a=rtpmap:8 PCMA/8000",
                "a=rtpmap:97 AMR-WB/16000",
            ],
            "Access-Network-Information": self.subscriber.get(
                "access_network_info",
                "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001010000100001",
            ),
            "Service-Id": "MMTEL-voice",
        }

    def _build_ccr(self, cc_request_type: int, used_units: dict | None = None) -> dict:
        """Build a full CCR message for IMS/VoLTE charging."""
        ccr = {
            "Session-Id": self.session_id,
            "Origin-Host": self._origin_host,
            "Origin-Realm": self._origin_realm,
            "Destination-Host": self._destination_host,
            "Destination-Realm": self._destination_realm,
            "Auth-Application-Id": 4,  # Diameter Credit-Control
            "Service-Context-Id": "32260@3gpp.org",  # IMS charging context
            "CC-Request-Type": cc_request_type,
            "CC-Request-Number": self._cc_request_number,
            "Event-Timestamp": int(time.time()),
            "Subscription-Id": self._build_subscription_id(),
            "Multiple-Services-Indicator": 1,
            "Multiple-Services-Credit-Control": [
                {
                    "Rating-Group": self.subscriber.get("rating_group", 10),
                    "Service-Identifier": self.subscriber.get("service_id", 500),  # VoLTE
                    **(
                        {
                            "Requested-Service-Unit": {
                                "CC-Time": 180,  # Request 180 seconds
                            }
                        }
                        if cc_request_type != self.TERMINATION_REQUEST
                        else {}
                    ),
                    **(
                        {
                            "Used-Service-Unit": {
                                "CC-Time": used_units.get("time", 60),
                                "CC-Total-Octets": used_units.get("total", 0),
                                "CC-Input-Octets": used_units.get("input", 0),
                                "CC-Output-Octets": used_units.get("output", 0),
                            }
                        }
                        if used_units
                        else {}
                    ),
                }
            ],
            "Service-Information": {
                "IMS-Information": self._build_ims_information(),
            },
            "User-Equipment-Info": {
                "User-Equipment-Info-Type": 0,  # IMEISV
                "User-Equipment-Info-Value": self.subscriber.get("imei", "1234567890123456"),
            },
        }
        return ccr

    async def create_session(self) -> Tuple[bool, float]:
        """Send CCR-Initial for VoLTE call setup."""
        self.session_id = self._generate_session_id()
        self._cc_request_number = 0

        payload = self._build_ccr(self.INITIAL_REQUEST)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/ro/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Initial",
                "X-Service-Context": "IMS-VoLTE",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code in (200, 201):
            body = response.json()
            result_code = body.get("Result-Code", 0)
            return result_code == 2001, latency_ms

        return False, latency_ms

    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Send CCR-Update for mid-call quota refresh."""
        if not self.session_id:
            return False, 0.0

        self._cc_request_number = sequence

        used_units = {
            "time": sequence * 60,  # 60 seconds per interval
            "total": 0,
            "input": 0,
            "output": 0,
        }

        payload = self._build_ccr(self.UPDATE_REQUEST, used_units=used_units)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/ro/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Update",
                "X-Service-Context": "IMS-VoLTE",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 200:
            body = response.json()
            result_code = body.get("Result-Code", 0)
            return result_code == 2001, latency_ms

        return False, latency_ms

    async def release_session(self) -> Tuple[bool, float]:
        """Send CCR-Terminate for call end."""
        if not self.session_id:
            return False, 0.0

        self._cc_request_number += 1

        used_units = {
            "time": 120,  # Final used time
            "total": 0,
            "input": 0,
            "output": 0,
        }

        payload = self._build_ccr(self.TERMINATION_REQUEST, used_units=used_units)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/ro/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Terminate",
                "X-Service-Context": "IMS-VoLTE",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 200:
            body = response.json()
            result_code = body.get("Result-Code", 0)
            success = result_code == 2001
            if success:
                self.session_id = None
            return success, latency_ms

        return False, latency_ms
