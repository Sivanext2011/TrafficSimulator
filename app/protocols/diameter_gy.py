"""Diameter Gy protocol simulation over HTTP (3GPP TS 32.299).

Simulates Gy Credit-Control (CCR/CCA) messages as HTTP REST calls
with proper AVP structures represented as JSON.
"""

import time
import uuid
from typing import Tuple

from .base import BaseProtocol


class DiameterGyProtocol(BaseProtocol):
    """Diameter Gy protocol client (HTTP simulation).

    Simulates Credit-Control-Request (CCR) Initial/Update/Terminate
    for PS (Packet-Switched) online charging:
    - CCR-I (CC-Request-Type=1): Initial request
    - CCR-U (CC-Request-Type=2): Update request
    - CCR-T (CC-Request-Type=3): Terminate request
    """

    # CC-Request-Type values
    INITIAL_REQUEST = 1
    UPDATE_REQUEST = 2
    TERMINATION_REQUEST = 3

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
        self._origin_host: str = (subscriber or {}).get("origin_host", "smf01.epc.mnc001.mcc001.3gppnetwork.org")
        self._origin_realm: str = (subscriber or {}).get("origin_realm", "epc.mnc001.mcc001.3gppnetwork.org")
        self._destination_host: str = (subscriber or {}).get("destination_host", "ocs01.epc.mnc001.mcc001.3gppnetwork.org")
        self._destination_realm: str = (subscriber or {}).get("destination_realm", "epc.mnc001.mcc001.3gppnetwork.org")

    def _generate_session_id(self) -> str:
        """Generate a Diameter-compliant Session-Id AVP value."""
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
        ]

    def _build_service_information(self) -> dict:
        """Build Service-Information AVP with PS-Information."""
        return {
            "PS-Information": {
                "3GPP-Charging-Id": int(uuid.uuid4().int % 4294967295),
                "3GPP-PDP-Type": 0,  # IPv4
                "PDP-Address": self.subscriber.get("ip_address", "10.45.0.2"),
                "SGSN-Address": self.subscriber.get("sgsn_address", "10.0.1.1"),
                "GGSN-Address": self.subscriber.get("ggsn_address", "10.0.2.1"),
                "Called-Station-Id": self.subscriber.get("dnn", "internet"),
                "3GPP-IMSI-MCC-MNC": f"{self.subscriber.get('mcc', '001')}{self.subscriber.get('mnc', '01')}",
                "3GPP-GGSN-MCC-MNC": f"{self.subscriber.get('mcc', '001')}{self.subscriber.get('mnc', '01')}",
                "3GPP-SGSN-MCC-MNC": f"{self.subscriber.get('mcc', '001')}{self.subscriber.get('mnc', '01')}",
                "3GPP-User-Location-Info": self.subscriber.get("uli", "130184000100000001"),
                "3GPP-RAT-Type": self.subscriber.get("rat_type", "06"),  # EUTRAN
                "3GPP-Selection-Mode": "0",
                "Serving-Node-Type": "PGWC",
                "PDN-Connection-Charging-ID": int(uuid.uuid4().int % 4294967295),
            }
        }

    def _build_ccr(self, cc_request_type: int, used_units: dict | None = None) -> dict:
        """Build a full Credit-Control-Request message as JSON AVPs."""
        ccr = {
            "Session-Id": self.session_id,
            "Origin-Host": self._origin_host,
            "Origin-Realm": self._origin_realm,
            "Destination-Host": self._destination_host,
            "Destination-Realm": self._destination_realm,
            "Auth-Application-Id": 4,  # Diameter Credit-Control
            "Service-Context-Id": "32251@3gpp.org",
            "CC-Request-Type": cc_request_type,
            "CC-Request-Number": self._cc_request_number,
            "Event-Timestamp": int(time.time()),
            "Subscription-Id": self._build_subscription_id(),
            "Multiple-Services-Indicator": 1,
            "Multiple-Services-Credit-Control": [
                {
                    "Rating-Group": self.subscriber.get("rating_group", 100),
                    "Service-Identifier": self.subscriber.get("service_id", 1),
                    **(
                        {
                            "Requested-Service-Unit": {
                                "CC-Total-Octets": 10485760,
                                "CC-Input-Octets": 5242880,
                                "CC-Output-Octets": 5242880,
                            }
                        }
                        if cc_request_type != self.TERMINATION_REQUEST
                        else {}
                    ),
                    **(
                        {
                            "Used-Service-Unit": {
                                "CC-Total-Octets": used_units.get("total", 2097152),
                                "CC-Input-Octets": used_units.get("input", 1048576),
                                "CC-Output-Octets": used_units.get("output", 1048576),
                                "CC-Time": used_units.get("time", 60),
                            }
                        }
                        if used_units
                        else {}
                    ),
                }
            ],
            "Service-Information": self._build_service_information(),
            "User-Equipment-Info": {
                "User-Equipment-Info-Type": 0,  # IMEISV
                "User-Equipment-Info-Value": self.subscriber.get("imei", "1234567890123456"),
            },
        }
        return ccr

    async def create_session(self) -> Tuple[bool, float]:
        """Send CCR-Initial (CC-Request-Type=1)."""
        self.session_id = self._generate_session_id()
        self._cc_request_number = 0

        payload = self._build_ccr(self.INITIAL_REQUEST)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/gy/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Initial",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code in (200, 201):
            body = response.json()
            result_code = body.get("Result-Code", 0)
            return result_code == 2001, latency_ms  # DIAMETER_SUCCESS

        return False, latency_ms

    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Send CCR-Update (CC-Request-Type=2)."""
        if not self.session_id:
            return False, 0.0

        self._cc_request_number = sequence

        used_units = {
            "total": sequence * 1048576,
            "input": sequence * 524288,
            "output": sequence * 524288,
            "time": sequence * 30,
        }

        payload = self._build_ccr(self.UPDATE_REQUEST, used_units=used_units)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/gy/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Update",
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
        """Send CCR-Terminate (CC-Request-Type=3)."""
        if not self.session_id:
            return False, 0.0

        self._cc_request_number += 1

        used_units = {
            "total": 2097152,
            "input": 1048576,
            "output": 1048576,
            "time": 120,
        }

        payload = self._build_ccr(self.TERMINATION_REQUEST, used_units=used_units)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/gy/ccr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Credit-Control-Request",
                "X-CC-Request-Type": "Terminate",
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
