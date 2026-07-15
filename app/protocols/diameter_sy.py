"""Diameter Sy protocol simulation over HTTP (3GPP TS 29.219).

Simulates Sy Spending-Limit-Request (SLR) messages as HTTP REST calls
for policy spending limit coordination between PCRF and OCS.
"""

import time
import uuid
from typing import Tuple

from .base import BaseProtocol


class DiameterSyProtocol(BaseProtocol):
    """Diameter Sy protocol client (HTTP simulation).

    Simulates Spending-Limit-Request (SLR) operations:
    - SLR Initial (Subscribe): Subscribe to spending limit notifications
    - SLR Intermediate (Update): Update subscription or query status
    - SLR Final (Unsubscribe): Remove spending limit subscription
    """

    # SL-Request-Type values
    INITIAL_REQUEST = 0  # Subscribe
    INTERMEDIATE_REQUEST = 1  # Update/Query
    FINAL_REQUEST = 2  # Unsubscribe

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
        self._origin_host: str = (subscriber or {}).get("origin_host", "pcrf01.epc.mnc001.mcc001.3gppnetwork.org")
        self._origin_realm: str = (subscriber or {}).get("origin_realm", "epc.mnc001.mcc001.3gppnetwork.org")
        self._destination_host: str = (subscriber or {}).get("destination_host", "ocs01.epc.mnc001.mcc001.3gppnetwork.org")
        self._destination_realm: str = (subscriber or {}).get("destination_realm", "epc.mnc001.mcc001.3gppnetwork.org")
        self._policy_counter_ids: list = (subscriber or {}).get("policy_counter_ids", [
            "PolicyCounter-1",
            "PolicyCounter-2",
            "PolicyCounter-Accumulated",
        ])

    def _generate_session_id(self) -> str:
        """Generate a Diameter-compliant Session-Id."""
        timestamp = int(time.time())
        unique = uuid.uuid4().hex[:8]
        return f"{self._origin_host};{timestamp};{unique}"

    def _build_subscription_id(self) -> list:
        """Build Subscription-Id AVP."""
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

    def _build_slr(self, sl_request_type: int) -> dict:
        """Build a Spending-Limit-Request message as JSON AVPs."""
        slr = {
            "Session-Id": self.session_id,
            "Origin-Host": self._origin_host,
            "Origin-Realm": self._origin_realm,
            "Destination-Host": self._destination_host,
            "Destination-Realm": self._destination_realm,
            "Auth-Application-Id": 16777302,  # Sy application ID
            "SL-Request-Type": sl_request_type,
            "Subscription-Id": self._build_subscription_id(),
            "Policy-Counter-Identifier": self._policy_counter_ids,
        }

        # Add additional AVPs for subscribe/update
        if sl_request_type in (self.INITIAL_REQUEST, self.INTERMEDIATE_REQUEST):
            slr["Policy-Counter-Status-Report"] = [
                {
                    "Policy-Counter-Identifier": counter_id,
                    "Policy-Counter-Status": "active",
                    "Pending-Policy-Counter-Information": {
                        "Policy-Counter-Identifier": counter_id,
                        "Policy-Counter-Change-Trigger": "USAGE_THRESHOLD_REACHED",
                    },
                }
                for counter_id in self._policy_counter_ids
            ]

        return slr

    async def create_session(self) -> Tuple[bool, float]:
        """Send SLR Initial (Subscribe to spending limit notifications)."""
        self.session_id = self._generate_session_id()

        payload = self._build_slr(self.INITIAL_REQUEST)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/sy/slr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Spending-Limit-Request",
                "X-SL-Request-Type": "Initial",
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
        """Send SLR Intermediate (Update/query spending limit status)."""
        if not self.session_id:
            return False, 0.0

        payload = self._build_slr(self.INTERMEDIATE_REQUEST)
        # Add sequence-specific query information
        payload["SL-Request-Number"] = sequence
        payload["Policy-Counter-Status-Report"] = [
            {
                "Policy-Counter-Identifier": counter_id,
                "Policy-Counter-Status": "active",
                "Accumulated-Usage": {
                    "CC-Total-Octets": sequence * 5242880,
                    "CC-Input-Octets": sequence * 2621440,
                    "CC-Output-Octets": sequence * 2621440,
                },
            }
            for counter_id in self._policy_counter_ids
        ]

        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/sy/slr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Spending-Limit-Request",
                "X-SL-Request-Type": "Intermediate",
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
        """Send SLR Final (Unsubscribe from spending limit notifications)."""
        if not self.session_id:
            return False, 0.0

        payload = self._build_slr(self.FINAL_REQUEST)
        response, latency_ms = await self._timed_request(
            "POST",
            "/diameter/sy/slr",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Diameter-Command": "Spending-Limit-Request",
                "X-SL-Request-Type": "Final",
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
