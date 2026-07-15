"""SCAPv2 (Service Capability Application Protocol v2) implementation.

Simulates SCAPv2 operations for service capability interactions
including account management and service unit operations.
"""

import time
import uuid
from typing import Tuple

from .base import BaseProtocol


class ScapV2Protocol(BaseProtocol):
    """SCAPv2 protocol client.

    Implements Service Capability operations:
    - Create: Establish a service session with account reservation
    - Query: Check account status and available service units
    - Modify: Update service units or account parameters
    - Release: Terminate session and finalize account charges
    """

    # Operation types
    OP_CREATE = "Create"
    OP_QUERY = "Query"
    OP_MODIFY = "Modify"
    OP_RELEASE = "Release"

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
        self._sequence_number: int = 0
        self._transaction_id: str | None = None

    def _generate_transaction_id(self) -> str:
        """Generate a unique transaction ID for SCAPv2."""
        return f"SCAP-{int(time.time())}-{uuid.uuid4().hex[:12]}"

    def _build_subscriber_info(self) -> dict:
        """Build subscriber identification block."""
        return {
            "subscriberId": {
                "msisdn": self.subscriber.get("msisdn", "12125551234"),
                "imsi": self.subscriber.get("imsi", "001010000000001"),
                "accountId": self.subscriber.get("account_id", f"ACCT-{self.subscriber.get('msisdn', '12125551234')}"),
            },
            "subscriberType": self.subscriber.get("subscriber_type", "postpaid"),
            "serviceProfile": self.subscriber.get("service_profile", "default"),
        }

    def _build_account_info(self) -> dict:
        """Build account information block."""
        return {
            "accountId": self.subscriber.get("account_id", f"ACCT-{self.subscriber.get('msisdn', '12125551234')}"),
            "accountType": self.subscriber.get("account_type", "individual"),
            "billingCycleDay": self.subscriber.get("billing_cycle_day", 1),
            "currency": self.subscriber.get("currency", "USD"),
            "creditLimit": self.subscriber.get("credit_limit", 100.00),
            "balanceInfo": {
                "mainBalance": self.subscriber.get("main_balance", 50.00),
                "reservedAmount": 0.0,
                "availableBalance": self.subscriber.get("main_balance", 50.00),
            },
        }

    def _build_service_units(self, operation: str, sequence: int = 0) -> dict:
        """Build service units block based on operation type."""
        if operation == self.OP_CREATE:
            return {
                "requestedUnits": {
                    "totalVolume": self.subscriber.get("requested_volume", 10485760),
                    "totalTime": self.subscriber.get("requested_time", 3600),
                    "serviceSpecificUnits": self.subscriber.get("requested_ssu", 100),
                },
                "ratingGroup": self.subscriber.get("rating_group", 100),
                "serviceId": self.subscriber.get("service_id", "DATA-DEFAULT"),
            }
        elif operation == self.OP_MODIFY:
            return {
                "usedUnits": {
                    "totalVolume": sequence * 1048576,
                    "totalTime": sequence * 300,
                    "serviceSpecificUnits": sequence * 10,
                },
                "requestedUnits": {
                    "totalVolume": 10485760,
                    "totalTime": 3600,
                    "serviceSpecificUnits": 100,
                },
                "ratingGroup": self.subscriber.get("rating_group", 100),
                "serviceId": self.subscriber.get("service_id", "DATA-DEFAULT"),
            }
        elif operation == self.OP_RELEASE:
            return {
                "usedUnits": {
                    "totalVolume": sequence * 1048576,
                    "totalTime": sequence * 300,
                    "serviceSpecificUnits": sequence * 10,
                },
                "ratingGroup": self.subscriber.get("rating_group", 100),
                "serviceId": self.subscriber.get("service_id", "DATA-DEFAULT"),
                "finalIndicator": True,
            }
        else:  # Query
            return {
                "ratingGroup": self.subscriber.get("rating_group", 100),
                "serviceId": self.subscriber.get("service_id", "DATA-DEFAULT"),
            }

    def _build_request(self, operation: str, sequence: int = 0) -> dict:
        """Build a complete SCAPv2 request payload."""
        self._transaction_id = self._generate_transaction_id()
        return {
            "header": {
                "version": "2.0",
                "messageType": "ServiceCapabilityRequest",
                "operationType": operation,
                "transactionId": self._transaction_id,
                "sessionId": self.session_id,
                "sequenceNumber": self._sequence_number,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "originHost": self.subscriber.get("origin_host", "pcf01.operator.com"),
                "destinationHost": self.subscriber.get("destination_host", "ocs01.operator.com"),
            },
            "subscriberInfo": self._build_subscriber_info(),
            "accountInfo": self._build_account_info(),
            "serviceUnits": self._build_service_units(operation, sequence),
            "serviceContext": {
                "serviceType": self.subscriber.get("service_type", "DATA"),
                "networkElement": self.subscriber.get("network_element", "PGW-01"),
                "accessPointName": self.subscriber.get("dnn", "internet"),
                "locationInfo": {
                    "cellId": self.subscriber.get("cell_id", "0000001"),
                    "lac": self.subscriber.get("lac", "0001"),
                    "mcc": self.subscriber.get("mcc", "001"),
                    "mnc": self.subscriber.get("mnc", "01"),
                },
            },
        }

    async def create_session(self) -> Tuple[bool, float]:
        """Create a SCAPv2 service session (reserve service units)."""
        self.session_id = f"SCAP-SESSION-{uuid.uuid4().hex[:16]}"
        self._sequence_number = 0

        payload = self._build_request(self.OP_CREATE)
        response, latency_ms = await self._timed_request(
            "POST",
            "/scapv2/service-capability",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-SCAP-Operation": self.OP_CREATE,
                "X-SCAP-Version": "2.0",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code in (200, 201):
            body = response.json()
            result_code = body.get("header", {}).get("resultCode", 0)
            # Store session ID from response if provided
            resp_session = body.get("header", {}).get("sessionId")
            if resp_session:
                self.session_id = resp_session
            return result_code in (0, 2001), latency_ms

        return False, latency_ms

    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Modify service session (report usage, request more units)."""
        if not self.session_id:
            return False, 0.0

        self._sequence_number = sequence

        payload = self._build_request(self.OP_MODIFY, sequence)
        response, latency_ms = await self._timed_request(
            "POST",
            "/scapv2/service-capability",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-SCAP-Operation": self.OP_MODIFY,
                "X-SCAP-Version": "2.0",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 200:
            body = response.json()
            result_code = body.get("header", {}).get("resultCode", 0)
            return result_code in (0, 2001), latency_ms

        return False, latency_ms

    async def release_session(self) -> Tuple[bool, float]:
        """Release SCAPv2 service session (finalize charges)."""
        if not self.session_id:
            return False, 0.0

        self._sequence_number += 1

        payload = self._build_request(self.OP_RELEASE, self._sequence_number)
        response, latency_ms = await self._timed_request(
            "POST",
            "/scapv2/service-capability",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-SCAP-Operation": self.OP_RELEASE,
                "X-SCAP-Version": "2.0",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 200:
            body = response.json()
            result_code = body.get("header", {}).get("resultCode", 0)
            success = result_code in (0, 2001)
            if success:
                self.session_id = None
            return success, latency_ms

        return False, latency_ms

    async def query_session(self) -> Tuple[bool, float]:
        """Query account/service status (additional SCAPv2 operation)."""
        if not self.session_id:
            return False, 0.0

        payload = self._build_request(self.OP_QUERY)
        response, latency_ms = await self._timed_request(
            "POST",
            "/scapv2/service-capability",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-SCAP-Operation": self.OP_QUERY,
                "X-SCAP-Version": "2.0",
            },
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 200:
            body = response.json()
            result_code = body.get("header", {}).get("resultCode", 0)
            return result_code in (0, 2001), latency_ms

        return False, latency_ms
