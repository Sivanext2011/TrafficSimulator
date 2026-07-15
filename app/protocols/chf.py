"""5G CHF protocol implementation - Nchf_ConvergedCharging v3 (3GPP TS 32.291)."""

import time
import uuid
from typing import Tuple

from .base import BaseProtocol


class ChfProtocol(BaseProtocol):
    """Nchf_ConvergedCharging v3 protocol client.

    Implements the 3GPP converged charging interface:
    - POST /nchf-convergedcharging/v3/chargingData (Initial)
    - POST /nchf-convergedcharging/v3/chargingData/{ref}/update
    - POST /nchf-convergedcharging/v3/chargingData/{ref}/release
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
        **kwargs,
    ):
        super().__init__(fqdn, port, base_path, cert_path, key_path, ca_path, subscriber, **kwargs)
        self.charging_data_ref: str | None = None
        self._invocation_sequence_number: int = 0

    def _build_create_payload(self) -> dict:
        """Build the ChargingDataRequest payload for session creation (Initial)."""
        self._invocation_sequence_number = 0
        return {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '001010000000001')}"),
            "nfConsumerIdentification": {
                "nfName": "smf-01",
                "nfIPv4Address": "10.0.0.1",
                "nfPLMNID": {
                    "mcc": self.subscriber.get("mcc", "001"),
                    "mnc": self.subscriber.get("mnc", "01"),
                },
            },
            "invocationTimeStamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "invocationSequenceNumber": self._invocation_sequence_number,
            "tenantIdentifier": self.subscriber.get("tenant_id", "default"),
            "multipleUnitUsage": [
                {
                    "ratingGroup": 100,
                    "requestedUnit": {
                        "totalVolume": 0,
                        "uplinkVolume": 0,
                        "downlinkVolume": 0,
                    },
                }
            ],
            "pDUSessionChargingInformation": {
                "chargingId": int(uuid.uuid4().int % 4294967295),
                "userInformation": {
                    "servedGPSI": self.subscriber.get("gpsi", f"msisdn-{self.subscriber.get('msisdn', '12125551234')}"),
                    "servedPEI": self.subscriber.get("pei", "imeisv-1234567890123456"),
                },
                "userLocationinfo": {
                    "eutraLocation": {
                        "tai": {
                            "plmnId": {
                                "mcc": self.subscriber.get("mcc", "001"),
                                "mnc": self.subscriber.get("mnc", "01"),
                            },
                            "tac": "000001",
                        },
                        "ecgi": {
                            "plmnId": {
                                "mcc": self.subscriber.get("mcc", "001"),
                                "mnc": self.subscriber.get("mnc", "01"),
                            },
                            "eutraCellId": "0000001",
                        },
                    }
                },
                "pduSessionInformation": {
                    "networkSlicingInfo": {
                        "sNSSAI": {
                            "sst": self.subscriber.get("sst", 1),
                            "sd": self.subscriber.get("sd", "000001"),
                        }
                    },
                    "pduSessionID": 1,
                    "pduType": "IPV4",
                    "sscMode": "SSC_MODE_1",
                    "servingNodeID": [{
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "amfId": "cafe00",
                    }],
                    "dnnId": self.subscriber.get("dnn", "internet"),
                },
            },
        }

    def _build_update_payload(self, sequence: int) -> dict:
        """Build the ChargingDataRequest payload for session update."""
        self._invocation_sequence_number = sequence
        return {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '001010000000001')}"),
            "invocationTimeStamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "invocationSequenceNumber": self._invocation_sequence_number,
            "multipleUnitUsage": [
                {
                    "ratingGroup": 100,
                    "usedUnitContainer": [
                        {
                            "localSequenceNumber": sequence,
                            "totalVolume": sequence * 1048576,
                            "uplinkVolume": sequence * 524288,
                            "downlinkVolume": sequence * 524288,
                        }
                    ],
                    "requestedUnit": {
                        "totalVolume": 10485760,
                        "uplinkVolume": 5242880,
                        "downlinkVolume": 5242880,
                    },
                }
            ],
            "pDUSessionChargingInformation": {
                "chargingId": int(uuid.uuid4().int % 4294967295),
                "pduSessionInformation": {
                    "pduSessionID": 1,
                    "dnnId": self.subscriber.get("dnn", "internet"),
                },
            },
        }

    def _build_release_payload(self) -> dict:
        """Build the ChargingDataRequest payload for session release."""
        self._invocation_sequence_number += 1
        return {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '001010000000001')}"),
            "invocationTimeStamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "invocationSequenceNumber": self._invocation_sequence_number,
            "multipleUnitUsage": [
                {
                    "ratingGroup": 100,
                    "usedUnitContainer": [
                        {
                            "localSequenceNumber": self._invocation_sequence_number,
                            "totalVolume": 2097152,
                            "uplinkVolume": 1048576,
                            "downlinkVolume": 1048576,
                        }
                    ],
                }
            ],
        }

    async def create_session(self) -> Tuple[bool, float]:
        """Send Initial charging request (create chargingData).

        Extracts chargingDataRef from the Location header of a 201 response.
        """
        payload = self._build_create_payload()
        response, latency_ms = await self._timed_request(
            "POST",
            "/nchf-convergedcharging/v3/chargingdata",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 201:
            location = response.headers.get("Location", "")
            # Extract chargingDataRef from Location header
            # Location: /nchf-convergedcharging/v3/chargingData/{chargingDataRef}
            if location:
                self.charging_data_ref = location.rstrip("/").split("/")[-1]
            else:
                # Fallback: try response body
                body = response.json()
                self.charging_data_ref = body.get("chargingDataRef", self._generate_id())
            return True, latency_ms

        return False, latency_ms

    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Send Update charging request."""
        if not self.charging_data_ref:
            return False, 0.0

        payload = self._build_update_payload(sequence)
        response, latency_ms = await self._timed_request(
            "POST",
            f"/nchf-convergedcharging/v3/chargingdata/{self.charging_data_ref}/update",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        return response.status_code == 200, latency_ms

    async def release_session(self) -> Tuple[bool, float]:
        """Send Release charging request (terminate session)."""
        if not self.charging_data_ref:
            return False, 0.0

        payload = self._build_release_payload()
        response, latency_ms = await self._timed_request(
            "POST",
            f"/nchf-convergedcharging/v3/chargingdata/{self.charging_data_ref}/release",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        success = response.status_code == 204
        if success:
            self.charging_data_ref = None
        return success, latency_ms
