"""5G PCF protocol implementation - Npcf_SMPolicyControl v1 (3GPP TS 29.512)."""

import time
from typing import Tuple

from .base import BaseProtocol


class PcfProtocol(BaseProtocol):
    """Npcf_SMPolicyControl v1 protocol client.

    Implements the 3GPP SM Policy Control interface:
    - POST /npcf-smpolicycontrol/v1/sm-policies (Create)
    - POST /npcf-smpolicycontrol/v1/sm-policies/{id}/update
    - POST /npcf-smpolicycontrol/v1/sm-policies/{id}/delete
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
        self.sm_policy_id: str | None = None
        self._pdu_session_id: int = 1

    def _build_create_payload(self) -> dict:
        """Build SmPolicyContextData payload for SM policy creation."""
        return {
            "supi": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '001010000000001')}"),
            "gpsi": self.subscriber.get("gpsi", f"msisdn-{self.subscriber.get('msisdn', '12125551234')}"),
            "pduSessionId": self._pdu_session_id,
            "pduSessionType": "IPV4",
            "dnn": self.subscriber.get("dnn", "internet"),
            "notificationUri": f"https://smf.example.com/npcf-smpolicycontrol/v1/sm-policies/notify",
            "sliceInfo": {
                "sst": self.subscriber.get("sst", 1),
                "sd": self.subscriber.get("sd", "000001"),
            },
            "servingNetwork": {
                "mcc": self.subscriber.get("mcc", "001"),
                "mnc": self.subscriber.get("mnc", "01"),
            },
            "userLocationInfo": {
                "nrLocation": {
                    "tai": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "tac": "000001",
                    },
                    "ncgi": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "nrCellId": "000000001",
                    },
                }
            },
            "ipv4Address": self.subscriber.get("ip_address", "10.45.0.2"),
            "ratType": "NR",
            "accessType": "3GPP_ACCESS",
            "subscriberInfo": {
                "subscriberType": self.subscriber.get("subscriber_type", "postpaid"),
                "subscriberGroup": self.subscriber.get("subscriber_group", "default"),
            },
            "pduSessionInfo": {
                "pduSessionId": self._pdu_session_id,
                "sessionAmbr": {
                    "uplink": self.subscriber.get("ambr_ul", "100 Mbps"),
                    "downlink": self.subscriber.get("ambr_dl", "200 Mbps"),
                },
                "defaultQosInformation": {
                    "5qi": self.subscriber.get("default_5qi", 9),
                    "arp": {
                        "priorityLevel": 8,
                        "preemptCap": "NOT_PREEMPT",
                        "preemptVuln": "PREEMPTABLE",
                    },
                },
            },
        }

    def _build_update_payload(self, sequence: int) -> dict:
        """Build SmPolicyUpdateContextData payload for policy update."""
        return {
            "repPolicyCtrlReqTriggers": ["LOC_CH"],
            "userLocationInfo": {
                "nrLocation": {
                    "tai": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "tac": f"{sequence:06d}",
                    },
                    "ncgi": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "nrCellId": f"{sequence:09d}",
                    },
                }
            },
            "accessType": "3GPP_ACCESS",
            "ratType": "NR",
            "servingNetwork": {
                "mcc": self.subscriber.get("mcc", "001"),
                "mnc": self.subscriber.get("mnc", "01"),
            },
            "traceReq": None,
            "ipv4Address": self.subscriber.get("ip_address", "10.45.0.2"),
            "pduSessionInfo": {
                "pduSessionId": self._pdu_session_id,
                "sessionAmbr": {
                    "uplink": self.subscriber.get("ambr_ul", "100 Mbps"),
                    "downlink": self.subscriber.get("ambr_dl", "200 Mbps"),
                },
            },
        }

    def _build_delete_payload(self) -> dict:
        """Build SmPolicyDeleteData payload for policy termination."""
        return {
            "userLocationInfo": {
                "nrLocation": {
                    "tai": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "tac": "000001",
                    },
                    "ncgi": {
                        "plmnId": {
                            "mcc": self.subscriber.get("mcc", "001"),
                            "mnc": self.subscriber.get("mnc", "01"),
                        },
                        "nrCellId": "000000001",
                    },
                }
            },
            "accu_usage_report": None,
            "pduSessionRelCause": "PS_TO_CS_HO",
        }

    async def create_session(self) -> Tuple[bool, float]:
        """Create SM Policy association.

        Extracts sm_policy_id from the Location header of a 201 response.
        """
        payload = self._build_create_payload()
        response, latency_ms = await self._timed_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        if response.status_code == 201:
            location = response.headers.get("Location", "")
            if location:
                self.sm_policy_id = location.rstrip("/").split("/")[-1]
            else:
                body = response.json()
                self.sm_policy_id = body.get("smPolicyId", self._generate_id())
            return True, latency_ms

        return False, latency_ms

    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Update SM Policy (e.g., location change trigger)."""
        if not self.sm_policy_id:
            return False, 0.0

        payload = self._build_update_payload(sequence)
        response, latency_ms = await self._timed_request(
            "POST",
            f"/npcf-smpolicycontrol/v1/sm-policies/{self.sm_policy_id}/update",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        return response.status_code == 200, latency_ms

    async def release_session(self) -> Tuple[bool, float]:
        """Delete SM Policy association."""
        if not self.sm_policy_id:
            return False, 0.0

        payload = self._build_delete_payload()
        response, latency_ms = await self._timed_request(
            "POST",
            f"/npcf-smpolicycontrol/v1/sm-policies/{self.sm_policy_id}/delete",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response is None:
            return False, latency_ms

        success = response.status_code == 204
        if success:
            self.sm_policy_id = None
        return success, latency_ms
