"""5G CHF protocol implementation - Nchf_ConvergedCharging v3 (3GPP TS 32.291).

Based on real SMF pcap analysis - implements full pDUSessionChargingInformation,
realistic quota tracking, and proper usage reporting.
"""

import random
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
        self._charging_id: int = int(uuid.uuid4().int % 4294967295)
        self._session_start_time: str | None = None
        self._last_usage_time: str | None = None
        self._local_sequence_number: int = 0
        # Quota tracking
        self._granted_total_volume: int = 0
        self._reported_total_volume: int = 0
        self._granted_quota_threshold: int = 0
        # NF identity
        self._nf_instance_id: str = str(uuid.uuid4())
        self._upf_id: str = str(uuid.uuid4())
        # UE address assigned at session start
        self._ue_ipv4: str = f"10.{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(2, 254)}"

    def _get_rating_group(self) -> int:
        """Get rating group from subscriber config."""
        return self.subscriber.get("rating_group", 1000)

    def _get_mcc(self) -> str:
        return self.subscriber.get("mcc", "466")

    def _get_mnc(self) -> str:
        return self.subscriber.get("mnc", "92")

    def _get_current_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _get_nf_fqdn(self) -> str:
        """Generate realistic SMF FQDN."""
        mcc = self._get_mcc()
        mnc = self._get_mnc()
        return f"smf01.5gc.mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"

    def _get_amf_fqdn(self) -> str:
        """Generate realistic AMF FQDN."""
        mcc = self._get_mcc()
        mnc = self._get_mnc()
        return f"amf01.amf.5gc.mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"

    def _build_nf_consumer_identification(self) -> dict:
        """Build full nfConsumerIdentification matching real SMF."""
        return {
            "nFFqdn": self._get_nf_fqdn(),
            "nFIPv4Address": self.subscriber.get("smf_ip", "192.168.0.1"),
            "nFName": self._nf_instance_id,
            "nFPLMNID": {
                "mcc": self._get_mcc(),
                "mnc": self._get_mnc(),
            },
            "nodeFunctionality": "SMF",
        }

    def _build_pdu_session_charging_info(self, include_start_time: bool = False, include_stop_time: bool = False) -> dict:
        """Build full pDUSessionChargingInformation matching real SMF pcap.

        Args:
            include_start_time: Include startTime (for Create).
            include_stop_time: Include stopTime and sessionStopIndicator (for Release).
        """
        mcc = self._get_mcc()
        mnc = self._get_mnc()
        dnn = self.subscriber.get("dnn", "internet")
        sst = self.subscriber.get("sst", 1)
        sd = self.subscriber.get("sd", "000001")

        pdu_session_info = {
            "authorizedQoSInformation": {
                "5qi": self.subscriber.get("5qi", 9),
                "arp": {
                    "preemptCap": "NOT_PREEMPT",
                    "preemptVuln": "PREEMPTABLE",
                    "priorityLevel": self.subscriber.get("arp_priority", 6),
                },
            },
            "authorizedSessionAMBR": {
                "downlink": self.subscriber.get("ambr_dl", "10 Gbps"),
                "uplink": self.subscriber.get("ambr_ul", "10 Gbps"),
            },
            "chargingCharacteristics": self.subscriber.get("charging_characteristics", "0094"),
            "chargingCharacteristicsSelectionMode": "HOME_DEFAULT",
            "dnnId": dnn,
            "hPlmnId": {
                "mcc": mcc,
                "mnc": mnc,
            },
            "networkSlicingInfo": {
                "sNSSAI": {
                    "sst": sst,
                    "sd": sd,
                }
            },
            "pduAddress": {
                "iPv4dynamicAddressFlag": True,
                "pduIPv4Address": self._ue_ipv4,
            },
            "pduSessionID": 1,
            "pduType": "IPV4",
            "ratType": "NR",
            "servingCNPlmnId": {
                "mcc": mcc,
                "mnc": mnc,
            },
            "servingNetworkFunctionID": {
                "aMFId": "80000C",
                "servingNetworkFunctionInformation": {
                    "nFFqdn": self._get_amf_fqdn(),
                    "nFIPv4Address": self.subscriber.get("amf_ip", "10.156.129.238"),
                    "nFName": str(uuid.uuid4()),
                    "nFPLMNID": {
                        "mcc": mcc,
                        "mnc": mnc,
                    },
                    "nodeFunctionality": "AMF",
                },
            },
            "sscMode": "SSC_MODE_1",
            "subscribedQoSInformation": {
                "5qi": self.subscriber.get("5qi", 9),
                "arp": {
                    "preemptCap": "NOT_PREEMPT",
                    "preemptVuln": "PREEMPTABLE",
                    "priorityLevel": self.subscriber.get("arp_priority", 6),
                },
            },
            "subscribedSessionAMBR": {
                "downlink": self.subscriber.get("ambr_dl", "10 Gbps"),
                "uplink": self.subscriber.get("ambr_ul", "10 Gbps"),
            },
        }

        if include_start_time:
            pdu_session_info["startTime"] = self._session_start_time

        if include_stop_time:
            pdu_session_info["stopTime"] = self._get_current_timestamp()
            pdu_session_info["sessionStopIndicator"] = True

        result = {
            "chargingId": self._charging_id,
            "pduSessionInformation": pdu_session_info,
            "uetimeZone": self.subscriber.get("ue_timezone", "+08:00+0"),
            "userInformation": {
                "servedGPSI": self.subscriber.get("gpsi", f"msisdn-{self.subscriber.get('msisdn', '886988414918')}"),
                "servedPEI": self.subscriber.get("pei", f"imeisv-{self.subscriber.get('imei', '3547414504519910')}"),
                "unauthenticatedFlag": False,
            },
            "userLocationinfo": {
                "nrLocation": {
                    "ncgi": {
                        "nrCellId": self.subscriber.get("nr_cell_id", "000000001"),
                        "plmnId": {
                            "mcc": mcc,
                            "mnc": mnc,
                        },
                    },
                    "tai": {
                        "plmnId": {
                            "mcc": mcc,
                            "mnc": mnc,
                        },
                        "tac": self.subscriber.get("tac", "000001"),
                    },
                }
            },
        }

        return result

    def _build_create_payload(self) -> dict:
        """Build the ChargingDataRequest payload for session creation (Initial).

        Matches real SMF behavior:
        - Full nfConsumerIdentification with FQDN
        - notifyUri for re-authorization
        - Complete pDUSessionChargingInformation with QoS, AMBR, pduAddress, etc.
        - No multipleUnitUsage (Create doesn't request quota in online-only)
        """
        self._invocation_sequence_number = 0
        self._session_start_time = self._get_current_timestamp()
        self._local_sequence_number = 0
        self._reported_total_volume = 0
        self._granted_total_volume = 0

        payload = {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '466924300000018')}"),
            "nfConsumerIdentification": self._build_nf_consumer_identification(),
            "invocationTimeStamp": self._session_start_time,
            "invocationSequenceNumber": self._invocation_sequence_number,
            "notifyUri": self.subscriber.get(
                "notify_uri",
                f"http://{self.subscriber.get('smf_ip', '192.168.0.1')}:9090/notifications/chf/convergedcharging/v3/referenceid/{random.randint(1000000000, 9999999999)}",
            ),
            "pDUSessionChargingInformation": self._build_pdu_session_charging_info(include_start_time=True),
        }

        return payload

    def _build_update_payload(self, sequence: int) -> dict:
        """Build the ChargingDataRequest payload for session update.

        Matches real SMF behavior:
        - First update (seq 1): Only requestedUnit, no usedUnitContainer
        - Subsequent updates: requestedUnit + usedUnitContainer with actual consumption
        - Includes pDUContainerInformation with timeofFirstUsage/timeofLastUsage
        - Reports usage triggered by QUOTA_THRESHOLD
        """
        self._invocation_sequence_number = sequence
        current_time = self._get_current_timestamp()
        rating_group = self._get_rating_group()

        multiple_unit_usage_entry = {
            "ratingGroup": rating_group,
            "requestedUnit": {},  # Empty object = request quota (real SMF behavior)
        }

        # First update after Create: just request quota, no usage to report yet
        if sequence == 1:
            pass  # Only requestedUnit, no usedUnitContainer
        else:
            # Subsequent updates: report usage consumed since last grant
            # Simulate consuming ~80-95% of granted quota (realistic behavior)
            if self._granted_total_volume > 0:
                consumption_ratio = random.uniform(0.80, 0.95)
                consumed = int(self._granted_total_volume * consumption_ratio)
            else:
                # Fallback: simulate some realistic data usage (500KB - 5MB)
                consumed = random.randint(500000, 5000000)

            # Split into uplink (~10-15%) and downlink (~85-90%)
            uplink_ratio = random.uniform(0.08, 0.15)
            uplink_volume = int(consumed * uplink_ratio)
            downlink_volume = consumed - uplink_volume

            self._local_sequence_number += 1
            self._reported_total_volume += consumed

            first_usage_time = self._last_usage_time or self._session_start_time
            last_usage_time = current_time

            multiple_unit_usage_entry["usedUnitContainer"] = [
                {
                    "totalVolume": consumed,
                    "uplinkVolume": uplink_volume,
                    "downlinkVolume": downlink_volume,
                    "localSequenceNumber": self._local_sequence_number,
                    "quotaManagementIndicator": "ONLINE_CHARGING",
                    "triggerTimestamp": current_time,
                    "triggers": [
                        {
                            "triggerCategory": "IMMEDIATE_REPORT",
                            "triggerType": "QUOTA_THRESHOLD",
                        }
                    ],
                    "pDUContainerInformation": {
                        "timeofFirstUsage": first_usage_time,
                        "timeofLastUsage": last_usage_time,
                    },
                }
            ]

            # Also include uPFID in multipleUnitUsage
            multiple_unit_usage_entry["uPFID"] = self._upf_id

        self._last_usage_time = current_time

        payload = {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '466924300000018')}"),
            "nfConsumerIdentification": self._build_nf_consumer_identification(),
            "invocationTimeStamp": current_time,
            "invocationSequenceNumber": self._invocation_sequence_number,
            "notifyUri": self.subscriber.get(
                "notify_uri",
                f"http://{self.subscriber.get('smf_ip', '192.168.0.1')}:9090/notifications/chf/convergedcharging/v3/referenceid/{random.randint(1000000000, 9999999999)}",
            ),
            "multipleUnitUsage": [multiple_unit_usage_entry],
            "pDUSessionChargingInformation": self._build_pdu_session_charging_info(),
        }

        return payload

    def _build_release_payload(self) -> dict:
        """Build the ChargingDataRequest payload for session release.

        Matches real SMF behavior:
        - Reports remaining unreported usage since last update
        - Includes FINAL trigger type
        - Includes pDUContainerInformation
        - Includes sessionStopIndicator and stopTime
        """
        self._invocation_sequence_number += 1
        current_time = self._get_current_timestamp()
        rating_group = self._get_rating_group()

        # Calculate remaining unreported usage
        # In a real scenario, some data may have been consumed since last CCR-U
        if self._granted_total_volume > 0:
            # Report remaining consumption (~5-20% of last grant, or whatever wasn't reported)
            remaining_unreported = int(self._granted_total_volume * random.uniform(0.05, 0.20))
        else:
            # Small final usage
            remaining_unreported = random.randint(1000, 100000)

        uplink_ratio = random.uniform(0.08, 0.15)
        uplink_volume = int(remaining_unreported * uplink_ratio)
        downlink_volume = remaining_unreported - uplink_volume

        self._local_sequence_number += 1

        first_usage_time = self._last_usage_time or self._session_start_time
        last_usage_time = current_time

        payload = {
            "subscriberIdentifier": self.subscriber.get("supi", f"imsi-{self.subscriber.get('imsi', '466924300000018')}"),
            "nfConsumerIdentification": self._build_nf_consumer_identification(),
            "invocationTimeStamp": current_time,
            "invocationSequenceNumber": self._invocation_sequence_number,
            "multipleUnitUsage": [
                {
                    "ratingGroup": rating_group,
                    "usedUnitContainer": [
                        {
                            "totalVolume": remaining_unreported,
                            "uplinkVolume": uplink_volume,
                            "downlinkVolume": downlink_volume,
                            "localSequenceNumber": self._local_sequence_number,
                            "quotaManagementIndicator": "ONLINE_CHARGING",
                            "triggerTimestamp": current_time,
                            "triggers": [
                                {
                                    "triggerCategory": "IMMEDIATE_REPORT",
                                    "triggerType": "FINAL",
                                }
                            ],
                            "pDUContainerInformation": {
                                "timeofFirstUsage": first_usage_time,
                                "timeofLastUsage": last_usage_time,
                            },
                        }
                    ],
                    "uPFID": self._upf_id,
                }
            ],
            "pDUSessionChargingInformation": self._build_pdu_session_charging_info(include_stop_time=True),
            "triggers": [
                {
                    "triggerCategory": "IMMEDIATE_REPORT",
                    "triggerType": "FINAL",
                }
            ],
        }

        return payload

    def _parse_granted_quota(self, response_body: dict) -> None:
        """Parse the CHA response to track granted quota for realistic usage reporting."""
        try:
            multi_unit_info = response_body.get("multipleUnitInformation", [])
            for unit_info in multi_unit_info:
                granted = unit_info.get("grantedUnit", {})
                self._granted_total_volume = granted.get("totalVolume", 0)
                threshold = unit_info.get("volumeQuotaThreshold", 0)
                if threshold:
                    self._granted_quota_threshold = threshold
        except (KeyError, TypeError, AttributeError):
            pass

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
            if location:
                self.charging_data_ref = location.rstrip("/").split("/")[-1]
            else:
                # Fallback: try response body
                body = response.json()
                self.charging_data_ref = body.get("chargingDataRef", self._generate_id())

            # Parse response for triggers and initial session info
            try:
                body = response.json()
                self._parse_granted_quota(body)
            except Exception:
                pass

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

        if response.status_code == 200:
            # Parse granted quota from response for next update's usage reporting
            try:
                body = response.json()
                self._parse_granted_quota(body)
            except Exception:
                pass
            return True, latency_ms

        return False, latency_ms

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
