"""eN28 Nchf_SpendingLimitControl client (PCF role).

Implements:
- Subscribe: POST /nchf-spendinglimitcontrol/v1/subscriptions
- Unsubscribe: DELETE /nchf-spendinglimitcontrol/v1/subscriptions/{subscriptionId}

The simulator acts as PCF, subscribing to a real CHF/CHA for spending limit
notifications on configured policy counter IDs.
"""

import logging
import time
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


class SpendingLimitClient:
    """Client for Nchf_SpendingLimitControl Subscribe/Unsubscribe.

    Sends subscription requests to the real CHF and stores the subscription ID
    returned in the Location header for later unsubscribe.
    """

    def __init__(
        self,
        fqdn: str,
        port: int,
        base_path: str = "/nchf-spendinglimitcontrol/v1",
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        secure: bool = True,
        verify_ssl: bool = False,
    ):
        self.fqdn = fqdn
        self.port = port
        self.base_path = (base_path or "/nchf-spendinglimitcontrol/v1").rstrip("/")
        self.cert_path = cert_path
        self.key_path = key_path
        self.secure = secure
        self.verify_ssl = verify_ssl

        scheme = "https" if self.secure else "http"
        self._base_url = f"{scheme}://{self.fqdn}:{self.port}{self.base_path}"
        self._client: Optional[httpx.AsyncClient] = None
        self._subscription_id: Optional[str] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            kwargs = {
                "verify": False,
                "timeout": httpx.Timeout(30.0, connect=10.0),
            }
            if self.secure and self.cert_path and self.key_path:
                kwargs["cert"] = (self.cert_path, self.key_path)
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def subscribe(
        self,
        supi: str,
        gpsi: str,
        notif_uri: str,
        policy_counter_ids: List[str],
        initial_retrieval: bool = True,
        enable_en28: bool = False,
    ) -> Tuple[bool, float, Optional[dict]]:
        """Subscribe to spending limit notifications.

        Args:
            supi: Subscriber IMSI (e.g., "imsi-466924300000018")
            gpsi: Subscriber MSISDN (e.g., "msisdn-886988414918")
            notif_uri: Callback URL the CHF will POST notifications to
            policy_counter_ids: List of policy counter IDs to monitor
            initial_retrieval: Whether to retrieve current status on subscribe
            enable_en28: If True, include vendorSpecific-000193 (ERICSSON_SLC)
                         to request Policy Groups from Ericsson CHF

        Returns:
            (success, latency_ms, response_data)
            response_data includes initial SpendingLimitStatus if available
        """
        client = await self._get_client()
        url = f"{self._base_url}/subscriptions"

        payload: Dict = {
            "supi": supi,
            "gpsi": gpsi,
            "notifUri": notif_uri,
            "initialSpendingLimitRetrieval": initial_retrieval,
            "supportedFeatures": "0",
        }

        # Only include spendingLimitContext if counter IDs are specified
        # In E-N28 mode, policyCounterIds is not used (CHF returns all)
        if policy_counter_ids and not enable_en28:
            payload["spendingLimitContext"] = {
                "policyCounterIds": policy_counter_ids,
            }

        # E-N28 Ericsson extension: request Policy Groups via vendorSpecific-000193
        if enable_en28:
            payload["vendorSpecific-000193"] = {
                "slcFeatures": [
                    {
                        "featureName": "ERICSSON_SLC",
                        "featureVersion": "1.0.0",
                    }
                ]
            }

        logger.info(f">>> eN28 SUBSCRIBE: URL={url} {'[E-N28 mode]' if enable_en28 else '[standard N28]'}")
        logger.info(f">>> PAYLOAD: supi={supi}, counters={policy_counter_ids}, notifUri={notif_uri}, en28={enable_en28}")

        start = time.perf_counter()
        try:
            response = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            latency_ms = (time.perf_counter() - start) * 1000.0

            logger.info(f"<<< eN28 SUBSCRIBE RESPONSE: status={response.status_code}, latency={latency_ms:.1f}ms")
            logger.info(f"<<< HEADERS: {dict(response.headers)}")

            if response.status_code in (200, 201):
                # Extract subscription ID from Location header
                location = response.headers.get("location", "")
                if location:
                    self._subscription_id = location.rstrip("/").split("/")[-1]
                    logger.info(f"    Subscription ID: {self._subscription_id}")

                # Parse response body (may contain initial SpendingLimitStatus)
                response_data = {}
                if response.text:
                    try:
                        response_data = response.json()
                        logger.info(f"<<< BODY: {response.text[:1000]}")
                    except Exception:
                        pass

                return True, latency_ms, response_data
            else:
                logger.warning(f"    Subscribe failed: {response.status_code} - {response.text[:500]}")
                return False, latency_ms, None

        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000.0
            logger.error(f"eN28 subscribe error: {e}")
            return False, latency_ms, None

    async def unsubscribe(self) -> Tuple[bool, float]:
        """Unsubscribe from spending limit notifications.

        Uses the subscription ID obtained from the subscribe response.

        Returns:
            (success, latency_ms)
        """
        if not self._subscription_id:
            logger.warning("No subscription ID available — skipping unsubscribe")
            return False, 0.0

        client = await self._get_client()
        url = f"{self._base_url}/subscriptions/{self._subscription_id}"

        logger.info(f">>> eN28 UNSUBSCRIBE: URL={url}")

        start = time.perf_counter()
        try:
            response = await client.delete(url)
            latency_ms = (time.perf_counter() - start) * 1000.0

            logger.info(f"<<< eN28 UNSUBSCRIBE RESPONSE: status={response.status_code}, latency={latency_ms:.1f}ms")

            success = response.status_code in (200, 204)
            if success:
                logger.info(f"    Subscription {self._subscription_id} removed")
                self._subscription_id = None
            else:
                logger.warning(f"    Unsubscribe failed: {response.status_code} - {response.text[:500]}")

            return success, latency_ms

        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000.0
            logger.error(f"eN28 unsubscribe error: {e}")
            return False, latency_ms

    @property
    def subscription_id(self) -> Optional[str]:
        return self._subscription_id

    @property
    def is_subscribed(self) -> bool:
        return self._subscription_id is not None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
