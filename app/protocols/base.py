"""Base protocol class with common HTTP client logic, SSL context creation, and timing wrapper."""

import ssl
import time
import uuid
from abc import ABC, abstractmethod
from typing import Tuple

import httpx


class BaseProtocol(ABC):
    """Base class for all telecom protocol implementations.

    Provides:
    - mTLS SSL context creation from cert/key/ca paths
    - httpx.AsyncClient with HTTP/2 support
    - Timing wrapper for measuring request latency
    - Common session lifecycle interface
    """

    def __init__(
        self,
        fqdn: str,
        port: int,
        base_path: str,
        cert_path: str = None,
        key_path: str = None,
        ca_path: str = None,
        subscriber: dict = None,
        secure: bool = True,
        verify_ssl: bool = True,
    ):
        self.fqdn = fqdn
        self.port = port
        self.base_path = (base_path or "").rstrip("/")
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.subscriber = subscriber or {}
        self.secure = secure
        self.verify_ssl = verify_ssl

        scheme = "https" if self.secure else "http"
        self._base_url = f"{scheme}://{self.fqdn}:{self.port}{self.base_path}"
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an mTLS SSL context from certificate, key, and CA paths."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.cert_path and self.key_path:
            ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        if self.ca_path:
            ctx.load_verify_locations(cafile=self.ca_path)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP/2 client.

        Supports:
        - mTLS (secure=True with certs)
        - TLS without client cert (secure=True, no certs)
        - TLS without verification (secure=True, verify_ssl=False)
        - Plain HTTP (secure=False)
        """
        if self._client is None or self._client.is_closed:
            if not self.secure:
                # Plain HTTP - no TLS
                self._client = httpx.AsyncClient(
                    http2=True,
                    verify=False,
                    base_url=self._base_url,
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
            elif self.cert_path and self.key_path:
                # mTLS with client cert
                if self.verify_ssl:
                    ssl_context = self._create_ssl_context()
                    self._client = httpx.AsyncClient(
                        http2=True,
                        verify=ssl_context,
                        base_url=self._base_url,
                        timeout=httpx.Timeout(30.0, connect=10.0),
                    )
                else:
                    # mTLS but skip server verification (like curl -k)
                    self._client = httpx.AsyncClient(
                        http2=True,
                        verify=False,
                        cert=(self.cert_path, self.key_path),
                        base_url=self._base_url,
                        timeout=httpx.Timeout(30.0, connect=10.0),
                    )
            else:
                # HTTPS without client cert
                self._client = httpx.AsyncClient(
                    http2=True,
                    verify=self.verify_ssl,
                    base_url=self._base_url,
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
        return self._client

    async def _timed_request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Tuple[httpx.Response | None, float]:
        """Execute an HTTP request and measure latency in milliseconds.

        Returns:
            Tuple of (response or None on error, latency_ms)
        """
        client = await self._get_client()
        start = time.perf_counter()
        try:
            response = await client.request(method, url, **kwargs)
            latency_ms = (time.perf_counter() - start) * 1000.0
            return response, latency_ms
        except (httpx.HTTPError, OSError):
            latency_ms = (time.perf_counter() - start) * 1000.0
            return None, latency_ms

    @staticmethod
    def _generate_id() -> str:
        """Generate a unique identifier for sessions."""
        return str(uuid.uuid4())

    @abstractmethod
    async def create_session(self) -> Tuple[bool, float]:
        """Create a new session. Returns (success, latency_ms)."""
        ...

    @abstractmethod
    async def update_session(self, sequence: int) -> Tuple[bool, float]:
        """Update an existing session. Returns (success, latency_ms)."""
        ...

    @abstractmethod
    async def release_session(self) -> Tuple[bool, float]:
        """Release/terminate a session. Returns (success, latency_ms)."""
        ...

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
