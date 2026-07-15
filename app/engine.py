import asyncio
import logging
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class TrafficEngine:
    def __init__(self):
        self._running = False
        self._tps = 1.0
        self._task: Optional[asyncio.Task] = None
        self._metrics = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "active_sessions": 0,
            "avg_latency_ms": 0.0,
            "current_tps": 0.0,
            "protocol": None,
            "state": "idle",
        }
        self._latencies = []
        self._request_times = []

    def set_tps(self, tps: float):
        self._tps = max(0.1, tps)

    def get_metrics(self) -> dict:
        now = time.time()
        # Calculate actual TPS from last 5 seconds
        recent = [t for t in self._request_times if now - t < 5.0]
        self._metrics["current_tps"] = len(recent) / 5.0 if recent else 0.0
        return self._metrics.copy()

    async def start(
        self,
        protocol,
        tps: float,
        num_sessions: int,
        updates_per_session: int,
        metrics_callback: Callable,
    ):
        if self._running:
            await self.stop()

        self._tps = tps
        self._running = True
        self._metrics["state"] = "running"
        self._metrics["protocol"] = protocol.__class__.__name__
        self._task = asyncio.create_task(
            self._run_loop(protocol, num_sessions, updates_per_session, metrics_callback)
        )

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._metrics["state"] = "idle"

    async def _run_loop(
        self, protocol, num_sessions: int, updates_per_session: int, metrics_callback: Callable
    ):
        try:
            sessions_started = 0
            while self._running and sessions_started < num_sessions:
                interval = 1.0 / self._tps
                start = time.time()

                # Run one full session lifecycle
                asyncio.create_task(
                    self._run_session(protocol, updates_per_session, metrics_callback)
                )
                sessions_started += 1

                elapsed = time.time() - start
                sleep_time = max(0, interval - elapsed)
                await asyncio.sleep(sleep_time)

            # Wait for remaining sessions to complete
            await asyncio.sleep(2)
            self._metrics["state"] = "completed"
            await metrics_callback(self.get_metrics())

        except asyncio.CancelledError:
            logger.info("Traffic engine stopped")
        except Exception as e:
            logger.error(f"Engine error: {e}")
            self._metrics["state"] = "error"

    async def _run_session(self, protocol, updates_per_session: int, metrics_callback: Callable):
        self._metrics["active_sessions"] += 1

        try:
            # CREATE
            success, latency = await protocol.create_session()
            self._record_request(success, latency)
            await metrics_callback(self.get_metrics())

            if not success:
                return

            # UPDATES
            for i in range(updates_per_session):
                if not self._running:
                    break
                await asyncio.sleep(1.0 / self._tps)
                success, latency = await protocol.update_session(sequence=i + 1)
                self._record_request(success, latency)
                await metrics_callback(self.get_metrics())

            # RELEASE
            success, latency = await protocol.release_session()
            self._record_request(success, latency)
            await metrics_callback(self.get_metrics())

        except Exception as e:
            logger.error(f"Session error: {e}")
            self._metrics["failed"] += 1
        finally:
            self._metrics["active_sessions"] -= 1

    def _record_request(self, success: bool, latency_ms: float):
        self._metrics["total_requests"] += 1
        if success:
            self._metrics["successful"] += 1
        else:
            self._metrics["failed"] += 1

        self._latencies.append(latency_ms)
        if len(self._latencies) > 1000:
            self._latencies = self._latencies[-500:]
        self._metrics["avg_latency_ms"] = sum(self._latencies) / len(self._latencies)

        self._request_times.append(time.time())
        if len(self._request_times) > 1000:
            self._request_times = self._request_times[-500:]
