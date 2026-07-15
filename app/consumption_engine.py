"""Consumption engine that simulates data usage at a configured speed.

The slider controls the simulated download speed (Mbps). The engine:
1. Creates a session with requested units for each rating group
2. Simulates consumption at the configured speed
3. When granted quota is exhausted, sends an update request
4. Repeats until stopped or session duration expires
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RatingGroupState:
    """Tracks quota state for a single rating group."""
    rating_group: int
    granted_total_volume: int = 0  # bytes granted by server
    granted_time: int = 0  # seconds granted
    used_total_volume: int = 0  # bytes consumed so far
    used_time: int = 0  # seconds consumed
    used_uplink: int = 0
    used_downlink: int = 0
    local_sequence_number: int = 0
    result_code: str = ""

    @property
    def remaining_volume(self) -> int:
        return max(0, self.granted_total_volume - self.used_total_volume)

    @property
    def is_exhausted(self) -> bool:
        if self.granted_total_volume > 0:
            return self.used_total_volume >= self.granted_total_volume
        return False


@dataclass
class SessionState:
    """Tracks the overall session state."""
    session_id: str = ""
    charging_data_ref: str = ""
    active: bool = False
    rating_groups: Dict[int, RatingGroupState] = field(default_factory=dict)
    invocation_sequence: int = 0
    start_time: float = 0.0
    last_update_time: float = 0.0


class ConsumptionEngine:
    """Simulates data consumption and drives charging session lifecycle.

    The speed_mbps controls how fast data is 'consumed'. When granted units
    are exhausted for any rating group, an update is triggered.
    """

    def __init__(self):
        self._speed_mbps: float = 10.0  # default 10 Mbps
        self._running: bool = False
        self._sessions: List[SessionState] = []
        self._task: Optional[asyncio.Task] = None
        self._metrics = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "active_sessions": 0,
            "current_tps": 0.0,
            "avg_latency_ms": 0.0,
            "speed_mbps": 10.0,
            "total_volume_consumed_mb": 0.0,
            "state": "idle",
            "protocol": None,
        }
        self._latencies: List[float] = []
        self._request_times: List[float] = []

    @property
    def speed_mbps(self) -> float:
        return self._speed_mbps

    def set_speed(self, speed_mbps: float):
        """Set the simulated download speed (Mbps). Controls update frequency."""
        self._speed_mbps = max(0.1, min(speed_mbps, 10000.0))
        self._metrics["speed_mbps"] = self._speed_mbps

    def get_metrics(self) -> dict:
        now = time.time()
        recent = [t for t in self._request_times if now - t < 5.0]
        self._metrics["current_tps"] = len(recent) / 5.0 if recent else 0.0
        return self._metrics.copy()

    async def start(
        self,
        protocol,
        speed_mbps: float,
        num_sessions: int,
        rating_groups: List[int],
        session_duration_sec: int = 300,
        metrics_callback: Callable = None,
    ):
        """Start the consumption simulation.

        Args:
            protocol: Protocol handler (CHF, Diameter, etc.)
            speed_mbps: Simulated download speed in Mbps
            num_sessions: Number of concurrent sessions
            rating_groups: List of rating group IDs to use
            session_duration_sec: How long each session lasts
            metrics_callback: Async function called with metrics updates
        """
        if self._running:
            await self.stop()

        self._speed_mbps = speed_mbps
        self._running = True
        self._metrics["state"] = "running"
        self._metrics["protocol"] = protocol.__class__.__name__
        self._metrics["speed_mbps"] = speed_mbps

        self._task = asyncio.create_task(
            self._run_sessions(
                protocol, num_sessions, rating_groups,
                session_duration_sec, metrics_callback
            )
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

    async def _run_sessions(
        self, protocol, num_sessions, rating_groups,
        session_duration_sec, metrics_callback
    ):
        """Launch multiple concurrent sessions."""
        try:
            tasks = []
            for i in range(num_sessions):
                task = asyncio.create_task(
                    self._run_single_session(
                        protocol, rating_groups, session_duration_sec, metrics_callback
                    )
                )
                tasks.append(task)
                # Stagger session starts slightly
                await asyncio.sleep(0.1)

            await asyncio.gather(*tasks, return_exceptions=True)
            self._metrics["state"] = "completed"
            if metrics_callback:
                await metrics_callback(self.get_metrics())

        except asyncio.CancelledError:
            logger.info("Consumption engine stopped")
        except Exception as e:
            logger.error(f"Engine error: {e}")
            self._metrics["state"] = "error"

    async def _run_single_session(
        self, protocol, rating_groups, session_duration_sec, metrics_callback
    ):
        """Run a single session: Create → consume → Update(s) → Release."""
        session = SessionState(
            rating_groups={rg: RatingGroupState(rating_group=rg) for rg in rating_groups},
            start_time=time.time(),
            last_update_time=time.time(),
        )
        self._metrics["active_sessions"] += 1

        try:
            # === CREATE ===
            success, latency, response_data = await protocol.create_session(rating_groups)
            self._record(success, latency)
            if metrics_callback:
                await metrics_callback(self.get_metrics())

            if not success:
                return

            session.charging_data_ref = protocol.get_session_ref()
            session.active = True

            # Parse granted units from response
            self._parse_grants(session, response_data)

            # If all rating groups failed on create, skip consumption and release immediately
            if self._all_rating_groups_failed(session):
                logger.info("All rating groups failed on CREATE — sending release immediately")
                session.invocation_sequence += 1
                used_units = self._build_used_units(session, include_requested=False)
                success, latency, _ = await protocol.release_session(
                    sequence=session.invocation_sequence,
                    used_units=used_units,
                )
                self._record(success, latency)
                if metrics_callback:
                    await metrics_callback(self.get_metrics())
                return

            # === CONSUMPTION LOOP ===
            while self._running and session.active:
                elapsed = time.time() - session.start_time
                if elapsed >= session_duration_sec:
                    break

                # Simulate consumption
                time_step = 0.5  # check every 500ms
                await asyncio.sleep(time_step)

                # Calculate bytes consumed in this time step
                bytes_per_second = (self._speed_mbps * 1_000_000) / 8  # Mbps to bytes/sec
                bytes_consumed = int(bytes_per_second * time_step)

                # Distribute across rating groups (simple even split)
                per_rg = bytes_consumed // len(rating_groups) if rating_groups else 0

                any_exhausted = False
                for rg_id, rg_state in session.rating_groups.items():
                    rg_state.used_total_volume += per_rg
                    rg_state.used_downlink += int(per_rg * 0.7)
                    rg_state.used_uplink += int(per_rg * 0.3)
                    rg_state.used_time += int(time_step)

                    if rg_state.is_exhausted:
                        any_exhausted = True

                # Update total consumption metric
                total_consumed = sum(rg.used_total_volume for rg in session.rating_groups.values())
                self._metrics["total_volume_consumed_mb"] = total_consumed / (1024 * 1024)

                # If any RG exhausted, send update
                if any_exhausted or (time.time() - session.last_update_time > 30):
                    session.invocation_sequence += 1
                    used_units = self._build_used_units(session)

                    success, latency, response_data = await protocol.update_session(
                        sequence=session.invocation_sequence,
                        used_units=used_units,
                    )
                    self._record(success, latency)
                    session.last_update_time = time.time()

                    if metrics_callback:
                        await metrics_callback(self.get_metrics())

                    if success:
                        # Reset consumed counters and apply new grants
                        self._parse_grants(session, response_data)

                        # If all rating groups failed, stop consuming and release
                        if self._all_rating_groups_failed(session):
                            logger.info("All rating groups failed/exhausted — sending release")
                            break

                        # Only reset after confirming we got new grants
                        self._reset_used(session)
                    else:
                        # HTTP error — stop and release
                        logger.warning(f"Update failed with HTTP error — terminating session")
                        break

            # === RELEASE ===
            session.invocation_sequence += 1
            used_units = self._build_used_units(session, include_requested=False)
            success, latency, _ = await protocol.release_session(
                sequence=session.invocation_sequence,
                used_units=used_units,
            )
            self._record(success, latency)
            if metrics_callback:
                await metrics_callback(self.get_metrics())

        except Exception as e:
            logger.error(f"Session error: {e}")
            self._metrics["failed"] += 1
        finally:
            session.active = False
            self._metrics["active_sessions"] -= 1

    def _parse_grants(self, session: SessionState, response_data: Optional[dict]):
        """Parse multipleUnitInformation to extract granted units.

        Handles:
        - SUCCESS with grantedUnit → use granted values
        - RATING_FAILED / no grantedUnit → set granted to 0 (will trigger release)
        - No response → default grant for first request only
        """
        if not response_data:
            # Default grant only if this is the first request (no result yet)
            for rg_state in session.rating_groups.values():
                if not rg_state.result_code:
                    rg_state.granted_total_volume = 10 * 1024 * 1024  # 10MB default
                    rg_state.granted_time = 300
            return

        units_info = response_data.get("multipleUnitInformation", [])
        for unit in units_info:
            rg_id = unit.get("ratingGroup")
            if rg_id in session.rating_groups:
                rg_state = session.rating_groups[rg_id]
                rg_state.result_code = unit.get("resultCode", "")

                # Only grant units if resultCode indicates success
                if rg_state.result_code in ("SUCCESS", ""):
                    granted = unit.get("grantedUnit", {})
                    if granted:
                        rg_state.granted_total_volume = granted.get("totalVolume", 0)
                        rg_state.granted_time = granted.get("time", 0)
                    else:
                        # SUCCESS but no grantedUnit — no more quota
                        rg_state.granted_total_volume = 0
                        rg_state.granted_time = 0
                else:
                    # RATING_FAILED or other error — no grant
                    rg_state.granted_total_volume = 0
                    rg_state.granted_time = 0
                    logger.warning(
                        f"Rating group {rg_id} returned {rg_state.result_code} — no quota granted"
                    )

    def _all_rating_groups_failed(self, session: SessionState) -> bool:
        """Check if all rating groups have failed (no quota available)."""
        for rg_state in session.rating_groups.values():
            if rg_state.result_code in ("SUCCESS", ""):
                return False
            if rg_state.granted_total_volume > 0:
                return False
        return True

    def _build_used_units(self, session: SessionState, include_requested: bool = True) -> List[dict]:
        """Build usedUnitContainer list for update/release.

        Args:
            include_requested: If True, include requestedUnit (for updates). False for release.
        """
        used_units = []
        for rg_id, rg_state in session.rating_groups.items():
            rg_state.local_sequence_number += 1
            used_container = {
                "localSequenceNumber": rg_state.local_sequence_number,
                "totalVolume": rg_state.used_total_volume,
                "uplinkVolume": rg_state.used_uplink,
                "downlinkVolume": rg_state.used_downlink,
            }
            if rg_state.used_time > 0:
                used_container["time"] = rg_state.used_time

            entry = {
                "ratingGroup": rg_id,
                "usedUnitContainer": [used_container],
            }
            if include_requested:
                entry["requestedUnit"] = {
                    "totalVolume": 0,
                    "uplinkVolume": 0,
                    "downlinkVolume": 0,
                }
            used_units.append(entry)
        return used_units

    def _reset_used(self, session: SessionState):
        """Reset used counters after a successful update."""
        for rg_state in session.rating_groups.values():
            rg_state.used_total_volume = 0
            rg_state.used_uplink = 0
            rg_state.used_downlink = 0
            rg_state.used_time = 0

    def _record(self, success: bool, latency_ms: float):
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
