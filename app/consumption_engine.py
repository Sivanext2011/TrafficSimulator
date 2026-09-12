"""Consumption engine that simulates data usage at a configured speed.

The slider controls the simulated download speed (Mbps). The engine:
1. Creates a session with requested units for each rating group
2. Simulates consumption at the configured speed
3. When granted quota threshold is reached (or quota exhausted, or validity
   time expires), sends an update request with the appropriate trigger type
4. Repeats until stopped or session duration expires

Trigger-aware behavior (from CHF responses):
- volumeQuotaThreshold: report when used volume reaches (grantedVolume - threshold)
- validityTime: report when timer expires regardless of volume
- volumeLimit64 (session-level): report when cumulative volume crosses limit
- timeLimit (session-level): report when cumulative time crosses limit
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TriggerConfig:
    """Trigger thresholds from CHF Create/Update responses."""
    # Per-rating-group (from multipleUnitInformation)
    volume_quota_threshold: int = 0  # bytes - report when remaining <= this
    validity_time: int = 0  # seconds - report after this time

    # Session-level (from triggers array in Create response)
    volume_limit: int = 0  # bytes - session cumulative volume limit
    time_limit: int = 0  # seconds - session cumulative time limit
    max_number_of_ccc: int = 0  # max charging condition changes


@dataclass
class RatingGroupState:
    """Tracks quota state for a single rating group."""
    rating_group: int
    granted_total_volume: int = 0  # bytes granted by server
    granted_time: int = 0  # seconds granted
    used_total_volume: int = 0  # bytes consumed since last report
    used_time: int = 0  # seconds consumed since last report
    used_uplink: int = 0
    used_downlink: int = 0
    cumulative_volume: int = 0  # total bytes consumed across all updates
    cumulative_time: int = 0  # total seconds across all updates
    local_sequence_number: int = 0
    result_code: str = ""
    grant_timestamp: float = 0.0  # when the current grant was received
    final_unit: bool = False  # Final-Unit-Indication received (last grant)

    # Trigger config for this rating group
    triggers: TriggerConfig = field(default_factory=TriggerConfig)

    @property
    def remaining_volume(self) -> int:
        return max(0, self.granted_total_volume - self.used_total_volume)

    @property
    def threshold_reached(self) -> bool:
        """True when consumed volume reaches the quota threshold point."""
        if self.triggers.volume_quota_threshold > 0 and self.granted_total_volume > 0:
            report_at = self.granted_total_volume - self.triggers.volume_quota_threshold
            return self.used_total_volume >= report_at
        return False

    @property
    def is_exhausted(self) -> bool:
        """True when full granted volume is consumed."""
        if self.granted_total_volume > 0:
            return self.used_total_volume >= self.granted_total_volume
        return False

    @property
    def validity_expired(self) -> bool:
        """True when validity time has elapsed since grant."""
        if self.triggers.validity_time > 0 and self.grant_timestamp > 0:
            elapsed = time.time() - self.grant_timestamp
            return elapsed >= self.triggers.validity_time
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

    # Session-level triggers (from CHF Create response)
    session_triggers: TriggerConfig = field(default_factory=TriggerConfig)

    # Scheduled event triggers to simulate (feature #4): list of
    # {"at": <elapsed_seconds:int>, "type": <triggerType:str>}. When the session
    # elapsed time passes 'at', an UPDATE is sent with that triggerType, once.
    event_triggers: List[dict] = field(default_factory=list)
    fired_event_indexes: set = field(default_factory=set)


class ConsumptionEngine:
    """Simulates data consumption and drives charging session lifecycle.

    The speed_mbps controls how fast data is 'consumed'. When granted units
    threshold is reached, validity time expires, or session-level triggers
    fire, an update is sent.
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
        self._event_triggers: List[dict] = []

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

    def record_manual(self, success: bool, latency_ms: float = 0.0):
        """Record a manual-mode transaction into the dashboard metrics so the
        success/failure counters reflect manual Create/Update/Release too."""
        self._record(bool(success), float(latency_ms or 0.0))

    async def start(
        self,
        protocol,
        speed_mbps: float,
        num_sessions: int,
        rating_groups: List[int],
        session_duration_sec: int = 300,
        metrics_callback: Callable = None,
        event_triggers: Optional[List[dict]] = None,
    ):
        """Start the consumption simulation.

        Args:
            protocol: Protocol handler (CHF, Diameter, etc.)
            speed_mbps: Simulated download speed in Mbps
            num_sessions: Number of concurrent sessions
            rating_groups: List of rating group IDs to use
            session_duration_sec: How long each session lasts
            metrics_callback: Async function called with metrics updates
            event_triggers: Optional list of {"at": seconds, "type": triggerType}
                to simulate mid-session event reports (RAT_CHANGE, PLMN_CHANGE, ...)
        """
        if self._running:
            await self.stop()

        self._event_triggers = list(event_triggers or [])
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
            # Give the task time to send release requests gracefully
            try:
                await asyncio.wait_for(self._task, timeout=15.0)
            except asyncio.TimeoutError:
                logger.warning("Stop timed out waiting for sessions to release, cancelling")
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
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
            event_triggers=list(self._event_triggers),
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

            # Parse session-level triggers and granted units from response
            self._parse_session_triggers(session, response_data)
            self._parse_grants(session, response_data)

            # If all rating groups failed on create, skip consumption and release immediately
            if self._all_rating_groups_failed(session):
                logger.info("All rating groups failed on CREATE — sending release immediately")
                session.invocation_sequence += 1
                used_units = self._build_used_units(session, include_requested=False, trigger_type="FINAL")
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

                # Check session-level time limit
                if session.session_triggers.time_limit > 0:
                    if elapsed >= session.session_triggers.time_limit:
                        logger.info("Session TIME_LIMIT reached — sending update then release")
                        break

                # Simulate consumption
                time_step = 0.5  # check every 500ms
                await asyncio.sleep(time_step)

                # Calculate bytes consumed in this time step
                bytes_per_second = (self._speed_mbps * 1_000_000) / 8  # Mbps to bytes/sec
                bytes_consumed = int(bytes_per_second * time_step)

                # Distribute across rating groups (simple even split)
                per_rg = bytes_consumed // len(rating_groups) if rating_groups else 0

                trigger_type = None
                any_triggered = False

                for rg_id, rg_state in session.rating_groups.items():
                    # Cap consumption so a single interval never reports the ENTIRE
                    # grant. Report at the quota-threshold point (granted - threshold)
                    # if a threshold was given; otherwise cap at the full grant.
                    # Reporting 100% of the grant in one tick makes the OCS think the
                    # balance is exhausted and return a final (TERMINATE) grant even
                    # when balance remains — the bug this guards against.
                    if rg_state.granted_total_volume > 0:
                        thr = rg_state.triggers.volume_quota_threshold
                        report_cap = (rg_state.granted_total_volume - thr) if thr > 0 else rg_state.granted_total_volume
                        report_cap = max(1, report_cap)
                        available = report_cap - rg_state.used_total_volume
                        actual_consumed = max(0, min(per_rg, available))
                    else:
                        actual_consumed = per_rg
                    rg_state.used_total_volume += actual_consumed
                    rg_state.used_downlink += int(actual_consumed * 0.7)
                    rg_state.used_uplink += actual_consumed - int(actual_consumed * 0.7)
                    rg_state.used_time += int(time_step)
                    rg_state.cumulative_volume += actual_consumed
                    rg_state.cumulative_time += int(time_step)

                    # Check triggers in priority order
                    if rg_state.validity_expired and not any_triggered:
                        trigger_type = "VALIDITY_TIME"
                        any_triggered = True
                    elif rg_state.threshold_reached and not any_triggered:
                        trigger_type = "QUOTA_THRESHOLD"
                        any_triggered = True
                    elif rg_state.is_exhausted and not any_triggered:
                        trigger_type = "VOLUME_LIMIT"
                        any_triggered = True

                # Check session-level volume limit
                if not any_triggered and session.session_triggers.volume_limit > 0:
                    total_cumulative = sum(rg.cumulative_volume for rg in session.rating_groups.values())
                    if total_cumulative >= session.session_triggers.volume_limit:
                        trigger_type = "VOLUME_LIMIT"
                        any_triggered = True

                # Check scheduled event triggers (feature #4): fire an UPDATE with
                # the configured triggerType (e.g. RAT_CHANGE) once its time arrives.
                if not any_triggered and session.event_triggers:
                    for idx, ev in enumerate(session.event_triggers):
                        if idx in session.fired_event_indexes:
                            continue
                        if elapsed >= float(ev.get("at", 0)):
                            trigger_type = str(ev.get("type", "RAT_CHANGE"))
                            any_triggered = True
                            session.fired_event_indexes.add(idx)
                            logger.info(f"Event trigger fired at {elapsed:.0f}s: {trigger_type}")
                            break

                # Update total consumption metric
                total_consumed = sum(rg.cumulative_volume for rg in session.rating_groups.values())
                self._metrics["total_volume_consumed_mb"] = total_consumed / (1024 * 1024)

                # If any trigger fired, or fallback 30s timer, send update
                if any_triggered or (time.time() - session.last_update_time > 30):
                    if not trigger_type:
                        trigger_type = "TIME_LIMIT"  # periodic fallback

                    session.invocation_sequence += 1
                    used_units = self._build_used_units(session, trigger_type=trigger_type)

                    success, latency, response_data = await protocol.update_session(
                        sequence=session.invocation_sequence,
                        used_units=used_units,
                    )
                    self._record(success, latency)
                    session.last_update_time = time.time()

                    if metrics_callback:
                        await metrics_callback(self.get_metrics())

                    if success:
                        # Parse new grants and triggers from response
                        self._parse_grants(session, response_data)

                        # If all rating groups failed, stop consuming and release
                        if self._all_rating_groups_failed(session):
                            logger.info("All rating groups failed/exhausted — sending release")
                            break

                        # Final-Unit-Indication: the OCS granted the last quota.
                        # Consume it, then terminate (no further quota will be granted).
                        if any(rg.final_unit for rg in session.rating_groups.values()):
                            logger.info("Final-Unit-Indication received — consuming final grant then releasing")
                            self._reset_used(session)
                            break

                        # Reset consumed counters (cumulative keeps accumulating)
                        self._reset_used(session)
                    else:
                        # HTTP error — stop and release
                        logger.warning("Update failed with HTTP error — terminating session")
                        break

            # === RELEASE ===
            # If used counters are zero (after last _reset_used), simulate final
            # consumption of remaining granted quota that hasn't been reported yet.
            for rg_state in session.rating_groups.values():
                if rg_state.used_total_volume == 0 and rg_state.granted_total_volume > 0:
                    # Report remaining unreported usage (what was consumed since last update)
                    # In reality, some data would have been used between last CCR-U and CCR-T
                    # Cap at granted volume (3GPP: can't report more than granted)
                    import random as _rnd
                    final_usage = max(1, int(rg_state.granted_total_volume * _rnd.uniform(0.10, 0.50)))
                    final_usage = min(final_usage, rg_state.granted_total_volume)
                    rg_state.used_total_volume = final_usage
                    rg_state.used_downlink = int(final_usage * 0.7)
                    rg_state.used_uplink = final_usage - int(final_usage * 0.7)
                    rg_state.cumulative_volume += final_usage

            session.invocation_sequence += 1
            used_units = self._build_used_units(session, include_requested=False, trigger_type="FINAL")
            success, latency, _ = await protocol.release_session(
                sequence=session.invocation_sequence,
                used_units=used_units,
            )
            self._record(success, latency)
            if metrics_callback:
                await metrics_callback(self.get_metrics())

        except (Exception, asyncio.CancelledError) as e:
            if not isinstance(e, asyncio.CancelledError):
                logger.error(f"Session error: {e}")
                self._metrics["failed"] += 1
            # Send release on any exit (including cancellation)
            try:
                logger.info("Sending release before session cleanup")
                session.invocation_sequence += 1
                used_units = self._build_used_units(session, include_requested=False, trigger_type="FINAL")
                success, latency, _ = await protocol.release_session(
                    sequence=session.invocation_sequence,
                    used_units=used_units,
                )
                self._record(success, latency)
                if metrics_callback:
                    await metrics_callback(self.get_metrics())
            except Exception as release_err:
                logger.error(f"Failed to send release: {release_err}")
        finally:
            session.active = False
            self._metrics["active_sessions"] -= 1

    def _parse_session_triggers(self, session: SessionState, response_data: Optional[dict]):
        """Parse session-level triggers from CHF Create response.

        The Create response contains a 'triggers' array like:
        [
            {"triggerType": "TIME_LIMIT", "timeLimit": 3600, "triggerCategory": "IMMEDIATE_REPORT"},
            {"triggerType": "VOLUME_LIMIT", "volumeLimit64": 52428800, "triggerCategory": "IMMEDIATE_REPORT"},
            {"triggerType": "MAX_NUMBER_OF_CHANGES_IN_CHARGING_CONDITIONS", "maxNumberOfccc": 1}
        ]
        """
        if not response_data:
            return

        triggers_list = response_data.get("triggers", [])
        for trigger in triggers_list:
            trigger_type = trigger.get("triggerType", "")
            if trigger_type == "TIME_LIMIT":
                session.session_triggers.time_limit = trigger.get("timeLimit", 0)
                logger.info(f"  Session trigger: TIME_LIMIT = {session.session_triggers.time_limit}s")
            elif trigger_type == "VOLUME_LIMIT":
                session.session_triggers.volume_limit = trigger.get("volumeLimit64", 0)
                logger.info(f"  Session trigger: VOLUME_LIMIT = {session.session_triggers.volume_limit} bytes")
            elif trigger_type == "MAX_NUMBER_OF_CHANGES_IN_CHARGING_CONDITIONS":
                session.session_triggers.max_number_of_ccc = trigger.get("maxNumberOfccc", 0)
                logger.info(f"  Session trigger: MAX_CCC = {session.session_triggers.max_number_of_ccc}")

    def _parse_grants(self, session: SessionState, response_data: Optional[dict]):
        """Parse multipleUnitInformation to extract granted units and per-RG triggers.

        The Update response looks like:
        {
            "multipleUnitInformation": [{
                "ratingGroup": 1000,
                "resultCode": "SUCCESS",
                "grantedUnit": {"totalVolume": 524288},
                "volumeQuotaThreshold": 10240,
                "validityTime": 900,
                "quotaHoldingTime": 0
            }]
        }
        """
        if not response_data:
            # No response to parse — do not fabricate a grant. Leave state as-is;
            # the request path already recorded success/failure truthfully.
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
                        rg_state.granted_total_volume = 0
                        rg_state.granted_time = 0

                    # Parse per-RG trigger thresholds
                    rg_state.triggers.volume_quota_threshold = unit.get("volumeQuotaThreshold", 0)
                    rg_state.triggers.validity_time = unit.get("validityTime", 0)
                    rg_state.grant_timestamp = time.time()
                    # Final-Unit-Indication: this is the last grant for this RG.
                    rg_state.final_unit = bool(unit.get("finalUnitIndication") or unit.get("final"))

                    logger.info(
                        f"  RG {rg_id}: granted={rg_state.granted_total_volume} bytes, "
                        f"threshold={rg_state.triggers.volume_quota_threshold}, "
                        f"validityTime={rg_state.triggers.validity_time}s"
                        + (" [FINAL-UNIT]" if rg_state.final_unit else "")
                    )
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

    def _build_used_units(
        self,
        session: SessionState,
        include_requested: bool = True,
        trigger_type: str = "QUOTA_THRESHOLD",
    ) -> List[dict]:
        """Build usedUnitContainer list for update/release.

        Includes trigger information matching what the real SMF sends:
        - triggerType: QUOTA_THRESHOLD, VOLUME_LIMIT, TIME_LIMIT, VALIDITY_TIME, FINAL
        - triggerCategory: IMMEDIATE_REPORT
        """
        used_units = []
        for rg_id, rg_state in session.rating_groups.items():
            rg_state.local_sequence_number += 1

            # Hard cap: never report more than what was granted (3GPP compliance)
            reported_total = rg_state.used_total_volume
            if rg_state.granted_total_volume > 0:
                reported_total = min(reported_total, rg_state.granted_total_volume)
            reported_downlink = int(reported_total * 0.7)
            reported_uplink = reported_total - reported_downlink

            used_container = {
                "localSequenceNumber": rg_state.local_sequence_number,
                "totalVolume": reported_total,
                "uplinkVolume": reported_uplink,
                "downlinkVolume": reported_downlink,
                "quotaManagementIndicator": "ONLINE_CHARGING",
                "triggerTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "triggers": [
                    {
                        "triggerCategory": "IMMEDIATE_REPORT",
                        "triggerType": trigger_type,
                    }
                ],
            }
            if rg_state.used_time > 0:
                used_container["time"] = rg_state.used_time

            entry = {
                "ratingGroup": rg_id,
                "usedUnitContainer": [used_container],
            }
            if include_requested:
                entry["requestedUnit"] = {}
            used_units.append(entry)
        return used_units

    def _reset_used(self, session: SessionState):
        """Reset used counters after a successful update (cumulative keeps accumulating)."""
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
