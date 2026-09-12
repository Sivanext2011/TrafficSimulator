"""Tests for consumption-engine scheduled event triggers (feature #4)."""
import asyncio

from app.consumption_engine import ConsumptionEngine


class FakeChfHandler:
    """Minimal protocol handler capturing the trigger types sent on updates."""
    def __init__(self):
        self.update_triggers = []
        self.released = False
        self._ref = "abc123p1"

    async def create_session(self, rating_groups):
        # Large quota + long validity so volume/validity triggers do NOT fire
        # during the short test window — only the scheduled event should.
        resp = {
            "multipleUnitInformation": [{
                "ratingGroup": rating_groups[0],
                "resultCode": "SUCCESS",
                "grantedUnit": {"totalVolume": 10 ** 12},
                "validityTime": 100000,
                "volumeQuotaThreshold": 0,
            }],
            "triggers": [],
        }
        return True, 1.0, resp

    async def update_session(self, sequence, used_units):
        for u in used_units:
            for c in u.get("usedUnitContainer", []):
                for t in c.get("triggers", []):
                    self.update_triggers.append(t.get("triggerType"))
        resp = {
            "multipleUnitInformation": [{
                "ratingGroup": u["ratingGroup"],
                "resultCode": "SUCCESS",
                "grantedUnit": {"totalVolume": 10 ** 12},
                "validityTime": 100000,
            } for u in used_units],
        }
        return True, 1.0, resp

    async def release_session(self, sequence, used_units):
        self.released = True
        return True, 1.0, {}

    def get_session_ref(self):
        return self._ref


def test_scheduled_event_trigger_fires_update():
    async def _run():
        engine = ConsumptionEngine()
        handler = FakeChfHandler()
        # Fire a RAT_CHANGE ~1s in; run ~3s then stop.
        await engine.start(
            protocol=handler,
            speed_mbps=1.0,
            num_sessions=1,
            rating_groups=[1000],
            session_duration_sec=3,
            event_triggers=[{"at": 1, "type": "RAT_CHANGE"}],
        )
        await asyncio.sleep(4)
        await engine.stop()
        return handler

    handler = asyncio.run(_run())
    assert "RAT_CHANGE" in handler.update_triggers, (
        f"expected RAT_CHANGE update, got {handler.update_triggers}"
    )
    assert handler.released is True


class QuotaCapHandler:
    """Grants a fixed quota with a threshold; records reported usage volumes."""
    def __init__(self, granted, threshold):
        self.granted = granted
        self.threshold = threshold
        self.reported_totals = []
        self.released = False
        self._ref = "capp1"

    def _grant(self, rg):
        return {"multipleUnitInformation": [{
            "ratingGroup": rg, "resultCode": "SUCCESS",
            "grantedUnit": {"totalVolume": self.granted},
            "validityTime": 100000, "volumeQuotaThreshold": self.threshold,
        }]}

    async def create_session(self, rating_groups):
        return True, 1.0, {**self._grant(rating_groups[0]), "triggers": []}

    async def update_session(self, sequence, used_units):
        for u in used_units:
            for c in u.get("usedUnitContainer", []):
                self.reported_totals.append(c.get("totalVolume", 0))
        return True, 1.0, self._grant(u["ratingGroup"])

    async def release_session(self, sequence, used_units):
        for u in used_units:
            for c in u.get("usedUnitContainer", []):
                self.reported_totals.append(c.get("totalVolume", 0))
        self.released = True
        return True, 1.0, {}

    def get_session_ref(self):
        return self._ref


def test_update_never_reports_full_grant():
    """With a high speed the engine used to dump the entire grant in one update,
    provoking a premature final grant. The threshold cap must keep per-update
    reported usage <= (granted - threshold)."""
    granted, threshold = 10_485_760, 1_048_576  # matches the real trace
    async def _run():
        engine = ConsumptionEngine()
        handler = QuotaCapHandler(granted, threshold)
        await engine.start(
            protocol=handler,
            speed_mbps=1000.0,  # very fast — would blow through grant in one tick
            num_sessions=1,
            rating_groups=[1000],
            session_duration_sec=2,
        )
        await asyncio.sleep(3)
        await engine.stop()
        return handler

    handler = asyncio.run(_run())
    cap = granted - threshold
    # No UPDATE should report the full grant; release may add remaining usage but
    # each individual container report must respect the per-cycle cap.
    over = [t for t in handler.reported_totals if t > granted]
    assert not over, f"reported more than granted: {handler.reported_totals}"
    # At least one update happened and the first update did NOT report full grant.
    assert handler.reported_totals, "no usage reported"
    assert handler.reported_totals[0] <= cap, (
        f"first update reported {handler.reported_totals[0]} > cap {cap}"
    )


class FinalGrantHandler:
    """CREATE grants a small quota; the FIRST update returns a large FINAL grant
    with TERMINATE. Mirrors the real CHF trace. Records total reported volume."""
    def __init__(self, first_grant, final_grant):
        self.first_grant = first_grant
        self.final_grant = final_grant
        self.total_reported = 0
        self.updates = 0
        self.released = False
        self._ref = "fup1"

    async def create_session(self, rating_groups):
        return True, 1.0, {"multipleUnitInformation": [{
            "ratingGroup": rating_groups[0], "resultCode": "SUCCESS",
            "grantedUnit": {"totalVolume": self.first_grant},
            "validityTime": 1800, "volumeQuotaThreshold": self.first_grant // 10,
        }], "triggers": []}

    async def update_session(self, sequence, used_units):
        self.updates += 1
        for u in used_units:
            for c in u.get("usedUnitContainer", []):
                self.total_reported += c.get("totalVolume", 0)
        # First update -> return the FINAL grant with TERMINATE.
        return True, 1.0, {"multipleUnitInformation": [{
            "ratingGroup": u["ratingGroup"], "resultCode": "SUCCESS",
            "grantedUnit": {"totalVolume": self.final_grant},
            "validityTime": 900, "volumeQuotaThreshold": self.final_grant // 10,
            "finalUnitIndication": {"finalUnitAction": "TERMINATE"},
        }]}

    async def release_session(self, sequence, used_units):
        for u in used_units:
            for c in u.get("usedUnitContainer", []):
                self.total_reported += c.get("totalVolume", 0)
        self.released = True
        return True, 1.0, {}

    def get_session_ref(self):
        return self._ref


def test_final_grant_is_consumed_before_release():
    """When the CHF returns a final grant with TERMINATE, the session must
    consume (report) the full final grant before releasing — not bail out
    immediately reporting a random fraction."""
    first, final = 10_485_760, 283_362_786  # matches the real trace
    async def _run():
        engine = ConsumptionEngine()
        handler = FinalGrantHandler(first, final)
        await engine.start(
            protocol=handler,
            speed_mbps=1000.0,   # fast so the final grant drains within the window
            num_sessions=1,
            rating_groups=[1000],
            session_duration_sec=10,
        )
        await asyncio.sleep(6)
        await engine.stop()
        return handler

    handler = asyncio.run(_run())
    assert handler.released is True
    # The total reported across update(s)+release must cover the final grant,
    # i.e. the ~283 MB final grant was actually consumed (allow small rounding).
    assert handler.total_reported >= final * 0.95, (
        f"final grant not consumed: reported {handler.total_reported} of {final}"
    )
