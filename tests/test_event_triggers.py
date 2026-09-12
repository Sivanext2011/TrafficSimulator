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
