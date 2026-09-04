"""Unit tests for M3 — stateful session tracker."""

import pytest

from exfiltrap.baseline_engine import BaselineEngine
from exfiltrap.session_tracker import SessionTracker, interval_cv


class TestIntervalCv:
    def test_perfect_period_is_zero(self):
        assert interval_cv([0.0, 30.0, 60.0, 90.0, 120.0]) == 0.0

    def test_poisson_like_is_near_one(self):
        # Exponential-ish gaps: 1, 9, 1, 9 -> mean 5, std 4 -> CV 0.8
        cv = interval_cv([0.0, 1.0, 10.0, 11.0, 20.0])
        assert 0.7 < cv < 0.9

    def test_needs_three_points(self):
        assert interval_cv([0.0, 5.0]) is None
        assert interval_cv([]) is None

    def test_zero_mean_is_none(self):
        assert interval_cv([1.0, 1.0, 1.0]) is None


class TestBeaconDetection:
    def test_periodic_session_flags_without_baseline(self):
        # Machine-regular 65s queries, benign-looking masses: the beacon
        # signal fires even with NO baseline at all (content-agnostic).
        tracker = SessionTracker(baseline=None)
        state = None
        for i in range(15):
            state = tracker.update("beacon-host", i * 65.0, 4.0, 2.5)
        assert state.beacon_candidate is True
        assert state.slow_drip_candidate is False  # mass signal stays clean
        assert state.interval_cv == 0.0

    def test_poisson_session_never_flags(self):
        tracker = SessionTracker(baseline=None)
        t = 0.0
        import random

        rng = random.Random(7)
        state = None
        for _ in range(200):
            t += rng.expovariate(1.0)
            state = tracker.update("poisson-host", t, 4.0, 2.5)
        assert state.beacon_candidate is False
        assert state.slow_drip_candidate is False

    def test_jittered_beacon_still_flags(self):
        # +/-10% jitter on a 60s timer keeps CV ~ 0.08 < 0.25.
        tracker = SessionTracker(baseline=None)
        import random

        rng = random.Random(3)
        t = 0.0
        state = None
        for i in range(20):
            t = i * 60.0 + rng.uniform(-6.0, 6.0)
            state = tracker.update("jittery", t, 4.0, 2.5)
        assert state.beacon_candidate is True

    def test_min_queries_guard(self):
        tracker = SessionTracker(baseline=None)
        state = None
        for i in range(9):  # one short of BEACON_MIN_QUERIES
            state = tracker.update("x", i * 65.0, 4.0, 2.5)
        assert state.beacon_candidate is False


def benign_mass(tracker, src, n, start=0.0, step=30.0, seed=5):
    """Feed n benign-looking queries (bytes=4, entropy=2.5 -> mass 2.0).

    Arrivals are Poisson-jittered around ``step``: benign resolvers are not
    metronomes, and perfectly periodic benign traffic would (correctly)
    trip the M3b beacon detector.
    """
    import random

    rng = random.Random(seed)
    last = None
    t = start
    for _ in range(n):
        t += rng.expovariate(1.0 / step)
        last = tracker.update(src, t, estimated_bytes=4.0, entropy=2.5)
    return last


class TestMassMath:
    def test_hand_computed_three_updates(self):
        tracker = SessionTracker(baseline=None)
        # (bytes=8, entropy=5.0) -> mass 8.0 ; (4, 2.5) -> 2.0 ; (10, 0.0) -> 0.0
        tracker.update("h1", 0.0, 8.0, 5.0)
        tracker.update("h1", 10.0, 4.0, 2.5)
        state = tracker.update("h1", 20.0, 10.0, 0.0)
        assert state.query_count == 3
        assert state.cumulative_mass == pytest.approx(10.0)
        assert state.mean_mass == pytest.approx(10.0 / 3.0)
        assert state.last_timestamp == 20.0

    def test_entropy_weight_clamped(self):
        assert SessionTracker.query_mass(10.0, 99.0) == 10.0  # weight capped at 1
        assert SessionTracker.query_mass(10.0, -5.0) == 0.0  # floored at 0


class TestSlowDripFlag:
    def test_benign_session_never_flags(self):
        tracker = SessionTracker(baseline=BaselineEngine(warmup=30))
        state = benign_mass(tracker, "benign-host", n=200, step=5.0)
        assert state is not None
        assert state.slow_drip_candidate is False

    def test_attacker_session_flags(self):
        tracker = SessionTracker(baseline=BaselineEngine(warmup=30))
        benign_mass(tracker, "benign-host", n=200, step=5.0)
        # Attacker: bytes=24, entropy=4.7 -> mass ~22.6, ~7x the benign mass
        # of 2.0, far above mean+3*std of the warmed-up baseline.
        flagged = None
        for i in range(60):
            state = tracker.update("attacker", 1000.0 + i * 30.0, 24.0, 4.7)
            if state.slow_drip_candidate:
                flagged = state
                break
        assert flagged is not None
        assert flagged.src_ip == "attacker"
        assert flagged.query_count >= 10  # min_queries guard respected

    def test_no_baseline_never_flags(self):
        tracker = SessionTracker(baseline=None)
        state = benign_mass(tracker, "x", n=50)
        for i in range(50):
            state = tracker.update("x", 5000.0 + i, 100.0, 5.0)
        assert state.slow_drip_candidate is False

    def test_sessions_independent(self):
        tracker = SessionTracker(baseline=BaselineEngine(warmup=30))
        benign_mass(tracker, "a", n=100, step=1.0)
        for i in range(100):
            tracker.update("b", i * 1.0, 24.0, 4.7)
        # "a" stays clean even while "b" is heavy.
        assert tracker.get("a").slow_drip_candidate is False


class TestWindowPruning:
    def test_old_entries_dropped(self):
        tracker = SessionTracker(window_seconds=100.0, baseline=None)
        tracker.update("s", 0.0, 8.0, 5.0)
        state = tracker.update("s", 50.0, 8.0, 5.0)
        assert state.query_count == 2
        # t=200: everything at or before t=100 leaves the window.
        state = tracker.update("s", 200.0, 8.0, 5.0)
        assert state.query_count == 1
        assert state.cumulative_mass == pytest.approx(8.0)

    def test_get_returns_none_for_unknown(self):
        assert SessionTracker(baseline=None).get("nobody") is None

    def test_snapshot_lists_all_sources(self):
        tracker = SessionTracker(baseline=None)
        tracker.update("a", 0.0, 1.0, 1.0)
        tracker.update("b", 0.0, 1.0, 1.0)
        assert set(tracker.snapshot()) == {"a", "b"}


class TestBeaconIntervalGuard:
    def test_fast_periodic_poller_not_flagged(self):
        # A 0.2s-period keepalive-style poller is periodic but FAST —
        # common benign machinery, must not trip M3b (BEACON_MIN_INTERVAL_S).
        tracker = SessionTracker(baseline=None)
        state = None
        for i in range(20):
            state = tracker.update("poller", i * 0.2, 4.0, 2.5)
        assert state.beacon_candidate is False

    def test_slow_periodic_still_flagged(self):
        tracker = SessionTracker(baseline=None)
        state = None
        for i in range(12):
            state = tracker.update("c2", i * 65.0, 4.0, 2.5)
        assert state.beacon_candidate is True
