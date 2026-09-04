"""Unit tests for M4 — dynamic baseline engine."""

import statistics

from exfiltrap.baseline_engine import BaselineEngine


class TestWarmup:
    def test_not_ready_before_warmup(self):
        eng = BaselineEngine(warmup=30)
        for _ in range(29):
            eng.update(1.0)
        assert not eng.ready
        assert eng.dynamic_threshold() is None
        assert eng.is_anomalous(100.0) is False

    def test_ready_after_warmup(self):
        eng = BaselineEngine(warmup=30)
        for _ in range(30):
            eng.update(1.0)
        assert eng.ready
        assert eng.dynamic_threshold() is not None


class TestEWMA:
    def test_first_observation_initializes(self):
        eng = BaselineEngine()
        assert eng.update(5.0) == 5.0

    def test_converges_to_constant_stream(self):
        eng = BaselineEngine(alpha=0.05)
        for _ in range(200):
            eng.update(1.0)
        assert abs(eng.mean - 1.0) < 0.01

    def test_alpha_weighting_exact(self):
        eng = BaselineEngine(alpha=0.25)
        eng.update(0.0)
        value = eng.update(1.0)
        assert abs(value - 0.25) < 1e-12

    def test_rejects_bad_alpha(self):
        try:
            BaselineEngine(alpha=0.0)
        except ValueError:
            pass
        else:
            raise AssertionError("alpha=0 must raise")


class TestWelfordStd:
    def test_single_observation_std_zero(self):
        eng = BaselineEngine()
        eng.update(3.0)
        assert eng.std == 0.0

    def test_matches_pstdev_of_stream(self):
        eng = BaselineEngine()
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        for v in values:
            eng.update(v)
        assert abs(eng.std - statistics.pstdev(values)) < 1e-9
        # Welford running mean over raw values should also match.
        assert abs(eng._welford_mean - statistics.fmean(values)) < 1e-9

    def test_threshold_uses_k_scaling(self):
        eng = BaselineEngine(alpha=1.0, k=3.0, warmup=1)
        eng.update(10.0)
        eng.update(10.0)
        # alpha=1 -> EWMA is the last observation (10); std over {10,10} is 0.
        assert abs(eng.dynamic_threshold() - 10.0) < 1e-9


class TestAnomalyDetection:
    def test_spike_after_constant_stream_is_anomalous(self):
        eng = BaselineEngine(alpha=0.05, warmup=30)
        for _ in range(100):
            eng.update(1.0)
        assert eng.is_anomalous(10.0) is True

    def test_small_wiggle_not_anomalous(self):
        # A constant stream has zero std, so ANY wiggle is anomalous by
        # mean+3*std (correct math). Use a mildly noisy baseline instead:
        # alternating 0.95/1.05 gives std ~= 0.05, threshold ~= 1.15.
        eng = BaselineEngine(alpha=0.05, warmup=30)
        for i in range(100):
            eng.update(0.95 if i % 2 else 1.05)
        assert eng.is_anomalous(1.05) is False
        assert eng.is_anomalous(1.5) is True

    def test_count_updates(self):
        eng = BaselineEngine()
        for i in range(7):
            eng.update(float(i))
        assert eng.n == 7
