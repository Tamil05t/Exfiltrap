"""Unit tests for M11 pure metric helpers (hand-computed expectations)."""

from eval.run_evaluation import (
    compute_metrics,
    confusion,
    detection_latency,
    build_stream,
    run_profile,
    PROFILES,
)


class TestConfusion:
    def test_balanced_example(self):
        # (T,T)->tp  (T,F)->fn  (F,T)->fp  (F,F)->tn
        assert confusion([(True, True), (True, False),
                          (False, True), (False, False)]) == (1, 1, 1, 1)

    def test_all_correct(self):
        assert confusion([(True, True), (True, True),
                          (False, False)]) == (2, 1, 0, 0)

    def test_empty(self):
        assert confusion([]) == (0, 0, 0, 0)


class TestComputeMetrics:
    def test_hand_computed(self):
        # tp=8 tn=10 fp=2 fn=2:
        # accuracy=18/22, precision=8/10, recall=8/10, fpr=2/12
        m = compute_metrics(8, 10, 2, 2)
        assert m["accuracy"] == 18 / 22
        assert m["precision"] == 0.8
        assert m["recall"] == 0.8
        assert m["fpr"] == 2 / 12

    def test_perfect(self):
        m = compute_metrics(10, 10, 0, 0)
        assert m["accuracy"] == 1.0 and m["fpr"] == 0.0

    def test_zero_division_guards(self):
        m = compute_metrics(0, 0, 0, 0)
        assert m == {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "fpr": 0.0}
        m = compute_metrics(0, 5, 0, 0)  # no positives at all
        assert m["recall"] == 0.0 and m["precision"] == 0.0

    def test_spec_balanced_case(self):
        # The spec's own sanity shape: TP=1 TN=1 FP=1 FN=1 -> all 0.5
        m = compute_metrics(1, 1, 1, 1)
        assert all(abs(v - 0.5) < 1e-12 for v in m.values())


class TestDetectionLatency:
    def test_first_flag(self):
        pairs = [(0.0, True, False), (30.0, True, True), (60.0, True, True),
                 (10.0, False, False)]
        assert detection_latency(pairs, attack_start=0.0) == 30.0

    def test_never_flagged(self):
        assert detection_latency([(0.0, True, False)], 0.0) is None

    def test_benign_flags_ignored(self):
        pairs = [(5.0, False, True), (50.0, True, True)]
        assert detection_latency(pairs, 10.0) == 40.0


class TestStreams:
    def test_profiles_deterministic(self):
        a = build_stream("slow-drip")
        b = build_stream("slow-drip")
        assert [r.query.qname for r in a] == [r.query.qname for r in b]

    def test_attack_profile_mixes_traffic(self):
        stream = build_stream("fast")
        flags = {r.is_malicious for r in stream}
        assert flags == {True, False}
        stamps = [r.query.timestamp for r in stream]
        assert stamps == sorted(stamps)

    def test_benign_profile_has_no_attacker_traffic(self):
        stream = build_stream("benign")
        assert all(not r.is_malicious for r in stream)

    def test_slow_drip_counts(self):
        stream = build_stream("slow-drip")
        malicious = [r for r in stream if r.is_malicious]
        from exfiltrap import config as cfg
        assert len(malicious) == int(7200.0 / cfg.SLOW_DRIP_QUERY_INTERVAL)

    def test_duration_override(self):
        stream = build_stream("slow-drip", slow_drip_duration=3600.0)
        from exfiltrap import config as cfg
        assert sum(1 for r in stream if r.is_malicious) == int(
            3600.0 / cfg.SLOW_DRIP_QUERY_INTERVAL)


class TestRunProfile:
    def test_benign_profile_full_pipeline_low_fpr(self):
        # Real run of the real pipeline (loads the real trained model).
        res = run_profile("benign", rf_only=False)
        assert res["n_malicious"] == 0
        assert res["fpr"] < 0.05  # benign noise must not light up the detector
        assert res["mode"] == "full"
        assert res["profile"] in PROFILES
