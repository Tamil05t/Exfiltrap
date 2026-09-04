"""Unit tests for M5 — classifier wrapper (tiny in-memory model, no artifacts)."""

from types import SimpleNamespace

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier

from exfiltrap.classifier import DNSClassifier


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Train a tiny separable RF and persist it, mimicking the real trainer."""
    import numpy as np

    rng = np.random.default_rng(0)
    benign = np.column_stack([
        rng.uniform(1.5, 3.2, 200), rng.uniform(10, 30, 200),
        rng.uniform(0, 2, 200), rng.uniform(1, 4, 200),
    ])
    malicious = np.column_stack([
        rng.uniform(4.2, 5.0, 200), rng.uniform(45, 120, 200),
        rng.uniform(2, 6, 200), rng.uniform(8, 50, 200),
    ])
    X = np.vstack([benign, malicious])
    y = np.array([0] * 200 + [1] * 200)
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(X, y)
    path = tmp_path_factory.mktemp("models") / "tiny_rf.joblib"
    joblib.dump(model, path)
    return model, path


class TestLoad:
    def test_load_missing_raises_helpful(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="train_classifier"):
            DNSClassifier.load(tmp_path / "nope.joblib")

    def test_load_roundtrip(self, trained):
        _, path = trained
        clf = DNSClassifier.load(path)
        assert clf.model is not None


class TestPredict:
    def test_proba_in_unit_range(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        p = clf.predict_proba([3.0, 20.0, 1.0, 2.0])
        assert 0.0 <= p <= 1.0
        assert isinstance(p, float)

    def test_separates_clear_cases(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        malicious_p = clf.predict_proba([4.8, 90.0, 4.0, 20.0])
        benign_p = clf.predict_proba([2.0, 15.0, 0.0, 1.0])
        assert malicious_p > 0.7
        assert benign_p < 0.3

    def test_accepts_attr_object(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        features = SimpleNamespace(entropy=4.8, length=90.0,
                                   subdomain_count=4.0, frequency=20.0)
        assert clf.predict_proba(features) > 0.7

    def test_accepts_tuple(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        assert clf.predict_proba((2.0, 15.0, 0.0, 1.0)) < 0.3

    def test_rejects_wrong_arity(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        with pytest.raises(ValueError):
            clf.predict_proba([1.0, 2.0])

    def test_predict_proba_many(self, trained):
        model, _ = trained
        clf = DNSClassifier(model)
        probs = clf.predict_proba_many([[4.8, 90.0, 4.0, 20.0],
                                        [2.0, 15.0, 0.0, 1.0]])
        assert len(probs) == 2
        assert probs[0] > 0.7 and probs[1] < 0.3
