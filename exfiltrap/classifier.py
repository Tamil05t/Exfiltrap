"""M5 — Random Forest classifier wrapper.

Loads the joblib-persisted RandomForestClassifier produced by
``tools/train_classifier.py`` and exposes a uniform ``predict_proba``
over the four base-paper features.
"""

from __future__ import annotations

from typing import Sequence

import joblib

from exfiltrap import config

FEATURE_ORDER = ("entropy", "length", "subdomain_count", "frequency")


class DNSClassifier:
    """Thin, injectable wrapper around the fitted sklearn model."""

    def __init__(self, model):
        self.model = model

    @classmethod
    def load(cls, path=None) -> "DNSClassifier":
        """Load a trained model; raises with a actionable message if absent."""
        path = path if path is not None else config.MODEL_PATH
        try:
            model = joblib.load(path)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"No trained model at {path}. Run `python3 tools/train_classifier.py` first."
            ) from None
        # Trained with n_jobs=-1; for streaming per-row inference the
        # thread-pool dispatch costs far more than it saves.
        model.n_jobs = 1
        return cls(model)

    @staticmethod
    def _to_row(features) -> Sequence[float]:
        """Accept a FeatureVector-like object or a plain 4-sequence."""
        if hasattr(features, "entropy"):
            return [
                float(features.entropy),
                float(features.length),
                float(features.subdomain_count),
                float(features.frequency),
            ]
        row = list(features)
        if len(row) != len(FEATURE_ORDER):
            raise ValueError(f"expected {len(FEATURE_ORDER)} features, got {len(row)}")
        return [float(v) for v in row]

    def predict_proba(self, features) -> float:
        """P(malicious) for one query's feature vector."""
        import warnings

        row = [self._to_row(features)]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # feature-name noise
            return float(self.model.predict_proba(row)[0, 1])

    def predict_proba_many(self, rows: Sequence[Sequence[float]]) -> list[float]:
        """Vectorized P(malicious) for many 4-sequences."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            probs = self.model.predict_proba([list(r) for r in rows])
        return [float(p[1]) for p in probs]
