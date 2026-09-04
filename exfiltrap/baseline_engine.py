"""M4 — Dynamic baseline engine (non-ML).

Maintains an exponentially weighted moving average of an observed metric and
a rolling standard deviation via Welford's algorithm, then exposes a dynamic
anomaly threshold ``mean + k * std``. Everything here is deterministic.
"""

from __future__ import annotations

from exfiltrap import config


class BaselineEngine:
    """EWMA mean + Welford std with a warmup-gated dynamic threshold.

    # ASSUMPTION: the EWMA tracks the level of the metric while the standard
    deviation is computed over the raw observations (not the EWMA series) —
    Welford over raw values is exact and keeps the threshold sensitive to
    genuine dispersion rather than to smoothing lag.
    """

    def __init__(
        self,
        alpha: float = config.EWMA_ALPHA,
        k: float = config.BASELINE_K,
        warmup: int = config.BASELINE_WARMUP,
    ):
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.k = k
        self.warmup = warmup
        self._ewma: float | None = None
        self._n = 0
        self._welford_mean = 0.0
        self._welford_m2 = 0.0

    def update(self, observed: float) -> float:
        """Fold one observation in; returns the updated EWMA mean."""
        if self._ewma is None:
            self._ewma = float(observed)
        else:
            self._ewma = self.alpha * observed + (1.0 - self.alpha) * self._ewma

        self._n += 1
        delta = observed - self._welford_mean
        self._welford_mean += delta / self._n
        self._welford_m2 += delta * (observed - self._welford_mean)
        return self._ewma

    @property
    def mean(self) -> float:
        """EWMA level of the metric."""
        return 0.0 if self._ewma is None else self._ewma

    @property
    def std(self) -> float:
        """Population std of raw observations seen so far (Welford)."""
        if self._n < 2:
            return 0.0
        return (self._welford_m2 / self._n) ** 0.5

    @property
    def n(self) -> int:
        return self._n

    @property
    def population_mean(self) -> float:
        """Running mean over ALL raw observations (Welford), not the EWMA.

        The EWMA intentionally tracks only the recent level (~1/alpha
        observations of memory). Tests that compare long-window session
        statistics against the population must use this full-history mean,
        or the EWMA's lag bias swamps the comparison.
        """
        return self._welford_mean

    @property
    def population_std(self) -> float:
        """Alias of :attr:`std` for symmetry with population_mean."""
        return self.std

    @property
    def ready(self) -> bool:
        return self._n >= self.warmup

    def dynamic_threshold(self) -> float | None:
        """mean + k*std once warmed up, else None (not yet trustworthy)."""
        if not self.ready:
            return None
        return self.mean + self.k * self.std

    def is_anomalous(self, observed: float) -> bool:
        threshold = self.dynamic_threshold()
        if threshold is None:
            return False
        return observed > threshold
