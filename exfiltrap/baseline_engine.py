"""M4 — Dynamic baseline engine (non-ML).

Maintains an exponentially weighted moving average of an observed metric and
a rolling standard deviation via Welford's algorithm, then exposes a dynamic
anomaly threshold ``mean + k * std``. Everything here is deterministic.
"""

from __future__ import annotations

import statistics
from collections import deque

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
        # Robust population view: real network traffic is heavy-tailed, so
        # mean/std are dominated by bursts. A rolling window + median/MAD
        # gives an outlier-resistant baseline for the session z-test.
        self._window: deque[tuple[float, str | None]] = deque(maxlen=4000)
        # Median/MAD cache (see population_stats_excluding): recomputed at
        # most every _recompute_every observations.
        self._recompute_every = config.BASELINE_STATS_RECOMPUTE_EVERY
        self._stats_cache: tuple[str | None, tuple[float, float, int], int] | None = None
        self._mad_cache: tuple[float, int] | None = None

    def update(self, observed: float, src: str | None = None) -> float:
        """Fold one observation in; returns the updated EWMA mean."""
        if self._ewma is None:
            self._ewma = float(observed)
        else:
            self._ewma = self.alpha * observed + (1.0 - self.alpha) * self._ewma

        self._n += 1
        delta = observed - self._welford_mean
        self._welford_mean += delta / self._n
        self._welford_m2 += delta * (observed - self._welford_mean)
        self._window.append((observed, src))
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

    def population_stats_excluding(self, src: str | None):
        """(mean, mad, n) of the window EXCLUDING one source.

        The leave-one-source-out reference: a tunnel session must be
        compared against traffic that does not CONTAIN the tunnel —
        otherwise the attacker's own heavy queries drag the baseline
        toward them (observed live: baseline mean poisoned to 21.6).
        Returns None when too few independent samples remain.

        The two medians cost O(W log W) per call; recomputing them for
        every query made 20k-query floods O(N²) (measured 2026-09-10:
        ~160 q/s at 5k queries and falling). The result is cached and
        recomputed at most every BASELINE_STATS_RECOMPUTE_EVERY
        observations — over a 4000-slot window, 16 new observations
        shift the medians negligibly.
        """
        if (self._stats_cache is not None
                and self._stats_cache[0] == src
                and self._n - self._stats_cache[2] < self._recompute_every):
            return self._stats_cache[1]
        vals = [m for (m, s) in self._window if s != src]
        if len(vals) < 30:
            self._stats_cache = None
            return None
        med = statistics.median(vals)
        mad = statistics.median(abs(v - med) for v in vals)
        stats = (statistics.fmean(vals), mad, len(vals))
        self._stats_cache = (src, stats, self._n)
        return stats

    @property
    def population_median(self) -> float:
        """Median of the recent observation window (robust center)."""
        if not self._window:
            return 0.0
        return statistics.median(m for m, _ in self._window)

    @property
    def population_mad(self) -> float:
        """Median absolute deviation of the window (robust spread)."""
        if (self._mad_cache is not None
                and self._n - self._mad_cache[1] < self._recompute_every):
            return self._mad_cache[0]
        if not self._window:
            return 0.0
        masses = [m for m, _ in self._window]
        med = statistics.median(masses)
        mad = statistics.median(abs(v - med) for v in masses)
        self._mad_cache = (mad, self._n)
        return mad

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
