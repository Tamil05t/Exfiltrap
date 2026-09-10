"""M3 — Stateful session tracker.

Keeps a per-source-IP sliding window (2 hours by default) of
``(timestamp, entropy-weighted byte mass)`` contributions. The cumulative
mass is what a slow-drip attacker cannot avoid building up: each query
carries a small payload, but the session total keeps growing while benign
resolver traffic stays dominated by short, low-entropy labels.
"""

from __future__ import annotations

import threading
import statistics
from collections import deque
from dataclasses import dataclass

from exfiltrap import config
from exfiltrap.baseline_engine import BaselineEngine
from exfiltrap.features import base_domain


@dataclass
class SessionState:
    """Snapshot of one source IP's window state after an update."""

    src_ip: str
    query_count: int
    cumulative_mass: float
    mean_mass: float
    window_seconds: float
    slow_drip_candidate: bool
    last_timestamp: float
    beacon_candidate: bool = False
    interval_cv: float | None = None
    velocity_candidate: bool = False
    domain_beacon: bool = False
    resp_answer_bytes: int = 0
    resp_flag: bool = False


def interval_cv(timestamps: list[float]) -> float | None:
    """Coefficient of variation of inter-arrival times (None if undefined).

    Machine-paced beacons (fixed timers) converge to CV ~ 0 regardless of
    the interval; organic Poisson-like traffic sits near 1. This makes the
    signal encoding- and content-agnostic: it fires even when the tunnel
    carries low-entropy, benign-looking labels.
    """
    if len(timestamps) < 3:
        return None
    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return None
    var = sum((i - mean) ** 2 for i in intervals) / len(intervals)
    return (var ** 0.5) / mean


class SessionTracker:
    """Sliding-window byte-mass accounting per source IP.

    # ASSUMPTION: the spec compares "cumulative entropy-weighted byte mass"
    # against M4's dynamic threshold. We implement that comparison as a
    # sequential z-test on the session's mean per-query mass: the test
    # statistic grows with accumulation (N queries tighten the standard
    # error), so a session that consistently carries heavier, higher-entropy
    # labels than the learned baseline eventually crosses k sigma — exactly
    # the "accumulated mass exceeds the dynamic threshold" condition — while
    # volume differences alone (a busy vs idle benign client) never trigger
    # it, because their per-query masses stay at the baseline level.
    """

    def __init__(
        self,
        window_seconds: float = config.SESSION_WINDOW_SECONDS,
        baseline: BaselineEngine | None = None,
        min_queries: int = config.SLOW_DRIP_MIN_QUERIES,
        resp_baseline: BaselineEngine | None = None,
    ):
        self.window_seconds = window_seconds
        self.baseline = baseline
        self.min_queries = min_queries
        # Download channel: answer-mass population gets its OWN baseline —
        # response sizes live on a different scale than query-label mass.
        self.resp_baseline = resp_baseline or BaselineEngine(
            alpha=config.EWMA_ALPHA, k=config.BASELINE_K,
            warmup=config.BASELINE_WARMUP)
        self._sessions: dict[str, deque[tuple[float, float]]] = {}
        self._resp_sessions: dict[str, deque[tuple[float, float]]] = {}
        # Domain-level tracking: (src, base_domain) -> timestamps. The
        # per-source session mixes attack + legitimate traffic on a real
        # host (defeating mass/timing per source), but the DOMAIN view
        # isolates the tunnel: one base domain receiving many high-entropy
        # labels at machine-regular intervals.
        self._domain_times: dict[tuple[str, str], deque[float]] = {}
        # Capture, API and maintenance threads all touch the deques; the
        # stress test caught a live "deque mutated during iteration" race
        # between them, so every access is serialized.
        self._lock = threading.RLock()

    @staticmethod
    def query_mass(estimated_bytes: float, entropy: float) -> float:
        """Entropy-weighted byte mass of a single query."""
        weight = min(max(entropy / config.MAX_LABEL_ENTROPY, 0.0), 1.0)
        return estimated_bytes * weight

    def update(
        self, src_ip: str, timestamp: float, estimated_bytes: float, entropy: float,
        qname: str | None = None,
    ) -> SessionState:
        """Fold one query into its source's window; returns the new state."""
        with self._lock:
            return self._update_locked(src_ip, timestamp, estimated_bytes,
                                       entropy, qname)

    def _update_locked(self, src_ip, timestamp, estimated_bytes, entropy,
                       qname=None):
        mass = self.query_mass(estimated_bytes, entropy)
        dq = self._sessions.setdefault(src_ip, deque())
        cutoff = timestamp - self.window_seconds
        while dq and dq[0][0] <= cutoff:
            dq.popleft()
        dq.append((timestamp, mass))

        if self.baseline is not None:
            self.baseline.update(mass, src_ip)

        # M3c domain-level signals (velocity + per-domain beacon timing).
        velocity_flag = False
        domain_beacon = False
        if qname:
            bd = base_domain(qname)
            dq2 = self._domain_times.setdefault((src_ip, bd), deque())
            # keep the full session window: velocity counts the last 60s,
            # the beacon test spans the whole session
            cutoff = timestamp - self.window_seconds
            while dq2 and dq2[0] <= cutoff:
                dq2.popleft()
            dq2.append(timestamp)
            recent = [ts for ts in dq2 if ts > timestamp - config.DOMAIN_VELOCITY_WINDOW]
            if (len(recent) >= config.DOMAIN_VELOCITY_COUNT
                    and entropy >= config.DOMAIN_VELOCITY_MIN_ENTROPY):
                velocity_flag = True
            if len(dq2) >= config.DOMAIN_BEACON_MIN_QUERIES:
                gaps = [b2 - a2 for a2, b2 in zip(list(dq2), list(dq2)[1:])]
                # Judge regularity on the TRAILING gaps only: over a 2 h
                # window the gap series of an ongoing periodic beacon is
                # poisoned by every idle period between sessions (one
                # 10-minute gap among 5.5 s gaps pushes CV past the gate
                # and the beacon never fires again — observed live), and
                # the attacker gains a permanent silence after the first
                # detection. The last MIN_QUERIES-1 gaps are exactly the
                # current machine-periodic run.
                tail = gaps[-(config.DOMAIN_BEACON_MIN_QUERIES - 1):]
                if len(tail) >= 2:
                    mean_gap = statistics.fmean(tail)
                    if mean_gap > 0:
                        var = sum((g - mean_gap) ** 2
                                  for g in tail) / len(tail)
                        dcv = (var ** 0.5) / mean_gap
                        if (dcv < config.DOMAIN_BEACON_MAX_CV
                                and mean_gap >= config.DOMAIN_BEACON_MIN_INTERVAL):
                            domain_beacon = True

        query_count = len(dq)
        cumulative = sum(m for _, m in dq)
        mean_mass = cumulative / query_count if query_count else 0.0

        slow_drip = False
        if self.baseline is not None and self.baseline.ready:
            if query_count >= self.min_queries:
                # Robust sequential test: compare the session MEAN against
                # the population MEAN (same statistic, both sides), with the
                # SPREAD estimated robustly by MAD — real desktop traffic is
                # bimodal/heavy-tailed (tiny www labels vs heavy bare-domain
                # labels), where plain std is inflated by bursts and a
                # mean-vs-median comparison is apples-vs-oranges (both
                # failure modes observed live on real machines).
                # Leave-one-source-out reference: immune to the attacker
                # polluting the baseline with its own traffic AND correct
                # for skewed/multimodal benign traffic (mean-vs-mean).
                excl = self.baseline.population_stats_excluding(src_ip)
                if excl is not None:
                    pop_mean, pop_mad, _ = excl
                else:
                    pop_mean = self.baseline.mean
                    pop_mad = self.baseline.population_mad
                # Floor the standard error: in a near-constant population
                # (MAD ~ 0) even a trivial 1-byte elevation becomes "z=200",
                # which is noise-chasing, not detection. The floor permits
                # meaningful elevations (~15% of the mean) to accumulate.
                sem = max(1.4826 * pop_mad,
                          0.15 * abs(pop_mean)) / (query_count ** 0.5)
                if sem < 1e-9:
                    z_ok = mean_mass > pop_mean
                else:
                    z_ok = (mean_mass - pop_mean) / sem > self.baseline.k
                # Practical significance: statistical significance alone
                # fires on any persistent micro-elevation (seen live on
                # real desktop traffic). A tunnel carries MULTI-BYTE extra
                # payload per query — require both.
                slow_drip = z_ok and (
                    pop_mean <= 1e-9 or mean_mass > config.SESSION_ELEVATION_RATIO * pop_mean)

        cv = interval_cv([t for t, _ in dq])
        intervals = [b - a for a, b in zip([t for t, _ in dq],
                                           [t for t, _ in dq][1:])]
        mean_interval = (sum(intervals) / len(intervals)) if intervals else 0.0
        beacon = (
            query_count >= config.BEACON_MIN_QUERIES
            and cv is not None
            and cv < config.BEACON_MAX_CV
            and mean_interval >= config.BEACON_MIN_INTERVAL_S
        )

        return SessionState(
            src_ip=src_ip,
            query_count=query_count,
            cumulative_mass=cumulative,
            mean_mass=mean_mass,
            window_seconds=self.window_seconds,
            slow_drip_candidate=slow_drip or velocity_flag,
            last_timestamp=timestamp,
            beacon_candidate=beacon or domain_beacon,
            interval_cv=cv,
            velocity_candidate=velocity_flag,
            domain_beacon=domain_beacon,
        )

    def get(self, src_ip: str) -> SessionState | None:
        """Read-only view of a session (no pruning, no baseline update)."""
        with self._lock:
            return self._get_locked(src_ip)

    def _get_locked(self, src_ip):
        dq = self._sessions.get(src_ip)
        if not dq:
            return None
        masses = [m for _, m in dq]
        cumulative = sum(masses)
        return SessionState(
            src_ip=src_ip,
            query_count=len(dq),
            cumulative_mass=cumulative,
            mean_mass=cumulative / len(masses),
            window_seconds=self.window_seconds,
            slow_drip_candidate=False,
            last_timestamp=dq[-1][0],
            beacon_candidate=False,
            interval_cv=interval_cv([t for t, _ in dq]),
        )

    def snapshot(self) -> dict[str, SessionState]:
        with self._lock:
            return {ip: self._get_locked(ip) for ip in self._sessions}

    def update_response(self, src_ip: str, timestamp: float,
                        answer_bytes: int, answer_entropy: float,
                        min_answers: int = 5) -> SessionState:
        """Fold one DNS response into the client session's answer window.

        Flags the session when its mean answer-mass rises >k sigma above
        the learned response population — the download/C2 counterpart of
        the query-side z-test.
        """
        with self._lock:
            return self._update_response_locked(src_ip, timestamp,
                                                answer_bytes, answer_entropy,
                                                min_answers)

    def _update_response_locked(self, src_ip, timestamp, answer_bytes,
                                answer_entropy, min_answers):
        weight = min(max(answer_entropy / config.MAX_LABEL_ENTROPY, 0.0), 1.0)
        mass = answer_bytes * weight
        dq = self._resp_sessions.setdefault(src_ip, deque())
        cutoff = timestamp - self.window_seconds
        while dq and dq[0][0] <= cutoff:
            dq.popleft()
        dq.append((timestamp, mass))
        self.resp_baseline.update(mass)
        resp_flag = False
        if len(dq) >= min_answers and self.resp_baseline.ready:
            mean = sum(m for _, m in dq) / len(dq)
            sem = self.resp_baseline.population_std / (len(dq) ** 0.5)
            if sem < 1e-9:
                resp_flag = mean > self.resp_baseline.population_mean
            else:
                z = (mean - self.resp_baseline.population_mean) / sem
                resp_flag = z > self.resp_baseline.k
        total_mass = sum(m for _, m in dq)
        state = self.get(src_ip) or SessionState(
            src_ip=src_ip, query_count=0, cumulative_mass=0.0, mean_mass=0.0,
            window_seconds=self.window_seconds,
            slow_drip_candidate=False, last_timestamp=timestamp)
        state.resp_answer_bytes = int(total_mass)
        state.resp_flag = resp_flag
        return state


# ---- warm restart (state persistence) ---------------------------------
import json


def save_state(tracker: SessionTracker, path) -> None:
    """Snapshot sessions + baseline so a restart doesn't reset detection."""
    with tracker._lock:
        sessions = {ip: [[t, m] for t, m in dq]
                    for ip, dq in tracker._sessions.items()}
    b = tracker.baseline
    blob = {
        "window_seconds": tracker.window_seconds,
        "sessions": sessions,
        "baseline": None if b is None else {
            "ewma": b._ewma, "n": b._n, "welford_mean": b._welford_mean,
            "welford_m2": b._welford_m2, "alpha": b.alpha, "k": b.k,
            "warmup": b.warmup,
        },
    }
    with open(path, "w") as fh:
        json.dump(blob, fh)


def load_state(tracker: SessionTracker, path) -> bool:
    """Restore a snapshot into an existing tracker (fresh pipeline)."""
    try:
        with open(path) as fh:
            blob = json.load(fh)
    except (OSError, ValueError):
        return False
    tracker._sessions = {ip: __import__("collections").deque(
        (tuple(x) for x in dq)) for ip, dq in blob.get("sessions", {}).items()}
    # (restore happens on a fresh, not-yet-running tracker: no lock needed)
    b = blob.get("baseline")
    if b and tracker.baseline is not None:
        tb = tracker.baseline
        tb._ewma, tb._n = b["ewma"], b["n"]
        tb._welford_mean, tb._welford_m2 = b["welford_mean"], b["welford_m2"]
    return True
