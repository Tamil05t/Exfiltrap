"""M2 — Feature extraction.

Per DNS query we compute the base paper's four features plus the label
metadata the stateful modules need:

* Shannon entropy of the leftmost label
* total domain length
* subdomain (label) count
* 60-second query frequency for the same base domain
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass

from exfiltrap import config


def shannon_entropy(s: str) -> float:
    """Shannon entropy H(x) = -sum(p(xi) * log2(p(xi))) over characters.

    Empty input has no uncertainty: 0.0 bits.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    # "+ 0.0" normalizes the -0.0 that a uniform single-symbol label produces.
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) + 0.0


def _strip_trailing_dot(qname: str) -> str:
    return qname[:-1] if qname.endswith(".") else qname


def leftmost_label(qname: str) -> str:
    """Text before the first dot of the (dot-stripped) qname."""
    return _strip_trailing_dot(qname).split(".", 1)[0]


def base_domain(qname: str) -> str:
    """Registrable-ish part of the qname: the last two labels.

    # ASSUMPTION: simple last-two-labels rule without a public-suffix list,
    # so "a.b.example.co.uk" yields "co.uk". Consistent everywhere in the
    # project, which is what matters for frequency baselines.
    """
    labels = _strip_trailing_dot(qname).split(".")
    if len(labels) <= 2:
        return _strip_trailing_dot(qname)
    return ".".join(labels[-2:])


@dataclass(frozen=True)
class FeatureVector:
    """The per-query feature set consumed by M5/M3 and logging."""

    entropy: float
    length: int
    subdomain_count: int
    frequency: float
    leftmost_label: str
    base_domain: str
    qname: str
    timestamp: float


class FeatureExtractor:
    """Stateful extractor that also tracks 60s per-base-domain frequency."""

    def __init__(self, frequency_window: float = config.FREQUENCY_WINDOW_SECONDS):
        self.frequency_window = frequency_window
        self._domains: dict[str, deque[float]] = {}

    def extract(self, qname: str, timestamp: float) -> FeatureVector:
        clean = _strip_trailing_dot(qname)
        labels = clean.split(".")
        label = labels[0]
        domain = base_domain(qname)
        subdomain_count = max(len(labels) - 2, 0)

        freq = self._bump_frequency(domain, timestamp)

        return FeatureVector(
            entropy=shannon_entropy(label),
            length=len(clean),
            subdomain_count=subdomain_count,
            frequency=freq,
            leftmost_label=label,
            base_domain=domain,
            qname=qname,
            timestamp=timestamp,
        )

    def _bump_frequency(self, domain: str, timestamp: float) -> float:
        """Record this query and count same-domain queries inside the window.

        Older timestamps are pruned on the way in so the deques stay small.
        """
        dq = self._domains.setdefault(domain, deque())
        cutoff = timestamp - self.frequency_window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        dq.append(timestamp)
        return float(len(dq))


def extract_static(qname: str) -> FeatureVector:
    """ Stateless variant for training-set construction (frequency = 0)."""
    extractor = FeatureExtractor()
    vec = extractor.extract(qname, 0.0)
    # The bump above counted this very query against a fresh deque -> 1.0;
    # static rows carry no frequency information by contract.
    return FeatureVector(
        entropy=vec.entropy,
        length=vec.length,
        subdomain_count=vec.subdomain_count,
        frequency=0.0,
        leftmost_label=vec.leftmost_label,
        base_domain=vec.base_domain,
        qname=qname,
        timestamp=0.0,
    )
