"""M2 — Feature extraction.

Per DNS query we compute the base paper's four features plus the label
metadata the stateful modules need:

* Shannon entropy of the leftmost label
* total domain length
* subdomain (label) count
* 60-second query frequency for the same base domain

v2.0 adds the two character-pattern features the peer detectors found to
carry the most signal beyond entropy, computed against a reference built
from the shipped Tranco corpus (real DNS-domain statistics, offline):

* n-gram deviation — share of the leftmost label's trigrams that are NOT
  attested in real domain behavior. Encoded/random payloads trigram
  differently from every legitimate domain; lexical (word-based) tunnels
  that defeat entropy land here instead.
* digit ratio — digit characters over label length. Encoded payloads
  carry digits at rates real names never do.

FEATURE_ORDER is the single source of truth for the classifier's column
order — training, inference and the batched live path all read it.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass

from exfiltrap import config

# Canonical column order for the classifier (v2.0). The first four are the
# base paper's features, kept first so v1 vs v2 comparisons stay aligned.
FEATURE_ORDER = ("entropy", "length", "subdomain_count", "frequency",
                 "ngram_deviation", "digit_ratio")

_NGRAM_N = 3


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
    ngram_deviation: float = 0.0
    digit_ratio: float = 0.0

    def row(self) -> list[float]:
        """Feature values in canonical FEATURE_ORDER (classifier columns)."""
        return [float(self.entropy), float(self.length),
                float(self.subdomain_count), float(self.frequency),
                float(self.ngram_deviation), float(self.digit_ratio)]


class FeatureExtractor:
    """Stateful extractor that also tracks 60s per-base-domain frequency.

    The trigram reference (real-domain letter statistics) is built lazily
    from the Tranco corpus on first use and cached for the process —
    training and live inference share the exact same reference, and a
    missing corpus degrades BOTH paths to the same fallback set.
    """

    _reference: frozenset[str] | None = None

    def __init__(self, frequency_window: float = config.FREQUENCY_WINDOW_SECONDS):
        self.frequency_window = frequency_window
        self._domains: dict[str, deque[float]] = {}

    # -- trigram reference --------------------------------------------------
    @classmethod
    def _trigram_reference(cls) -> frozenset[str]:
        if cls._reference is not None:
            return cls._reference
        counts: Counter[str] = Counter()
        try:
            import csv as _csv

            with open(config.TRANCO_CSV, newline="", encoding="utf-8",
                      errors="replace") as fh:
                for row in _csv.reader(fh):
                    if len(row) < 2 or not row[1].strip():
                        continue
                    domain = row[1].strip().lower()
                    for i in range(len(domain) - _NGRAM_N + 1):
                        counts[domain[i:i + _NGRAM_N]] += 1
        except OSError:
            pass
        if counts:
            common = frozenset(g for g, c in counts.items()
                               if c >= config.NGRAM_MIN_CORPUS_COUNT)
        else:
            common = frozenset(config.NGRAM_FALLBACK_COMMON)
        cls._reference = common
        return common

    def _ngram_deviation(self, label: str) -> float:
        """Share of the label's trigrams missing from real-domain behavior.

        Applies to the lowercased LEFTMOST label — the payload carrier —
        consistently with the entropy feature. [0, 1]; 0.0 for labels too
        short to form a trigram.
        """
        clean = "".join(c for c in label.lower() if c.isalnum())
        grams = [clean[i:i + _NGRAM_N]
                 for i in range(len(clean) - _NGRAM_N + 1)]
        if not grams:
            return 0.0
        common = self._trigram_reference()
        return sum(1 for g in grams if g not in common) / len(grams)

    @staticmethod
    def _digit_ratio(label: str) -> float:
        if not label:
            return 0.0
        return sum(c.isdigit() for c in label) / len(label)

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
            ngram_deviation=self._ngram_deviation(label),
            digit_ratio=self._digit_ratio(label),
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
        qname=vec.qname,
        timestamp=0.0,
        ngram_deviation=vec.ngram_deviation,
        digit_ratio=vec.digit_ratio,
    )
