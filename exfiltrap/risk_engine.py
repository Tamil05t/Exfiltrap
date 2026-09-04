"""M7 — Risk engine: the deterministic decision table.

Combines the per-query RF probability (M5), the slow-drip flag (M3) and the
payload-decode outcome (M6) into a single risk level. Pure function of its
inputs — no state, no ML, fully unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exfiltrap import config
from exfiltrap.events import DNSQuery

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CONFIRMED")


@dataclass(frozen=True)
class RiskAssessment:
    """Final verdict for one DNS query."""

    src_ip: str
    qname: str
    timestamp: float
    risk_level: str
    reasons: list[str] = field(default_factory=list)
    rf_probability: float = 0.0
    slow_drip_candidate: bool = False
    confirmed_exfiltration: bool = False
    decoded_preview: str | None = None
    query_index: int = 0


class RiskEngine:
    """Applies the spec's rule table in strict priority order."""

    def __init__(
        self,
        high: float = config.RISK_HIGH_THRESHOLD,
        medium: float = config.RISK_MEDIUM_THRESHOLD,
    ):
        self.high = high
        self.medium = medium

    def assess(
        self,
        query: DNSQuery,
        rf_probability: float,
        slow_drip_candidate: bool,
        decode_result=None,
        query_index: int = 0,
        beacon_candidate: bool = False,
    ) -> RiskAssessment:
        """Rule table (spec Section M7).

        ``decode_result`` is duck-typed (``.success``, ``.decoded``,
        ``.method``) so the engine stays decoupled from M6's concrete type.
        ``beacon_candidate`` (M3b) escalates like slow-drip and adds its own
        reason line so operators can see which stateful signal fired.
        """
        confirmed = decode_result is not None and bool(decode_result.success)
        reasons: list[str] = []
        preview: str | None = None

        if confirmed:
            risk = "CONFIRMED"
            method = getattr(decode_result, "method", None) or "unknown"
            reasons.append(f"payload decoded via {method}")
            decoded = getattr(decode_result, "decoded", None) or b""
            preview = repr(decoded[:40])
        elif rf_probability > self.high:
            risk = "HIGH"
        elif slow_drip_candidate or beacon_candidate:
            risk = "HIGH"
        elif rf_probability > self.medium:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        if rf_probability > self.high:
            reasons.append(f"RF probability {rf_probability:.3f} > {self.high}")
        if slow_drip_candidate:
            reasons.append("stateful slow-drip candidate (entropy-weighted mass)")
        if beacon_candidate:
            reasons.append(
                "beacon regularity: machine-periodic query timing (M3b)"
            )
        if self.medium < rf_probability <= self.high:
            reasons.append(f"RF probability {rf_probability:.3f} > {self.medium}")

        return RiskAssessment(
            src_ip=query.src_ip,
            qname=query.qname,
            timestamp=query.timestamp,
            risk_level=risk,
            reasons=reasons,
            rf_probability=rf_probability,
            slow_drip_candidate=slow_drip_candidate,
            confirmed_exfiltration=confirmed,
            decoded_preview=preview,
            query_index=query_index,
        )
