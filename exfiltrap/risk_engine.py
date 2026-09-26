"""M7 — Risk engine: the deterministic decision table.

Combines the per-query RF probability (M5), the slow-drip flag (M3) and the
payload-decode outcome (M6) into a single risk level. Pure function of its
inputs — no state, no ML, fully unit-testable.

Two provenance distinctions matter downstream (the automated response
reads them — M7 is where the "what should we act on" decision is made
precise):

* ``domain_signal`` — the evidence points at THIS domain specifically
  (M3c domain velocity / per-domain beacon). Only domain-specific
  evidence justifies a domain-level response.
* session-level flags (slow-drip, per-source beacon) describe the SOURCE.
  On a single host the source is the operator's own machine, so they may
  escalate the alert but must never drive a domain sink.

``mitre_tags`` maps a verdict to ATT&CK technique IDs — alerts carry the
mapping so the console and the paper speak the same language.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exfiltrap import config
from exfiltrap.events import DNSQuery

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CONFIRMED")

# MITRE ATT&CK techniques this detector's signals map to. Surfaced on the
# console per alert; the mapping is derived from the firing reasons.
MITRE_BY_SIGNAL = {
    "decode": "T1048.003",   # Exfiltration Over Unencrypted Non-C2 Protocol
    "rf": "T1048.003",
    "slow_drip": "T1048.003",
    "beacon": "T1071.004",   # Application Layer Protocol: DNS
    "domain_velocity": "T1568.002",  # Dynamic Resolution: Domain Generation Algorithms
    "response": "T1048.003",
    "canary": "T1071.004",
    "resolver_bypass": "T1071.004",
}


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
    domain_signal: bool = False   # evidence points at THIS domain, not just the source
    resolver: str = ""            # dst IP the query was sent to
    process: str = ""             # best-effort socket owner
    bypass_resolver: bool = False # query skipped the system resolver

    def mitre_tags(self) -> tuple[str, ...]:
        """ATT&CK technique IDs implied by this verdict's firing signals."""
        tags: list[str] = []
        if self.confirmed_exfiltration:
            tags.append(MITRE_BY_SIGNAL["decode"])
        if self.rf_probability > config.RISK_HIGH_THRESHOLD:
            tags.append(MITRE_BY_SIGNAL["rf"])
        if self.slow_drip_candidate:
            tags.append(MITRE_BY_SIGNAL["slow_drip"])
        if "beacon" in ";".join(self.reasons).lower():
            tags.append(MITRE_BY_SIGNAL["beacon"])
        if self.domain_signal:
            tags.append(MITRE_BY_SIGNAL["domain_velocity"])
        if self.bypass_resolver:
            tags.append(MITRE_BY_SIGNAL["resolver_bypass"])
        # de-duped, order-stable
        return tuple(dict.fromkeys(tags))


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
        domain_signal: bool = False,
        bypass_resolver: bool = False,
    ) -> RiskAssessment:
        """Rule table (spec Section M7).

        ``decode_result`` is duck-typed (``.success``, ``.decoded``,
        ``.method``) so the engine stays decoupled from M6's concrete type.
        ``beacon_candidate`` (M3b) escalates like slow-drip and adds its own
        reason line so operators can see which stateful signal fired.
        ``domain_signal`` marks DOMAIN-level evidence (M3c velocity /
        per-domain beacon) — the response layer sinks a domain only when
        this is set, never on source-level flags alone.
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
        if domain_signal:
            reasons.append(
                "domain-level signal: velocity/per-domain beacon on this "
                "base domain (M3c)"
            )
        if self.medium < rf_probability <= self.high:
            reasons.append(f"RF probability {rf_probability:.3f} > {self.medium}")
        if bypass_resolver:
            reasons.append(
                "resolver bypass: query sent outside the system resolver"
            )

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
            domain_signal=domain_signal,
            resolver=getattr(query, "dst_ip", "") or "",
            process=getattr(query, "process", "") or "",
            bypass_resolver=bypass_resolver,
        )
