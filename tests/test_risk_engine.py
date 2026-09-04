"""Unit tests for M7 — risk engine rule table."""

from types import SimpleNamespace

import pytest

from exfiltrap.events import DNSQuery
from exfiltrap.risk_engine import RiskAssessment, RiskEngine

Q = DNSQuery(src_ip="10.99.0.2", qname="abc.tunnel.example", timestamp=1.0)


def decode(success, decoded=b"payload-bytes-here", method="base32"):
    return SimpleNamespace(success=success, decoded=decoded, method=method)


class TestRuleTable:
    def test_confirmed_wins_over_everything(self):
        eng = RiskEngine()
        a = eng.assess(Q, rf_probability=0.99, slow_drip_candidate=True,
                       decode_result=decode(True))
        assert a.risk_level == "CONFIRMED"
        assert a.confirmed_exfiltration
        assert "payload decoded via base32" in a.reasons

    def test_high_rf(self):
        a = RiskEngine().assess(Q, 0.9, False, None)
        assert a.risk_level == "HIGH"
        assert not a.confirmed_exfiltration

    def test_high_via_slow_drip(self):
        a = RiskEngine().assess(Q, 0.2, True, None)
        assert a.risk_level == "HIGH"
        assert a.slow_drip_candidate
        assert any("slow-drip" in r for r in a.reasons)

    def test_medium_band(self):
        a = RiskEngine().assess(Q, 0.7, False, None)
        assert a.risk_level == "MEDIUM"

    def test_low(self):
        a = RiskEngine().assess(Q, 0.1, False, None)
        assert a.risk_level == "LOW"
        assert a.reasons == []

    def test_failed_decode_does_not_confirm(self):
        a = RiskEngine().assess(Q, 0.9, True, decode(False, decoded=None, method=None))
        assert a.risk_level == "HIGH"  # falls through to RF/slow-drip rules
        assert not a.confirmed_exfiltration
        assert a.decoded_preview is None


class TestBoundaries:
    def test_strict_inequality_at_high(self):
        eng = RiskEngine(high=0.85)
        assert eng.assess(Q, 0.85, False, None).risk_level == "MEDIUM"
        assert eng.assess(Q, 0.85000001, False, None).risk_level == "HIGH"

    def test_strict_inequality_at_medium(self):
        eng = RiskEngine(medium=0.60)
        assert eng.assess(Q, 0.60, False, None).risk_level == "LOW"
        assert eng.assess(Q, 0.60000001, False, None).risk_level == "MEDIUM"

    def test_rf_zero_with_slow_drip_still_high(self):
        assert RiskEngine().assess(Q, 0.0, True, None).risk_level == "HIGH"


class TestPayloadPlumbing:
    def test_preview_truncated(self):
        long_payload = bytes(range(32, 96)) * 4  # 256 printable bytes
        a = RiskEngine().assess(Q, 0.99, False, decode(True, decoded=long_payload))
        assert a.decoded_preview is not None
        assert len(a.decoded_preview) <= 45  # repr of 40 bytes

    def test_query_fields_carried_through(self):
        a = RiskEngine().assess(Q, 0.1, False, None, query_index=7)
        assert a.src_ip == "10.99.0.2"
        assert a.qname == "abc.tunnel.example"
        assert a.timestamp == 1.0
        assert a.query_index == 7
        assert a.rf_probability == 0.1

    def test_assessment_is_frozen(self):
        a = RiskEngine().assess(Q, 0.1, False, None)
        with pytest.raises(Exception):
            a.risk_level = "CONFIRMED"
