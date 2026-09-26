"""Tests for the attribution + new-response features (v1.5.0).

Covers: packet context capture (resolver / sport / answer IPs), process
attribution parsing, canary trap domains, resolver-bypass signal, and the
MITRE ATT&CK mapping.
"""

from types import SimpleNamespace

import pytest

from exfiltrap.events import DNSQuery, DNSResponse


# ---------------------------------------------------------------------------
# capture: packet context
# ---------------------------------------------------------------------------

def _dns_query_pkt(qname=b"evil.tunnel.example", src="127.0.0.1",
                   dst="127.0.0.53", sport=53511):
    scapy = pytest.importorskip("scapy.all")
    return (scapy.IP(src=src, dst=dst) /
            scapy.UDP(sport=sport, dport=53) /
            scapy.DNS(rd=1, qd=scapy.DNSQR(qname=qname)))


def _dns_response_pkt(qname=b"evil.tunnel.example", a_ip="6.6.6.6",
                      txt=b"AAAAAAAA"):
    scapy = pytest.importorskip("scapy.all")
    return (scapy.IP(src="1.2.3.4", dst="10.0.0.5") /
            scapy.UDP(sport=53, dport=53511) /
            scapy.DNS(qr=1, qd=scapy.DNSQR(qname=qname),
                      an=[scapy.DNSRR(rrname=qname, type="A", rdata=a_ip),
                          scapy.DNSRR(rrname=qname, type="TXT", rdata=txt)]))


class TestCaptureContext:
    def test_query_carries_resolver_and_sport(self):
        from exfiltrap.capture import packet_to_query

        q = packet_to_query(_dns_query_pkt())
        assert q is not None
        assert q.src_ip == "127.0.0.1"
        assert q.dst_ip == "127.0.0.53"
        assert q.sport == 53511
        assert q.qname == "evil.tunnel.example"

    def test_response_carries_resolver_and_answer_ips(self):
        from exfiltrap.capture import packet_to_response

        r = packet_to_response(_dns_response_pkt())
        assert r is not None
        assert r.resolver_ip == "1.2.3.4"
        assert r.client_ip == "10.0.0.5"
        assert "6.6.6.6" in r.answer_ips

    def test_synthetic_events_still_construct(self):
        # generators/eval build the plain 3-arg form: defaults must hold
        q = DNSQuery("10.99.0.2", "x.example", 1.0)
        assert q.dst_ip == "" and q.sport == 0 and q.process == ""


# ---------------------------------------------------------------------------
# procattr: /proc parsing (fixture text, no live /proc dependence)
# ---------------------------------------------------------------------------

class TestProcattrParsing:
    def test_hex_ipv4(self):
        from exfiltrap.procattr import _hex_ipv4

        assert _hex_ipv4("0100007F") == "127.0.0.1"
        assert _hex_ipv4("0A00000A") == "10.0.0.10"

    def test_hex_ipv6(self):
        from exfiltrap.procattr import _hex_ipv6

        # ::1 loopback in /proc/net/udp6 form (four LE u32 words)
        assert _hex_ipv6("00000000000000000000000001000000") == "::1"

    def test_read_udp_tables_from_fixture(self, tmp_path, monkeypatch):
        import exfiltrap.procattr as pa

        table = tmp_path / "udp"
        # local 127.0.0.1:53511 -> inode 25156
        table.write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue"
            " tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:D107 00000000:0000 07 00000000:00000000"
            " 00:00000000 00000000     0        0 25156 1\n")
        monkeypatch.setattr(pa, "_UDP_TABLES", (str(table),))
        out = pa._read_udp_tables()
        assert out[("127.0.0.1", 53511)] == 25156

    def test_resolve_is_safe_on_garbage(self):
        from exfiltrap.procattr import resolve

        assert resolve("", 0) is None
        assert resolve("127.0.0.1", 0) is None
        # an almost-certainly-unbound port: None, never an exception
        assert resolve("127.0.0.1", 59999) is None


# ---------------------------------------------------------------------------
# canary traps
# ---------------------------------------------------------------------------

class _StubClassifier:
    def predict_proba(self, f):
        return 0.02


class TestCanary:
    def _pipeline(self):
        from exfiltrap.pipeline import ExfilTrapPipeline

        return ExfilTrapPipeline(classifier=_StubClassifier(),
                                 storage=__import__("exfiltrap.storage",
                                                    fromlist=["NullStorage"]).NullStorage())

    def test_canary_hit_is_confirmed(self):
        p = self._pipeline()
        p.set_canary_domains(["trap1.canary.exfiltrap.sensor"])
        a = p.process_query(DNSQuery("127.0.0.1",
                                     "trap1.canary.exfiltrap.sensor", 1.0))
        assert a.risk_level == "CONFIRMED"
        assert a.confirmed_exfiltration is True
        assert any("canary" in r for r in a.reasons)

    def test_canary_subdomain_matches(self):
        p = self._pipeline()
        p.set_canary_domains(["trap.canary.example"])
        a = p.process_query(DNSQuery("127.0.0.1",
                                     "x.trap.canary.example", 1.0))
        assert a.risk_level == "CONFIRMED"

    def test_normal_domain_unaffected(self):
        p = self._pipeline()
        p.set_canary_domains(["trap.canary.example"])
        a = p.process_query(DNSQuery("127.0.0.1", "example.com", 1.0))
        assert a.risk_level != "CONFIRMED"
        assert not any("canary" in r for r in a.reasons)


# ---------------------------------------------------------------------------
# resolver-bypass signal
# ---------------------------------------------------------------------------

class TestResolverBypass:
    def _pipeline(self, resolvers=("127.0.0.53",)):
        from exfiltrap.pipeline import ExfilTrapPipeline

        p = ExfilTrapPipeline(classifier=_StubClassifier(),
                              storage=__import__("exfiltrap.storage",
                                                 fromlist=["NullStorage"]).NullStorage())
        p.set_system_resolvers(resolvers)
        return p

    def test_public_resolver_query_flagged(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.0.0.5", "data.example", 1.0,
                                     dst_ip="8.8.8.8", sport=40001))
        assert a.bypass_resolver is True
        assert a.risk_level in ("MEDIUM", "HIGH", "CONFIRMED")

    def test_stub_resolver_query_clean(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.0.0.5", "data.example", 1.0,
                                     dst_ip="127.0.0.53", sport=40002))
        assert a.bypass_resolver is False

    def test_no_stub_configured_signal_disabled(self):
        # no loopback resolver known: never guess (uplink query may be the
        # stub's own forwarder)
        p = self._pipeline(resolvers=("10.0.0.1",))
        a = p.process_query(DNSQuery("10.0.0.5", "data.example", 1.0,
                                     dst_ip="8.8.8.8", sport=40003))
        assert a.bypass_resolver is False

    def test_private_destination_not_flagged(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.0.0.5", "data.example", 1.0,
                                     dst_ip="192.168.1.1", sport=40004))
        assert a.bypass_resolver is False


# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------

class TestMitreTags:
    def test_confirmed_decode_maps_to_t1048(self):
        from exfiltrap.risk_engine import RiskAssessment

        a = RiskAssessment(src_ip="x", qname="q", timestamp=0.0,
                           risk_level="CONFIRMED", rf_probability=0.9,
                           confirmed_exfiltration=True)
        assert "T1048.003" in a.mitre_tags()

    def test_beacon_maps_to_t1071(self):
        from exfiltrap.risk_engine import RiskAssessment

        a = RiskAssessment(src_ip="x", qname="q", timestamp=0.0,
                           risk_level="HIGH",
                           reasons=["beacon regularity: machine-periodic"])
        assert "T1071.004" in a.mitre_tags()

    def test_domain_velocity_maps_to_dga(self):
        from exfiltrap.risk_engine import RiskAssessment

        a = RiskAssessment(src_ip="x", qname="q", timestamp=0.0,
                           risk_level="HIGH", domain_signal=True)
        assert "T1568.002" in a.mitre_tags()

    def test_low_verdict_no_tags(self):
        from exfiltrap.risk_engine import RiskAssessment

        a = RiskAssessment(src_ip="x", qname="q", timestamp=0.0,
                           risk_level="LOW", rf_probability=0.1)
        assert a.mitre_tags() == ()


# ---------------------------------------------------------------------------
# reputation guard
# ---------------------------------------------------------------------------

class TestReputation:
    def test_popular_base_and_full_qname(self):
        from exfiltrap import reputation

        reputation.reload()  # the shipped Tranco sample
        assert reputation.is_popular("google.com") is True
        assert reputation.is_popular("accounts.google.com") is True
        assert reputation.is_popular("random.foo.microsoft.com") is True
        assert reputation.is_popular("evil.tunnel.example") is False

    def test_builtin_survives_missing_csv(self, tmp_path):
        from exfiltrap import reputation

        reputation.reload(path=str(tmp_path / "missing.csv"))
        try:
            assert reputation.is_popular("google.com") is True
            assert reputation.is_popular("localhost") is True
            assert reputation.is_popular("x.in-addr.arpa") is True
        finally:
            reputation.reload()  # restore the corpus for other tests
