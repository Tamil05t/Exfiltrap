"""Tests for the research-upgrade signals (GitHub survey round, v1.6).

Every test maps to a finding from reading peer/attack-tool repositories:
iodine's 4s default ping evading the 5s beacon gate, iodine's NULL/PRIVATE
record types, dnscat2's TXT/MX/CNAME preference, the ibHH unique-label
cardinality approach (Akamai NDSS'24), NXDOMAIN-ratio detection, DNS over
TCP blindness, DoH visibility gaps and 0x20 case channels.
"""

import pytest

from exfiltrap.events import DNSQuery, DNSResponse


# ---------------------------------------------------------------------------
# capture: TCP/53 + qtype + rcode
# ---------------------------------------------------------------------------

class TestCaptureWireUpgrades:
    def test_tcp_dns_query_parsed(self):
        scapy = pytest.importorskip("scapy.all")
        from exfiltrap.capture import packet_to_query

        msg = scapy.DNS(rd=1, qd=scapy.DNSQR(qname=b"d13fd2.t6.example",
                                             qtype="TXT"))
        # DNS over TCP: 2-byte length prefix, then the message
        payload = len(bytes(msg)).to_bytes(2, "big") + bytes(msg)
        pkt = (scapy.IP(src="10.0.0.9", dst="1.2.3.4") /
               scapy.TCP(sport=51000, dport=53, flags="PA") / payload)
        q = packet_to_query(pkt)
        assert q is not None, "DNS over TCP must be parsed, not dropped"
        assert q.qname == "d13fd2.t6.example"
        assert q.qtype == 16

    def test_query_carries_qtype(self):
        scapy = pytest.importorskip("scapy.all")
        from exfiltrap.capture import packet_to_query

        pkt = (scapy.IP(src="10.0.0.9", dst="1.2.3.4") /
               scapy.UDP(sport=53001, dport=53) /
               scapy.DNS(rd=1, qd=scapy.DNSQR(qname=b"x.example",
                                              qtype="NULL")))
        q = packet_to_query(pkt)
        assert q.qtype == 10

    def test_nxdomain_response_kept_with_rcode(self):
        scapy = pytest.importorskip("scapy.all")
        from exfiltrap.capture import packet_to_response

        pkt = (scapy.IP(src="1.2.3.4", dst="10.0.0.9") /
               scapy.UDP(sport=53, dport=53002) /
               scapy.DNS(qr=1, rcode=3,
                         qd=scapy.DNSQR(qname=b"nope.fake-zone.example")))
        r = packet_to_response(pkt)
        assert r is not None, "rcode-only answers must reach the tracker"
        assert r.rcode == 3
        assert r.answer_count == 0


# ---------------------------------------------------------------------------
# tracker: fast beacon (iodine default 4s), cardinality velocity, qtype mix
# ---------------------------------------------------------------------------

def _entropy_of(s):
    from exfiltrap.features import shannon_entropy

    return shannon_entropy(s)


class TestFastBeacon:
    def _tracker(self):
        from exfiltrap.session_tracker import SessionTracker

        return SessionTracker()

    def test_iodine_default_4s_metronome_high_entropy_fires(self):
        tr = self._tracker()
        # iodine default: -I 4s ping with fresh high-entropy labels
        for i in range(24):
            state = tr.update("10.0.0.9", 1000.0 + i * 4.0, 60.0, 4.2,
                              qname=f"lbl{i}kq7zd.t6.example", qtype=10)
        assert state.domain_beacon is True, \
            "default-config iodine (4s) must trip the domain beacon"

    def test_4s_metronome_low_entropy_stays_quiet(self):
        tr = self._tracker()
        # benign fast keepalive: same-shaped low-entropy labels
        for i in range(24):
            state = tr.update("10.0.0.9", 1000.0 + i * 4.0, 10.0, 1.1,
                              qname="keepalive.example")
        assert state.domain_beacon is False

    def test_cardinality_velocity_catches_lexical_tunnel(self):
        tr = self._tracker()
        # Al Musa '26-style phonotactic channel: human-looking words,
        # LOW entropy, high DISTINCT-label cardinality under one domain
        words = ["upload", "secret", "backup", "camera", "mic-01", "vault",
                 "media", "docs-db", "keys", "wallet", "notes", "photo",
                 "recording", "final"]
        for i, w in enumerate(words):
            state = tr.update("10.0.0.9", 1000.0 + i, 40.0, 1.6,
                              qname=f"{w}.exfil.example")
        assert state.velocity_candidate is True, \
            "many DISTINCT low-entropy labels under one domain must fire"

    def test_cardinality_path_skips_popular_domains(self):
        tr = self._tracker()
        from exfiltrap import reputation

        reputation.reload()
        try:
            for i in range(15):
                state = tr.update("10.0.0.9", 1000.0 + i, 40.0, 1.6,
                                  qname=f"img-{i}.gstatic.com")
            assert state.velocity_candidate is False, \
                "CDN label churn must not look like a lexical tunnel"
        finally:
            pass

    def test_qtype_mix_ratio_fires(self):
        tr = self._tracker()
        for i in range(10):
            tr.update("10.0.0.9", 1000.0 + i, 40.0, 1.6,
                      qname=f"a{i}.relay.example", qtype=16)
        for i in range(3):
            state = tr.update("10.0.0.9", 1010.0 + i, 40.0, 1.6,
                              qname=f"b{i}.relay.example", qtype=1)
        assert state.qtype_mix_candidate is True

    def test_nxdomain_ratio_tracker(self):
        tr = self._tracker()
        for i in range(5):
            tr.update_response("10.0.0.9", 1000.0 + i, 0.0, 0.0,
                               rcode=3, qname=f"x{i}.dead.example")
        ratio, n = tr.domain_nxdomain_ratio("10.0.0.9", "y.dead.example")
        assert n == 5 and ratio == 1.0


# ---------------------------------------------------------------------------
# pipeline: wire-signal floors
# ---------------------------------------------------------------------------

class _StubClassifier:
    def predict_proba(self, f):
        return 0.02


def _pipeline():
    from exfiltrap.pipeline import ExfilTrapPipeline

    return ExfilTrapPipeline(classifier=_StubClassifier(),
                             storage=__import__("exfiltrap.storage",
                                                fromlist=["NullStorage"]).NullStorage())


class TestPipelineWireSignals:
    def test_null_qtype_floors_to_high(self):
        p = _pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "abc123.t6.example",
                                     1000.0, qtype=10))
        assert a.risk_level == "HIGH"
        assert any("NULL" in r or "tunnel-grade" in r for r in a.reasons)

    def test_iodine_private_class_floors_to_high(self):
        p = _pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "abc123.t6.example",
                                     1000.0, qtype=65399))
        assert a.risk_level == "HIGH"

    def test_txt_query_alone_stays_low(self):
        # per-query TXT must NOT escalate (SPF/DKIM/ACME are TXT-heavy)
        p = _pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "mail.example",
                                     1000.0, qtype=16))
        assert a.risk_level == "LOW"

    def test_malformed_label_floors_to_medium(self):
        p = _pipeline()
        big = "a" * 70 + ".example"
        a = p.process_query(DNSQuery("10.99.0.2", big, 1000.0))
        assert a.risk_level == "MEDIUM"
        assert any("malformed" in r for r in a.reasons)

    def test_doh_bootstrap_tagged_not_escalated(self):
        p = _pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "dns.google",
                                     1000.0, dst_ip="127.0.0.53"))
        assert a.risk_level == "LOW"
        assert any("INVISIBLE" in r for r in a.reasons)

    def test_case_channel_repetition_floors_to_medium(self):
        p = _pipeline()
        for i, name in enumerate(["Upload.Data.example",
                                  "UPLOAD.DATA.example",
                                  "upload.data.Example"]):
            a = p.process_query(DNSQuery("10.99.0.2", name, 1000.0 + i))
        assert a.risk_level == "MEDIUM"
        assert any("case" in r.lower() for r in a.reasons)

    def test_sinkhole_escalates_on_tunnel_qtype_strikes(self, tmp_path):
        """qtype evidence is domain-specific: 3 NULL-type strikes on a base
        domain must convict it (with the safe sinkhole semantics)."""
        from exfiltrap.mitigation import DomainSinkhole, LogOnlyMitigation
        from exfiltrap.policy import make_policy
        from exfiltrap.pipeline import ExfilTrapPipeline

        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        sink = DomainSinkhole(hosts_path=str(hosts), ttl=600.0, strikes=3)
        pol = make_policy(LogOnlyMitigation(), sinkhole=sink,
                          own_ips=("10.0.0.5",))
        p = ExfilTrapPipeline(classifier=_StubClassifier(),
                              mitigation=pol,
                              storage=__import__("exfiltrap.storage",
                                                 fromlist=["NullStorage"]).NullStorage())
        for i in range(3):
            a = p.process_query(DNSQuery("10.0.0.5",
                                         f"s{i}.tunnel.attacker.example",
                                         1000.0 + i, qtype=10))
        assert a.risk_level == "HIGH"
        assert sink.is_sunk("s3.tunnel.attacker.example"), \
            "tunnel-grade qtypes are domain evidence and must feed the sink"
        assert "0.0.0.0 attacker.example" in hosts.read_text()
