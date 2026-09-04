"""Tests for the response (download/C2) channel."""

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from exfiltrap.capture import _classify, packet_to_query, packet_to_response
from exfiltrap.events import DNSQuery, DNSResponse
from exfiltrap.pipeline import ExfilTrapPipeline
from exfiltrap.storage import Storage


def dns_response(qname="cmd123.tunnel.example", txt=b"JBSWY3DPEB3W64TQ",
                dst="10.99.0.2", src="10.99.0.1"):
    return IP(src=src, dst=dst) / UDP(sport=53, dport=40000) / DNS(
        qr=1, qd=DNSQR(qname=qname),
        an=DNSRR(rrname=qname, type="TXT", rdata=txt))


class TestCaptureParsing:
    def test_response_parsed(self):
        r = packet_to_response(dns_response())
        assert isinstance(r, DNSResponse)
        assert r.client_ip == "10.99.0.2"  # destination = the client
        assert r.answer_count == 1
        assert 10 <= r.answer_bytes <= 64  # TXT rdata (scapy-encoded)
        assert r.answer_entropy > 3.0  # encoded C2 payload

    def test_query_not_a_response(self):
        q = packet_to_response(IP() / UDP() / DNS(rd=1, qd=DNSQR(qname="a.b")))
        assert q is None

    def test_classify_routes_both_kinds(self):
        assert isinstance(_classify(dns_response()), DNSResponse)
        assert isinstance(_classify(
            IP(src="10.99.0.2") / UDP(sport=40000, dport=53) / DNS(
                rd=1, qd=DNSQR(qname="a.b"))), DNSQuery)


class TestSessionResponses:
    def test_heavy_answers_flag_session(self):
        p = ExfilTrapPipeline(classifier=_Stub(), storage=_Null())
        # benign population: small low-entropy answers
        for i in range(40):
            p.tracker.update_response("c1", i * 5.0, 40, 1.0)
        # C2 client: 300-byte near-ceiling-entropy TXT answers
        flagged = False
        benign_last = None
        for i in range(40, 60):
            st = p.tracker.update_response("c2", i * 5.0, 300, 4.8)
            flagged = flagged or st.resp_flag
            benign_last = p.tracker.update_response("c1", i * 5.0, 40, 1.0)
        assert flagged, "sustained heavy answers must flag the session"
        # benign session stays clean
        assert benign_last.resp_flag is False

    def test_pipeline_emits_risk_event(self, tmp_path):
        store = Storage(tmp_path / "r.db")
        p = ExfilTrapPipeline(classifier=_Stub(), storage=store)
        for i in range(40):
            p.process_response(_resp("10.1.1.1", i * 5.0, 40, 1.0))
        hits = [p.process_response(_resp("10.2.2.2", 200 + i * 5.0, 300, 4.8))
                for i in range(20)]
        assert any(h is not None for h in hits)
        store.recent_events(1)  # flush
        ev = store.recent_events(10)
        assert any("response channel" in e["reasons"] for e in ev)
        # responses never pollute the per-query metrics table
        assert store.totals()["queries"] == 0
        store.close()


class _Stub:
    def predict_proba(self, f):
        return 0.02


class _Null:
    def log_query(self, a): ...
    def log_risk_event(self, a): ...
    def log_block(self, *a): ...
    def totals(self):
        return {"queries": 0, "flagged": 0, "confirmed": 0, "blocked": 0}


def _resp(ip, ts, nbytes, entropy):
    return DNSResponse(client_ip=ip, qname="x.tunnel.example", timestamp=ts,
                       answer_count=1, answer_bytes=nbytes,
                       answer_entropy=entropy)
