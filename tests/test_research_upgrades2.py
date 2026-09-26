"""Tests for research-upgrade round 2 (bounded windows, cache flush,
hex-cluster + label-churn signals, pcap replay)."""

import pytest

from exfiltrap.events import DNSQuery, DNSResponse


class _StubClassifier:
    def predict_proba(self, f):
        return 0.02


def _pipeline():
    from exfiltrap.pipeline import ExfilTrapPipeline

    return ExfilTrapPipeline(classifier=_StubClassifier(),
                             storage=__import__("exfiltrap.storage",
                                                fromlist=["NullStorage"]).NullStorage())


class TestBoundedWindows:
    def test_domain_window_hard_cap(self):
        """A sustained unique-label flood must not grow the per-domain
        window without bound (the label string per tuple used to amplify
        memory 4x with no ceiling)."""
        from exfiltrap import config
        from exfiltrap.session_tracker import SessionTracker

        tr = SessionTracker()
        for i in range(config.DOMAIN_WINDOW_HARD_CAP + 500):
            tr.update("10.0.0.9", 1000.0 + i * 0.001, 40.0, 3.5,
                      qname=f"l{i}abcdef.t6.example")
        with tr._lock:
            dq2 = tr._domain_times[("10.0.0.9", "t6.example")]
        assert len(dq2) <= config.DOMAIN_WINDOW_HARD_CAP

    def test_hashed_labels_keep_cardinality(self):
        from exfiltrap.session_tracker import SessionTracker

        tr = SessionTracker()
        for i in range(14):
            state = tr.update("10.0.0.9", 1000.0 + i, 40.0, 1.5,
                              qname=f"word{i}.exfil.example")
        assert state.velocity_candidate is True


class TestHexClusterSignal:
    def test_hex_a_queries_cluster_flags(self):
        p = _pipeline()
        for i in range(4):
            a = p.process_query(DNSQuery(
                "10.99.0.2", f"a1b2c3d{i:02x}".replace("d", "d")[:8] + "f"
                if False else f"a1b2c3d{i}f01.c2beacon.example",
                1000.0 + i, qtype=1))
        assert a.risk_level == "MEDIUM"
        assert any("hex-labeled" in r for r in a.reasons)

    def test_hex_cluster_skips_popular_domains(self):
        p = _pipeline()
        from exfiltrap import reputation

        reputation.reload()
        for i in range(5):
            a = p.process_query(DNSQuery(
                "10.99.0.2", f"a1b2c3d{i}e5.img.gstatic.com",
                1000.0 + i, qtype=1))
        assert a.risk_level == "LOW"

    def test_two_hex_queries_below_threshold(self):
        p = _pipeline()
        for i in range(2):
            a = p.process_query(DNSQuery(
                "10.99.0.2", f"a1b2c3d{i}f01.c2beacon.example",
                1000.0 + i, qtype=1))
        assert a.risk_level == "LOW"


class TestLabelChurnSignal:
    def test_slow_unique_label_churn_flags(self):
        """Slow lexical tunnel: labels spaced beyond the 60s velocity
        window, but the session window shows ~no repeats."""
        p = _pipeline()
        for i in range(32):
            a = p.process_query(DNSQuery(
                "10.99.0.2", f"word{i}uniq.exfil.example",
                1000.0 + i * 65.0))
        assert any("label churn" in r for r in a.reasons)

    def test_repetitive_traffic_no_churn_flag(self):
        p = _pipeline()
        for i in range(35):
            a = p.process_query(DNSQuery(
                "10.99.0.2", "mail.example", 1000.0 + i * 65.0))
        assert not any("label churn" in r for r in a.reasons)


class TestSinkholeCacheFlush:
    def test_flush_attempted_on_sink_and_throttled(self, tmp_path,
                                                   monkeypatch):
        from exfiltrap.mitigation import DomainSinkhole

        calls = []

        def fake_run(argv, capture_output, timeout):
            calls.append(argv)
            class R:
                returncode = 0
            return R()

        monkeypatch.setattr("subprocess.run", fake_run)
        DomainSinkhole._last_flush = 0.0
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        sn = DomainSinkhole(hosts_path=str(hosts), ttl=600.0)
        sn.block_domain("a.evil.example")
        sn.block_domain("b.evil.example")   # second sink inside throttle
        assert len(calls) == 1, "flush is throttled to one per 5s"
        assert calls[0][0] in ("resolvectl", "systemd-resolve")

    def test_flush_failure_swallowed(self, tmp_path, monkeypatch):
        from exfiltrap.mitigation import DomainSinkhole

        def boom(*a, **k):
            raise OSError("no resolvectl")

        monkeypatch.setattr("subprocess.run", boom)
        DomainSinkhole._last_flush = 0.0
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        sn = DomainSinkhole(hosts_path=str(hosts), ttl=600.0)
        assert sn.block_domain("a.evil.example") is True
        assert "a.evil.example" in hosts.read_text()


class TestPcapReplay:
    def test_replay_tool_end_to_end(self, tmp_path):
        scapy = pytest.importorskip("scapy.all")
        import importlib.util
        from pathlib import Path as _Path

        tool_path = _Path(__file__).resolve().parent.parent / "tools" / "replay_pcap.py"
        spec = importlib.util.spec_from_file_location("replay_pcap", tool_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        pcap = tmp_path / "mini.pcap"
        pkts = []
        for i, chunk in enumerate(["aGFsbG8", "d29ybGQ", "ZXhmaWw"]):
            qname = f"{chunk.ljust(8, 'a')}.tunnel.example".encode()
            pkts.append(scapy.IP(src="10.99.0.2", dst="10.99.0.1") /
                        scapy.UDP(sport=40000 + i, dport=53) /
                        scapy.DNS(id=i, rd=1, qd=scapy.DNSQR(qname=qname)))
        # one benign query
        pkts.append(scapy.IP(src="10.99.0.2", dst="10.99.0.1") /
                    scapy.UDP(sport=40010, dport=53) /
                    scapy.DNS(id=99, rd=1,
                              qd=scapy.DNSQR(qname=b"www.example.com")))
        scapy.wrpcap(str(pcap), pkts)

        assert mod.main([str(pcap)]) == 0
