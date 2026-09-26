"""Tests for the final deep-audit round: header anomalies, A/AAAA dedupe,
and sink-TTL persistence across restarts."""

import time

import pytest

from exfiltrap.events import DNSQuery


class TestHeaderAnomalies:
    def _pipeline(self):
        from exfiltrap.pipeline import ExfilTrapPipeline

        class _Stub:
            def predict_proba(self, f):
                return 0.02

        from exfiltrap.storage import NullStorage

        return ExfilTrapPipeline(classifier=_Stub(), storage=NullStorage())

    def test_multiple_questions_flagged(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "x.example", 1.0,
                                     qdcount=3))
        assert a.risk_level == "MEDIUM"
        assert any("qdcount=3" in r for r in a.reasons)

    def test_non_query_opcode_flagged(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "x.example", 1.0,
                                     opcode=5))
        assert a.risk_level == "MEDIUM"
        assert any("opcode 5" in r for r in a.reasons)

    def test_reserved_z_bits_flagged(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "x.example", 1.0, z=5))
        assert a.risk_level == "MEDIUM"
        assert any("reserved header bits" in r for r in a.reasons)

    def test_normal_header_untouched(self):
        p = self._pipeline()
        a = p.process_query(DNSQuery("10.99.0.2", "x.example", 1.0))
        assert a.risk_level == "LOW"
        assert not any("opcode" in r or "qdcount" in r or "reserved" in r
                       for r in a.reasons)


class TestDualRecordDedupe:
    def test_a_and_aaaa_pair_both_admitted(self):
        """A normal getaddrinfo sends A + AAAA back-to-back with the same
        name inside the 10ms dedupe window — both must survive."""
        from exfiltrap.capture import DuplicateFilter

        df = DuplicateFilter()
        t = time.time()
        a = DNSQuery("127.0.0.1", "www.example.com", t, qtype=1, sport=5001)
        aaaa = DNSQuery("127.0.0.1", "www.example.com", t, qtype=28,
                        sport=5002)
        assert df.is_duplicate(a) is False
        assert df.is_duplicate(aaaa) is False, \
            "the AAAA half of a dual lookup must not be dropped as an echo"

    def test_loopback_echo_still_dropped(self):
        from exfiltrap.capture import DuplicateFilter

        df = DuplicateFilter()
        t = time.time()
        q = DNSQuery("127.0.0.1", "www.example.com", t, qtype=1, sport=5001)
        echo = DNSQuery("127.0.0.1", "www.example.com", t, qtype=1,
                        sport=5001)
        assert df.is_duplicate(q) is False
        assert df.is_duplicate(echo) is True


class TestSinkTtlPersistsAcrossRestart:
    def _make(self, tmp_path, ttl=600.0, clock=time.time):
        from exfiltrap.mitigation import DomainSinkhole

        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        return (DomainSinkhole(hosts_path=str(hosts), ttl=ttl, clock=clock),
                hosts)

    def test_entry_written_with_expiry(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        sn.block_domain("a.evil.example")
        text = hosts.read_text()
        assert ";exp=" in text
        assert "# exfiltrap-managed;exp=" in text

    def test_restart_adopts_live_entry_with_remaining_ttl(self, tmp_path):
        clock = {"t": 1000.0}
        sn, hosts = self._make(tmp_path, ttl=600.0, clock=lambda: clock["t"])
        sn.block_domain("a.evil.example", timestamp=1000.0)
        # "restart": a fresh sinkhole over the same hosts file, later in time
        sn2 = type(sn)(hosts_path=str(hosts), ttl=600.0,
                       clock=lambda: clock["t"])
        assert sn2.is_sunk("a.evil.example") is True
        clock["t"] += 601.0
        assert set(sn2.reap_expired()) == {"a.evil.example",
                                           "evil.example"}, \
            "the persisted TTL must survive the restart and still expire"
        assert "a.evil.example" not in hosts.read_text()

    def test_expired_entry_swept_at_startup(self, tmp_path):
        clock = {"t": 1000.0}
        sn, hosts = self._make(tmp_path, ttl=600.0, clock=lambda: clock["t"])
        sn.block_domain("old.evil.example", timestamp=1000.0)
        clock["t"] += 601.0   # entry now expired on disk
        sn2 = type(sn)(hosts_path=str(hosts), ttl=600.0,
                       clock=lambda: clock["t"])
        assert sn2.is_sunk("old.evil.example") is False
        assert "old.evil.example" not in hosts.read_text(), \
            "expired entries must be swept when the engine starts"

    def test_legacy_bare_marker_swept_at_startup(self, tmp_path):
        """v1.5 lines carried no expiry — they were the restart-forever
        bug; startup must remove rather than adopt them."""
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n"
                         "0.0.0.0 stuck.example # exfiltrap-managed\n"
                         ":: stuck.example # exfiltrap-managed\n")
        from exfiltrap.mitigation import DomainSinkhole

        DomainSinkhole(hosts_path=str(hosts), ttl=600.0)
        assert "stuck.example" not in hosts.read_text()

    def test_unblock_and_cleanup_flush(self, tmp_path, monkeypatch):
        from exfiltrap.mitigation import DomainSinkhole

        calls = []

        def fake_run(argv, capture_output, timeout):
            calls.append(argv)

            class R:
                returncode = 0
            return R()

        monkeypatch.setattr("subprocess.run", fake_run)
        DomainSinkhole._last_flush = 0.0
        sn, hosts = self._make(tmp_path)
        sn.flush_enabled = True
        sn.block_domain("a.evil.example")
        n_after_sink = len(calls)
        DomainSinkhole._last_flush = 0.0   # escape the 5s throttle
        sn.unblock_domain("a.evil.example")
        assert len(calls) == n_after_sink + 1
