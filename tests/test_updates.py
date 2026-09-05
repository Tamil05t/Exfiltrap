"""Tests for the live-deployment updates: alerting, watchdog, multi-IP."""

import os
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from exfiltrap.alerting import NullAlerter, SyslogAlerter, make_alerter
from exfiltrap.pipeline import ExfilTrapPipeline
from exfiltrap.service import ServiceRuntime, SystemdWatchdog
from exfiltrap.storage import NullStorage, Storage


def assessment(risk="CONFIRMED", ip="10.99.0.2", prob=0.99):
    return SimpleNamespace(
        src_ip=ip, qname="abcd.tunnel.example", timestamp=1.0,
        risk_level=risk, rf_probability=prob, reasons=["payload decoded via base32"],
        confirmed_exfiltration=True, decoded_preview="b'PK...'",
    )


class TestAlerting:
    def test_null_alerter(self):
        assert NullAlerter().send(assessment()) is False

    def test_syslog_sends_structured_line(self, tmp_path):
        sock_path = str(tmp_path / "syslog.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(sock_path)
        server.settimeout(2)
        alerter = SyslogAlerter(address=sock_path)
        assert alerter.send(assessment()) is True
        line = server.recv(4096).decode()
        assert "EXFILTRAP_ALERT" in line
        assert "risk=CONFIRMED" in line and "src=10.99.0.2" in line
        assert "prob=0.990" in line and "confirmed=1" in line
        server.close()

    def test_unavailable_syslog_is_silent_noop(self):
        alerter = SyslogAlerter(address="/nonexistent/syslog/sock")
        assert alerter.send(assessment()) is False

    def test_factory(self):
        assert isinstance(make_alerter("none"), NullAlerter)
        assert isinstance(make_alerter("syslog"), SyslogAlerter)
        with pytest.raises(ValueError):
            make_alerter("pager")

    def test_pipeline_alerts_only_high_risk(self, tmp_path):
        import base64

        sent = []

        class Recorder:
            def send(self, a):
                sent.append(a.risk_level)
                return True

        from exfiltrap.events import DNSQuery

        class StubClassifier:
            def predict_proba(self, features):
                return 0.95 if features.entropy > 4.0 else 0.02

        label = base64.b32encode(b"live tunnel payload!").decode().rstrip("=")
        p = ExfilTrapPipeline(classifier=StubClassifier(), storage=NullStorage(),
                              alerter=Recorder())
        # benign stream: LOW, no alerts (jittered arrivals — benign
        # resolvers are not metronomes, and periodic ones WOULD beacon)
        import random as _random

        rng = _random.Random(4)
        t, stream = 0.0, []
        for _ in range(20):
            t += rng.expovariate(1.0)
            stream.append(DNSQuery("10.99.0.3", "www.google.com", t))
        p.run_synthetic(stream)
        assert sent == []
        # tunnel query: decodes cleanly, so it escalates past HIGH to CONFIRMED
        p.run_synthetic([DNSQuery("10.99.0.2", f"{label}.tunnel.example", 100.0)])
        assert sent == ["CONFIRMED"]


class TestWatchdog:
    def _notify_socket(self, tmp_path):
        sock_path = str(tmp_path / "notify.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(sock_path)
        server.settimeout(3)
        return sock_path, server

    def test_ready_and_watchdog_pings(self, tmp_path, monkeypatch):
        sock_path, server = self._notify_socket(tmp_path)
        monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
        monkeypatch.setenv("WATCHDOG_USEC", "2000000")  # 2s -> 1s pings
        rt = ServiceRuntime("live:test")
        wd = SystemdWatchdog(rt, stall_limit=90)
        wd.start()
        try:
            msgs = [server.recv(128).decode() for _ in range(2)]
            assert msgs[0] == "READY=1"
            assert any(m == "WATCHDOG=1" for m in msgs[1:])
        finally:
            wd.stop()
            server.close()

    def test_stalled_heartbeat_suspends_pings(self, tmp_path, monkeypatch):
        sock_path, server = self._notify_socket(tmp_path)
        monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
        monkeypatch.setenv("WATCHDOG_USEC", "1000000")  # 0.5s pings
        rt = ServiceRuntime("live:test")
        # Simulate a long-stalled capture loop by rewinding the heartbeat.
        with rt._lock:
            rt._last_beat = time.monotonic() - 10_000
        wd = SystemdWatchdog(rt, stall_limit=5)
        wd.start()
        try:
            first = server.recv(128).decode()  # READY=1
            assert first == "READY=1"
            # No WATCHDOG=1 may arrive while the heartbeat is stale.
            server.settimeout(1.2)
            with pytest.raises(socket.timeout):
                server.recv(128)
        finally:
            wd.stop()
            server.close()

    def test_beat_resumes_pings(self, tmp_path, monkeypatch):
        sock_path, server = self._notify_socket(tmp_path)
        monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
        monkeypatch.setenv("WATCHDOG_USEC", "1000000")
        rt = ServiceRuntime("live:test")
        with rt._lock:
            rt._last_beat = time.monotonic() - 10_000
        wd = SystemdWatchdog(rt, stall_limit=5)
        wd.start()
        try:
            assert server.recv(128).decode() == "READY=1"
            rt.beat()  # capture thread recovers
            server.settimeout(3)
            deadline = time.time() + 3
            saw_ping = False
            while time.time() < deadline and not saw_ping:
                try:
                    saw_ping = server.recv(128).decode() == "WATCHDOG=1"
                except socket.timeout:
                    break
            assert saw_ping
        finally:
            wd.stop()
            server.close()

    def test_no_notify_socket_is_noop(self, monkeypatch):
        monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
        rt = ServiceRuntime("live:test")
        wd = SystemdWatchdog(rt)
        wd.start()  # must not raise
        wd.stop()

    def test_runtime_heartbeat_tracking(self):
        rt = ServiceRuntime("live:test")
        with rt._lock:
            rt._last_beat = time.monotonic() - 50
        assert rt.heartbeat_age() >= 49
        rt.beat()
        assert rt.heartbeat_age() < 1


class TestMultiIpSenders:
    def test_benign_sender_binds_source_ip(self, tmp_path):
        import sys
        sys.path.insert(0, ".")
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bg", Path("tools/benign_traffic_gen.py"))
        bg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bg)
        from exfiltrap.events import DNSQuery, LabeledQuery

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(3)
        # Some sandboxes drop traffic to loopback aliases; skip there.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.2", 0))
        probe.sendto(b"x", listener.getsockname())
        try:
            listener.recv(1)
        except socket.timeout:
            pytest.skip("loopback aliases unavailable in this environment")
        finally:
            probe.close()
        port = listener.getsockname()[1]
        records = [LabeledQuery(DNSQuery("127.0.0.2", "a.example.com", 0.0),
                                is_malicious=False)]
        threading.Thread(
            target=bg.send_queries, args=(records, "127.0.0.1"),
            kwargs={"source_ip": "127.0.0.2", "port": port}, daemon=True,
        ).start()
        data = listener.recv(2048)
        assert len(data) > 12  # DNS header + question
        assert data[2] & 0x80 == 0  # QR=0: a query, not a response
        assert data[2] & 0x01 == 1  # RD=1 as built
        assert data[4:6] == b"\x00\x01"  # qdcount = 1
        listener.close()


class TestBatchedLivePath:
    def test_process_many_equals_process_query(self):
        import random as _r

        from exfiltrap.events import DNSQuery

        class Stub:
            def predict_proba(self, f):
                return 0.95 if f.entropy > 4.0 else 0.02

        rng = _r.Random(1)
        stream, t = [], 0.0
        for i in range(40):
            t += rng.expovariate(1.0)
            name = ("www.corp.example" if i % 2 else
                    "MFZWIZLTOIYFAAAA.tunnel.example")
            stream.append(DNSQuery("10.1.1.9", name, t))
        a = ExfilTrapPipeline(classifier=Stub(), storage=NullStorage())
        b = ExfilTrapPipeline(classifier=Stub(), storage=NullStorage())
        batch = a.process_many(stream)
        single = [b.process_query(q) for q in stream]
        assert [x.risk_level for x in batch] == [x.risk_level for x in single]
        assert [x.rf_probability for x in batch] == \
               [x.rf_probability for x in single]


class TestDashboardAnalytics:
    def _db(self, tmp_path):
        store = Storage(tmp_path / "an.db")
        for i in range(50):
            store.log_query(assessment("LOW" if i % 5 else "HIGH",
                                       ip="10.0.0.1" if i % 2 else "10.0.0.2"))
        return store

    def test_risk_distribution_and_top_sources(self, tmp_path):
        store = self._db(tmp_path)
        dist = store.risk_distribution()
        assert dist == {"HIGH": 10, "LOW": 40}
        top = store.top_sources()
        assert top[0]["src_ip"] == "10.0.0.1" and top[0]["flagged"] >= 5
        store.close()

    def test_filtered_query_feed(self, tmp_path):
        store = self._db(tmp_path)
        high = store.recent_queries_filtered(100, "HIGH")
        assert high and all(q["risk_level"] == "HIGH" for q in high)
        assert len(store.recent_queries_filtered(100, None)) == 50
        store.close()

    def test_api_endpoints(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        store = self._db(tmp_path)
        store.recent_queries(1)  # flush buffered rows for other connections
        app = create_app(tmp_path / "an.db",
                         sessions_provider=lambda: [{"src_ip": "10.9.9.9",
                                                     "query_count": 7}])
        c = app.test_client()
        body = c.get("/api/queries?limit=10&risk=HIGH").json
        assert all(q["risk_level"] == "HIGH" for q in body["queries"])
        assert c.get("/api/sessions").json["sessions"][0]["src_ip"] == "10.9.9.9"
        stats = c.get("/api/stats").json
        assert stats["levels"]["HIGH"] == 10 and stats["top_sources"]
        assert c.get("/api/queries?limit=9999").json  # capped, not fatal
        store.close()


class TestPolicyEngine:
    def _inner(self):
        from exfiltrap.mitigation import LogOnlyMitigation

        return LogOnlyMitigation()

    def test_allowlist_blocks_nothing(self):
        from exfiltrap.policy import make_policy

        pol = make_policy(self._inner(), allowlist=("10.0.0.5",))
        assert pol.block_ip("10.0.0.5") is False
        assert pol.block_ip("10.0.0.6") is True

    def test_ttl_auto_unban(self):
        from exfiltrap.policy import PolicyMitigation

        clock = {"t": 0.0}

        def fake_time():
            return clock["t"]

        pol = PolicyMitigation(self._inner(), block_ttl=600, clock=fake_time)
        pol.block_ip("10.0.0.6")
        assert pol.reap_expired() == []          # not yet
        clock["t"] = 601
        assert pol.reap_expired() == ["10.0.0.6"]
        assert pol.is_blocked("10.0.0.6") is False

    def test_manual_unblock_idempotent(self):
        from exfiltrap.policy import make_policy

        pol = make_policy(self._inner())
        pol.block_ip("10.0.0.6")
        assert pol.unblock("10.0.0.6") is True
        assert pol.unblock("10.0.0.6") is False


class TestAlertDedup:
    def test_one_line_per_src_level_per_hour(self):
        import socket as s

        srv = s.socket(s.AF_UNIX, s.SOCK_DGRAM)
        path = "/tmp/exfiltrap_dedup.sock"
        try:
            import os

            os.unlink(path)
        except OSError:
            pass
        srv.bind(path)
        srv.settimeout(1)
        al = SyslogAlerter(address=path)
        assert al.send(assessment(ip="10.1.1.1")) is True
        assert al.send(assessment(ip="10.1.1.1")) is False   # suppressed
        assert al.send(assessment(ip="10.1.1.2")) is True    # different src
        srv.close()


class TestWarmRestart:
    def test_save_and_restore(self, tmp_path):
        from exfiltrap import session_tracker as stm
        from exfiltrap.baseline_engine import BaselineEngine

        tr = stm.SessionTracker(baseline=BaselineEngine(warmup=5))
        for i in range(8):
            tr.update("h1", i * 10.0, 4.0, 2.5)
        p = tmp_path / "state.json"
        stm.save_state(tr, p)

        tr2 = stm.SessionTracker(baseline=BaselineEngine(warmup=5))
        assert stm.load_state(tr2, p) is True
        got = tr2.get("h1")
        assert got.query_count == 8 and got.mean_mass == 2.0

    def test_load_missing_file(self, tmp_path):
        from exfiltrap import session_tracker as stm

        assert stm.load_state(stm.SessionTracker(),
                              tmp_path / "nope.json") is False


class TestUnblockEndpoint:
    def test_post_unblock(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        calls = []

        app = create_app(tmp_path / "u.db",
                         unblock_provider=lambda p: calls.append(p) or True)
        c = app.test_client()
        r = c.post("/api/unblock", json={"src_ip": "10.0.0.9"})
        assert r.status_code == 200 and r.json["ok"] is True
        assert calls == [{"src_ip": "10.0.0.9"}]


class TestUnblockFlow:
    def test_remove_block(self, tmp_path):
        store = Storage(tmp_path / "u.db")
        store.log_block(1.0, "10.0.0.9", "HIGH")
        assert store.remove_block("10.0.0.9") is True
        assert store.remove_block("10.0.0.9") is False
        assert store.blocked_list() == []
        store.close()

    def test_unblock_endpoint_without_provider_clears_row(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        store = Storage(tmp_path / "u2.db")
        store.log_block(1.0, "10.0.0.9", "HIGH")
        store.recent_queries(1)  # flush
        app = create_app(tmp_path / "u2.db")
        c = app.test_client()
        r = c.post("/api/unblock", json={"src_ip": "10.0.0.9"})
        assert r.status_code == 200 and r.json["ok"] is True
        assert c.get("/api/blocked").json["blocked"] == []
        store.close()

    def test_blocked_endpoint_live(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        store = Storage(tmp_path / "u3.db")
        store.log_block(1.0, "10.0.0.7", "HIGH")
        store.recent_queries(1)
        c = create_app(tmp_path / "u3.db").test_client()
        body = c.get("/api/blocked").json["blocked"]
        assert body == [{"src_ip": "10.0.0.7", "ts": 1.0, "risk_level": "HIGH"}]
        store.close()

    def test_service_unblock_provider_removes_row(self, tmp_path):
        # Service-mode _unblock: policy unblock + row removal (row is truth).
        from exfiltrap.mitigation import LogOnlyMitigation
        from exfiltrap.policy import make_policy
        from exfiltrap.storage import Storage

        store = Storage(tmp_path / "u4.db")
        pol = make_policy(LogOnlyMitigation())
        pol.block_ip("10.0.0.5")
        store.log_block(1.0, "10.0.0.5", "HIGH")

        ok = pol.unblock("10.0.0.5")
        removed = store.remove_block("10.0.0.5")
        assert ok and removed and store.blocked_list() == []
        store.close()
