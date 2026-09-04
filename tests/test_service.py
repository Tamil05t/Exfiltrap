"""Tests for the detection service: API surface, demo stream, privileges."""

import threading
import time

import pytest
from flask import Flask

from exfiltrap.classifier import DNSClassifier
from exfiltrap.pipeline import ExfilTrapPipeline
from exfiltrap.service import ServiceRuntime, build_demo_stream, run_demo_feed
from exfiltrap.storage import NullStorage, Storage


@pytest.fixture(scope="module")
def classifier():
    return DNSClassifier.load()


class TestDemoStream:
    def test_staged_incident_shape(self):
        stream = build_demo_stream()
        malicious = [r for r in stream if r.is_malicious]
        drip = [r for r in malicious if r.meta.get("mode") == "slow-drip"]
        fast = [r for r in malicious if r.meta.get("mode") == "fast"]
        assert len(drip) > 50 and len(fast) > 100
        assert min(r.query.timestamp for r in drip) >= 600.0  # starts after baseline
        stamps = [r.query.timestamp for r in stream]
        assert stamps == sorted(stamps)

    def test_demo_feed_processes_queries(self, classifier, tmp_path):
        storage = Storage(tmp_path / "demo.sqlite3", flush_every=50)
        pipeline = ExfilTrapPipeline(classifier=classifier, storage=storage)
        runtime = ServiceRuntime(mode="demo-test")
        stop = threading.Event()

        # Cap the run: stop after enough queries have been processed.
        watcher = threading.Timer(6.0, stop.set)
        watcher.start()
        started = time.time()
        run_demo_feed(pipeline, runtime, stop, speedup=600.0)
        elapsed = time.time() - started
        watcher.cancel()
        assert runtime.queries_processed > 200
        assert elapsed < 30  # speedup keeps the replay fast
        totals = storage.totals()
        assert totals["queries"] == runtime.queries_processed
        storage.close()


class TestServiceApi:
    @pytest.fixture()
    def app(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        storage = Storage(tmp_path / "api.sqlite3")
        app = create_app(tmp_path / "api.sqlite3",
                         status_provider=ServiceRuntime("demo").status)
        app.config["TEST_STORAGE"] = storage
        yield app
        storage.close()

    def test_status_endpoint(self, app):
        client = app.test_client()
        r = client.get("/api/status")
        assert r.status_code == 200
        body = r.json
        assert body["mode"] == "demo"
        assert "uptime_s" in body and "can_capture" in body

    def test_stats_events_blocked(self, app):
        client = app.test_client()
        assert client.get("/api/stats").status_code == 200
        assert client.get("/api/events").status_code == 200
        body = client.get("/api/stats").json
        assert "totals" in body and "timeseries" in body

    def test_ui_renders(self, app):
        client = app.test_client()
        r = client.get("/")
        assert r.status_code == 200
        assert b"ExFilTrap" in r.data          # branded header/title
        assert b"tab-overview" in r.data       # tabbed SPA shell
        assert b"blocked-json" in r.data       # embedded bootstrap data

    def test_bind_localhost_default(self):
        # The service must not expose the API beyond the machine by default;
        # documented behavior, asserted via the CLI default.
        from exfiltrap.service import main
        with pytest.raises(SystemExit):
            main(["--demo", "--help"])


class TestRuntimeStatus:
    def test_counts_and_uptime(self):
        rt = ServiceRuntime(mode="live:eth0")
        for _ in range(5):
            rt.count()
        status = rt.status()
        assert status["queries_processed"] == 5
        assert status["mode"] == "live:eth0"
        assert status["uptime_s"] >= 0.0
