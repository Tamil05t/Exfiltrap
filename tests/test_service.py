"""Tests for the detection service: API surface, privileges."""

import threading
import time

import pytest
from flask import Flask

from exfiltrap.classifier import DNSClassifier
from exfiltrap.pipeline import ExfilTrapPipeline
from exfiltrap.service import ServiceRuntime
from exfiltrap.storage import NullStorage, Storage


@pytest.fixture(scope="module")
def classifier():
    return DNSClassifier.load()


class TestServiceApi:
    @pytest.fixture()
    def app(self, tmp_path):
        from exfiltrap.dashboard.app import create_app

        storage = Storage(tmp_path / "api.sqlite3")
        app = create_app(tmp_path / "api.sqlite3",
                         status_provider=ServiceRuntime("live:test").status)
        app.config["TEST_STORAGE"] = storage
        yield app
        storage.close()

    def test_status_endpoint(self, app):
        client = app.test_client()
        r = client.get("/api/status")
        assert r.status_code == 200
        body = r.json
        assert body["mode"] == "live:test"
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

    def test_iface_required(self):
        # Live capture is the only mode; --iface is mandatory.
        from exfiltrap.service import main

        with pytest.raises(SystemExit):
            main([])


class TestRuntimeStatus:
    def test_counts_and_uptime(self):
        rt = ServiceRuntime(mode="live:eth0")
        for _ in range(5):
            rt.count()
        status = rt.status()
        assert status["queries_processed"] == 5
        assert status["mode"] == "live:eth0"
        assert status["uptime_s"] >= 0.0
