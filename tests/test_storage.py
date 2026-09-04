"""Unit tests for M9 storage — SQLite sink (tmp database)."""

from types import SimpleNamespace

from exfiltrap.storage import NullStorage, Storage


def assessment(ts, ip, qname, risk="LOW", prob=0.1, confirmed=False, preview=None):
    return SimpleNamespace(
        timestamp=ts, src_ip=ip, qname=qname, risk_level=risk,
        rf_probability=prob, reasons=[f"reason-{risk}"],
        confirmed_exfiltration=confirmed, decoded_preview=preview,
    )


class TestStorage:
    def test_roundtrip(self, tmp_path):
        store = Storage(tmp_path / "db.sqlite3")
        store.log_query(assessment(1.0, "10.0.0.1", "a.com"))
        store.log_query(assessment(2.0, "10.0.0.2", "b.com", risk="HIGH", prob=0.9))
        store.log_risk_event(assessment(2.0, "10.0.0.2", "b.com", risk="HIGH",
                                        prob=0.9))
        store.log_block(2.0, "10.0.0.2", "HIGH")

        totals = store.totals()
        assert totals["queries"] == 2
        assert totals["flagged"] == 1
        assert totals["confirmed"] == 0
        assert totals["blocked"] == 1

        recent = store.recent_queries(limit=10)
        assert recent[0]["qname"] == "b.com"  # newest first

        events = store.recent_events()
        assert events[0]["risk_level"] == "HIGH"
        assert "reason-HIGH" in events[0]["reasons"]

        blocked = store.blocked_list()
        assert blocked == [{"src_ip": "10.0.0.2", "ts": 2.0, "risk_level": "HIGH"}]
        store.close()

    def test_block_dedup(self, tmp_path):
        store = Storage(tmp_path / "db.sqlite3")
        store.log_block(1.0, "10.0.0.9", "HIGH")
        store.log_block(2.0, "10.0.0.9", "CONFIRMED")
        assert len(store.blocked_list()) == 1
        store.close()

    def test_confirmed_events_counted(self, tmp_path):
        store = Storage(tmp_path / "db.sqlite3")
        confirmed = assessment(3.0, "10.0.0.3", "c.com", risk="CONFIRMED",
                               confirmed=True, preview="'PK'")
        store.log_risk_event(confirmed)
        assert store.totals()["confirmed"] == 1
        store.close()

    def test_timeseries_buckets(self, tmp_path):
        store = Storage(tmp_path / "db.sqlite3")
        for i in range(10):
            store.log_query(assessment(float(i), "10.0.0.1", f"{i}.com"))
        store.log_query(assessment(61.0, "10.0.0.1", "late.com", risk="HIGH"))
        series = store.timeseries(bucket_seconds=60)
        assert series[0]["bucket"] == 0 and series[0]["queries"] == 10
        assert series[1]["bucket"] == 60 and series[1]["queries"] == 1
        assert series[1]["flagged"] == 1
        store.close()

    def test_wal_mode_enabled(self, tmp_path):
        store = Storage(tmp_path / "wal.sqlite3")
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        store.close()

    def test_batched_writes_visible_after_read(self, tmp_path):
        # flush_every=200: writes buffer until a read (or the 200 mark).
        store = Storage(tmp_path / "batch.sqlite3", flush_every=200)
        for i in range(50):
            store.log_query(assessment(float(i), "10.0.0.1", f"{i}.com"))
        assert store._pending == 50  # buffered, not yet committed
        # Reads flush first, so the dashboard always sees everything.
        assert store.totals()["queries"] == 50
        assert store._pending == 0
        store.close()

    def test_autoflush_at_threshold(self, tmp_path):
        store = Storage(tmp_path / "auto.sqlite3", flush_every=10)
        for i in range(25):
            store.log_query(assessment(float(i), "10.0.0.1", f"{i}.com"))
        assert store._pending == 5  # 20 committed in two batches of 10
        assert store.totals()["queries"] == 25
        store.close()

    def test_close_flushes_pending(self, tmp_path):
        store = Storage(tmp_path / "close.sqlite3", flush_every=1000)
        for i in range(7):
            store.log_query(assessment(float(i), "10.0.0.1", f"{i}.com"))
        store.close()
        # A fresh connection sees the rows committed by close().
        import sqlite3

        conn = sqlite3.connect(tmp_path / "close.sqlite3")
        assert conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0] == 7
        conn.close()

    def test_null_storage_silent(self):
        ns = NullStorage()
        ns.log_query(assessment(1, "x", "y"))
        assert ns.totals()["queries"] == 0
        assert ns.recent_events() == []
        ns.close()
