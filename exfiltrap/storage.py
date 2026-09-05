"""M9 (part 1) — SQLite persistence for queries, risk events and blocks.

The dashboard reads these tables; the pipeline is the only writer. Writes
happen from a single processing thread, but a lock keeps the connection
safe if the dashboard ever shares the process.
"""

from __future__ import annotations

import sqlite3
import threading

from exfiltrap import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    rf_probability REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);

CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    decoded_preview TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON risk_events(ts);

CREATE TABLE IF NOT EXISTS blocked_ips (
    src_ip TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    risk_level TEXT NOT NULL
);
"""


class Storage:
    """SQLite sink for the pipeline.

    Write path is optimized for a sustained capture loop: WAL journaling,
    ``synchronous=NORMAL`` (durability across power loss is traded for
    order-of-magnitude cheaper commits — the database holds monitoring
    data, not ledgers), and buffered batched inserts flushed on read or
    every ``flush_every`` pending rows. Readers (the dashboard/API) always
    see a consistent, complete view because reads flush first.
    """

    def __init__(self, db_path=None, flush_every: int = 200):
        self.db_path = str(db_path if db_path is not None else config.DB_PATH)
        self.flush_every = max(1, flush_every)
        self._lock = threading.Lock()
        self._pending = 0
        # isolation_level=None = autocommit: multiple connections (the
        # service's pipeline sink AND the dashboard/API) share this file,
        # and a lingering implicit transaction on one would lock the other
        # out (observed live). WAL + synchronous=NORMAL keeps autocommit
        # cheap; busy_timeout makes brief writer collisions wait, not fail.
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, timeout=30.0,
            isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _flush_locked(self) -> None:
        if self._pending:
            self._conn.commit()
            self._pending = 0

    def _record(self, sql: str, params: tuple) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._pending += 1
            if self._pending >= self.flush_every:
                self._flush_locked()

    # -- writes ----------------------------------------------------------
    def log_query(self, assessment) -> None:
        self._record(
            "INSERT INTO queries (ts, src_ip, qname, risk_level, rf_probability)"
            " VALUES (?, ?, ?, ?, ?)",
            (assessment.timestamp, assessment.src_ip, assessment.qname,
             assessment.risk_level, assessment.rf_probability),
        )

    def log_risk_event(self, assessment) -> None:
        self._record(
            "INSERT INTO risk_events (ts, src_ip, qname, risk_level, reasons,"
            " confirmed, decoded_preview) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (assessment.timestamp, assessment.src_ip, assessment.qname,
             assessment.risk_level, "; ".join(assessment.reasons),
             int(assessment.confirmed_exfiltration), assessment.decoded_preview),
        )

    def log_block(self, timestamp: float, src_ip: str, risk_level: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO blocked_ips (src_ip, ts, risk_level)"
                " VALUES (?, ?, ?)",
                (src_ip, timestamp, risk_level),
            )
            self._flush_locked()

    # -- reads (dashboard) -----------------------------------------------
    def totals(self) -> dict:
        with self._lock:
            self._flush_locked()
            n = self._conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            flagged = self._conn.execute(
                "SELECT COUNT(*) FROM queries WHERE risk_level IN ('HIGH','CONFIRMED')"
            ).fetchone()[0]
            confirmed = self._conn.execute(
                "SELECT COUNT(*) FROM risk_events WHERE confirmed = 1"
            ).fetchone()[0]
            blocked = self._conn.execute(
                "SELECT COUNT(*) FROM blocked_ips"
            ).fetchone()[0]
        return {"queries": n, "flagged": flagged, "confirmed": confirmed,
                "blocked": blocked}

    def recent_queries(self, limit: int = 50) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, rf_probability"
                " FROM queries ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "rf_probability")
        return [dict(zip(keys, r)) for r in rows]

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, reasons, confirmed,"
                " decoded_preview FROM risk_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "reasons", "confirmed",
                "decoded_preview")
        return [dict(zip(keys, r)) for r in rows]

    def remove_block(self, ip: str) -> bool:
        """Remove a block row (dashboard unblock). True if a row was removed."""
        with self._lock:
            self._flush_locked()
            cur = self._conn.execute(
                "DELETE FROM blocked_ips WHERE src_ip = ?", (ip,))
            self._conn.commit()
            return cur.rowcount > 0

    def blocked_list(self) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT src_ip, ts, risk_level FROM blocked_ips ORDER BY ts"
            ).fetchall()
        keys = ("src_ip", "ts", "risk_level")
        return [dict(zip(keys, r)) for r in rows]

    def response_flag_count(self) -> int:
        """Alerts raised by the response (download/C2) channel."""
        with self._lock:
            self._flush_locked()
            return self._conn.execute(
                "SELECT COUNT(*) FROM risk_events"
                " WHERE reasons LIKE '%response channel%'").fetchone()[0]

    def risk_distribution(self) -> dict:
        """Count per risk level (drives the dashboard doughnut)."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT risk_level, COUNT(*) FROM queries GROUP BY risk_level"
            ).fetchall()
        return {level: n for level, n in rows}

    def top_sources(self, limit: int = 8) -> list[dict]:
        """Sources with the most flagged queries (dashboard top-talkers)."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT src_ip, SUM(risk_level IN ('HIGH','CONFIRMED')) AS f,"
                " COUNT(*) AS total FROM queries GROUP BY src_ip"
                " ORDER BY f DESC, total DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"src_ip": s, "flagged": f, "total": t} for s, f, t in rows]

    def recent_queries_filtered(self, limit: int = 100,
                                 risk: str | None = None) -> list[dict]:
        """Recent queries with an optional risk-level filter (live feed)."""
        with self._lock:
            self._flush_locked()
            if risk:
                rows = self._conn.execute(
                    "SELECT ts, src_ip, qname, risk_level, rf_probability"
                    " FROM queries WHERE risk_level = ?"
                    " ORDER BY id DESC LIMIT ?", (risk, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, src_ip, qname, risk_level, rf_probability"
                    " FROM queries ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "rf_probability")
        return [dict(zip(keys, r)) for r in rows]

    def timeseries(self, bucket_seconds: int = 60, limit: int = 120) -> list[dict]:
        """Per-bucket counts of all queries vs flagged ones, oldest first."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT CAST(ts / ? AS INTEGER) * ? AS bucket,"
                " COUNT(*),"
                " SUM(risk_level IN ('HIGH','CONFIRMED'))"
                " FROM queries GROUP BY bucket ORDER BY bucket DESC LIMIT ?",
                (bucket_seconds, bucket_seconds, limit),
            ).fetchall()
        rows.reverse()  # oldest first, for charting
        keys = ("bucket", "queries", "flagged")
        return [dict(zip(keys, r)) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            self._conn.close()


class NullStorage:
    """Drop-in no-op sink for --no-db runs and tests."""

    def log_query(self, assessment) -> None: ...
    def log_risk_event(self, assessment) -> None: ...
    def log_block(self, timestamp, src_ip, risk_level) -> None: ...
    def totals(self) -> dict:
        return {"queries": 0, "flagged": 0, "confirmed": 0, "blocked": 0}

    def recent_queries(self, limit=50) -> list: return []
    def recent_events(self, limit=50) -> list: return []
    def blocked_list(self) -> list: return []
    def timeseries(self, bucket_seconds=60, limit=120) -> list: return []
    def close(self) -> None: ...
