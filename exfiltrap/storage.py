"""M9 (part 1) — SQLite persistence for queries, risk events and blocks.

The dashboard reads these tables; the pipeline is the only writer. Writes
happen from a single processing thread, but a lock keeps the connection
safe if the dashboard ever shares the process.

Schema notes (migrated in place on open — see ``Storage._migrate``):

* ``queries``/``risk_events`` gained ``resolver`` + ``process`` columns:
  on a single host the source IP is always the machine itself, so the
  resolver the query went to and the owning process are what make a row
  attributable.
* ``blocked_ips`` became a **response ledger** keyed on ``target``: a row
  is one automated response action — ``kind`` ∈ {source, domain, manual} —
  so a domain sink ("0.0.0.0 evil.example via hosts file") and a firewall
  DROP of a remote client coexist in one list with full provenance
  (triggering source, qname, resolver, process).
* ``sinkhole_hits`` counts queries that REACHED a sunk domain — evidence
  the response is actually intercepting the channel.
"""

from __future__ import annotations

import sqlite3
import time
import threading

from exfiltrap import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    rf_probability REAL NOT NULL,
    resolver TEXT DEFAULT '',
    process TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_risk ON queries(risk_level);
CREATE INDEX IF NOT EXISTS idx_queries_src ON queries(src_ip);

CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    decoded_preview TEXT,
    resolver TEXT DEFAULT '',
    process TEXT DEFAULT '',
    mitre TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON risk_events(ts);

CREATE TABLE IF NOT EXISTS blocked_ips (
    target TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    risk_level TEXT NOT NULL,
    kind TEXT DEFAULT 'source',
    trigger_src TEXT DEFAULT '',
    qname TEXT DEFAULT '',
    resolver TEXT DEFAULT '',
    process TEXT DEFAULT '',
    details TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_blocked_ts ON blocked_ips(ts);

-- Sinkhole interception evidence: a query for an already-sunk domain.
CREATE TABLE IF NOT EXISTS sinkhole_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    qname TEXT NOT NULL,
    base TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sinkhits_ts ON sinkhole_hits(ts);

-- Persistent operator allowlist: survives engine restarts (the --allowlist
-- flag alone lost every entry on restart — live marathon finding).
CREATE TABLE IF NOT EXISTS allowlist (
    ip TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    note TEXT
);

-- Persistent muted domains: matching queries are still stored but capped
-- at LOW and never alerted/blocked (own-host telemetry endpoints).
CREATE TABLE IF NOT EXISTS muted_domains (
    domain TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    note TEXT
);
"""


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


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
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Bring pre-1.5 databases up to the current schema in place."""
        with self._lock:
            qcols = _columns(self._conn, "queries")
            if "resolver" not in qcols:
                self._conn.execute(
                    "ALTER TABLE queries ADD COLUMN resolver TEXT DEFAULT ''")
            if "process" not in qcols:
                self._conn.execute(
                    "ALTER TABLE queries ADD COLUMN process TEXT DEFAULT ''")
            ecols = _columns(self._conn, "risk_events")
            if "resolver" not in ecols:
                self._conn.execute(
                    "ALTER TABLE risk_events ADD COLUMN resolver TEXT DEFAULT ''")
            if "process" not in ecols:
                self._conn.execute(
                    "ALTER TABLE risk_events ADD COLUMN process TEXT DEFAULT ''")
            if "mitre" not in ecols:
                self._conn.execute(
                    "ALTER TABLE risk_events ADD COLUMN mitre TEXT DEFAULT ''")
            # blocked_ips: pre-1.5 rows are (src_ip PRIMARY KEY, ts,
            # risk_level) — widen to the response ledger, keeping the rows.
            if "target" not in _columns(self._conn, "blocked_ips"):
                self._conn.execute(
                    "ALTER TABLE blocked_ips RENAME TO blocked_ips_legacy")
                self._conn.execute(
                    "CREATE TABLE blocked_ips ("
                    " target TEXT PRIMARY KEY,"
                    " ts REAL NOT NULL,"
                    " risk_level TEXT NOT NULL,"
                    " kind TEXT DEFAULT 'source',"
                    " trigger_src TEXT DEFAULT '',"
                    " qname TEXT DEFAULT '',"
                    " resolver TEXT DEFAULT '',"
                    " process TEXT DEFAULT '',"
                    " details TEXT DEFAULT '')")
                self._conn.execute(
                    "INSERT OR REPLACE INTO blocked_ips"
                    " (target, ts, risk_level, kind, trigger_src, details)"
                    " SELECT src_ip, ts, risk_level, 'source', src_ip,"
                    " " "'migrated from pre-1.5 block list'"
                    " FROM blocked_ips_legacy")
                self._conn.execute("DROP TABLE blocked_ips_legacy")

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
            "INSERT INTO queries (ts, src_ip, qname, risk_level,"
            " rf_probability, resolver, process)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (assessment.timestamp, assessment.src_ip, assessment.qname,
             assessment.risk_level, assessment.rf_probability,
             getattr(assessment, "resolver", "") or "",
             getattr(assessment, "process", "") or ""),
        )

    def log_risk_event(self, assessment) -> None:
        tags = getattr(assessment, "mitre_tags", None)
        mitre = ",".join(tags()) if callable(tags) else ""
        self._record(
            "INSERT INTO risk_events (ts, src_ip, qname, risk_level, reasons,"
            " confirmed, decoded_preview, resolver, process, mitre)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (assessment.timestamp, assessment.src_ip, assessment.qname,
             assessment.risk_level, "; ".join(assessment.reasons),
             int(assessment.confirmed_exfiltration), assessment.decoded_preview,
             getattr(assessment, "resolver", "") or "",
             getattr(assessment, "process", "") or "",
             mitre),
        )

    def log_block(self, timestamp: float, target: str, risk_level: str,
                  kind: str = "source", trigger_src: str = "",
                  qname: str = "", resolver: str = "", process: str = "",
                  details: str = "") -> None:
        """Record one automated response action in the ledger.

        ``target`` is what was acted on: a remote source IP for a firewall
        DROP, or the sunk hostname for a domain response.
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO blocked_ips (target, ts, risk_level,"
                " kind, trigger_src, qname, resolver, process, details)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (target, timestamp, risk_level, kind, trigger_src, qname,
                 resolver, process, details),
            )
            self._flush_locked()

    def log_sinkhole_hit(self, timestamp: float, qname: str, base: str) -> None:
        self._record(
            "INSERT INTO sinkhole_hits (ts, qname, base) VALUES (?, ?, ?)",
            (timestamp, qname, base),
        )

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
            sinkhits = self._conn.execute(
                "SELECT COUNT(*) FROM sinkhole_hits").fetchone()[0]
        return {"queries": n, "flagged": flagged, "confirmed": confirmed,
                "blocked": blocked, "sinkhole_hits": sinkhits}

    def recent_queries(self, limit: int = 50) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, rf_probability,"
                " resolver, process"
                " FROM queries ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "rf_probability",
                "resolver", "process")
        return [dict(zip(keys, r)) for r in rows]

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, reasons, confirmed,"
                " decoded_preview, resolver, process, mitre"
                " FROM risk_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "reasons", "confirmed",
                "decoded_preview", "resolver", "process", "mitre")
        return [dict(zip(keys, r)) for r in rows]

    def remove_block(self, target: str) -> bool:
        """Remove a response-ledger row (dashboard unblock)."""
        with self._lock:
            self._flush_locked()
            cur = self._conn.execute(
                "DELETE FROM blocked_ips WHERE target = ?", (target,))
            self._conn.commit()
            return cur.rowcount > 0

    def blocked_list(self) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT target, ts, risk_level, kind, trigger_src, qname,"
                " resolver, process, details FROM blocked_ips ORDER BY ts"
            ).fetchall()
        keys = ("target", "ts", "risk_level", "kind", "trigger_src", "qname",
                "resolver", "process", "details")
        return [dict(zip(keys, r)) for r in rows]

    def sinkhole_hits_recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT ts, qname, base FROM sinkhole_hits"
                " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": ts, "qname": q, "base": b} for ts, q, b in rows]

    # ---- persistent allowlist + muted domains (survive restarts) --------

    def allowlist_add(self, ip: str, note: str = "") -> bool:
        with self._lock:
            self._conn.execute(
                "INSERT INTO allowlist (ip, ts, note) VALUES (?, ?, ?)"
                " ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts,"
                " note = excluded.note", (ip, time.time(), note))
            self._conn.commit()
            return True

    def allowlist_remove(self, ip: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM allowlist WHERE ip = ?", (ip,))
            self._conn.commit()
            return cur.rowcount > 0

    def allowlist_list(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, ts, note FROM allowlist ORDER BY ts").fetchall()
        return [{"ip": ip, "ts": ts, "note": note} for ip, ts, note in rows]

    def muted_add(self, domain: str, note: str = "") -> bool:
        domain = domain.lower().strip()
        with self._lock:
            self._conn.execute(
                "INSERT INTO muted_domains (domain, ts, note) VALUES (?, ?, ?)"
                " ON CONFLICT(domain) DO UPDATE SET ts = excluded.ts,"
                " note = excluded.note", (domain, time.time(), note))
            self._conn.commit()
            return True

    def muted_remove(self, domain: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM muted_domains WHERE domain = ?",
                (domain.lower().strip(),))
            self._conn.commit()
            return cur.rowcount > 0

    def muted_list(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT domain, ts, note FROM muted_domains ORDER BY ts"
            ).fetchall()
        return [{"domain": d, "ts": ts, "note": note} for d, ts, note in rows]

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

    def top_flagged_domains(self, limit: int = 8) -> list[dict]:
        """Base domains with the most flagged queries (tunnel hunting)."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT qname, COUNT(*) FROM queries"
                " WHERE risk_level IN ('HIGH','CONFIRMED')"
                " GROUP BY qname ORDER BY COUNT(*) DESC LIMIT ?",
                (limit,)).fetchall()
        from exfiltrap.features import base_domain
        merged: dict[str, int] = {}
        for qname, n in rows:
            merged[base_domain(qname)] = merged.get(base_domain(qname), 0) + n
        return [{"domain": d, "flagged": n}
                for d, n in sorted(merged.items(),
                                   key=lambda kv: -kv[1])[:limit]]

    def recent_queries_filtered(self, limit: int = 100,
                                 risk: str | None = None) -> list[dict]:
        """Recent queries with an optional risk-level filter (live feed)."""
        with self._lock:
            self._flush_locked()
            if risk:
                rows = self._conn.execute(
                    "SELECT ts, src_ip, qname, risk_level, rf_probability,"
                    " resolver, process"
                    " FROM queries WHERE risk_level = ?"
                    " ORDER BY id DESC LIMIT ?", (risk, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, src_ip, qname, risk_level, rf_probability,"
                    " resolver, process"
                    " FROM queries ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        keys = ("ts", "src_ip", "qname", "risk_level", "rf_probability",
                "resolver", "process")
        return [dict(zip(keys, r)) for r in rows]

    def queries_since(self, last_id: int, limit: int = 200) -> list[dict]:
        """Rows newer than ``last_id`` ascending — drives the SSE stream."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT id, ts, src_ip, qname, risk_level, rf_probability,"
                " resolver, process FROM queries WHERE id > ?"
                " ORDER BY id ASC LIMIT ?", (last_id, limit)).fetchall()
        keys = ("id", "ts", "src_ip", "qname", "risk_level",
                "rf_probability", "resolver", "process")
        return [dict(zip(keys, r)) for r in rows]

    def events_since(self, last_id: int, limit: int = 100) -> list[dict]:
        """Risk events newer than ``last_id`` ascending (SSE stream)."""
        with self._lock:
            self._flush_locked()
            rows = self._conn.execute(
                "SELECT id, ts, src_ip, qname, risk_level, reasons, confirmed,"
                " decoded_preview, resolver, process, mitre"
                " FROM risk_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (last_id, limit)).fetchall()
        keys = ("id", "ts", "src_ip", "qname", "risk_level", "reasons",
                "confirmed", "decoded_preview", "resolver", "process", "mitre")
        return [dict(zip(keys, r)) for r in rows]

    def max_query_id(self) -> int:
        with self._lock:
            self._flush_locked()
            row = self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM queries").fetchone()
        return int(row[0])

    def max_event_id(self) -> int:
        with self._lock:
            self._flush_locked()
            row = self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM risk_events").fetchone()
        return int(row[0])

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

    def export_json(self, window_seconds: float = 3600.0) -> dict:
        """Evidence pack: every table's rows inside the time window.

        One JSON blob an operator (or a paper) can cite — queries, risk
        events with reasons and ATT&CK tags, the response ledger and the
        sinkhole interception log, all cut to the same window ending now.
        """
        now = time.time()
        since = now - window_seconds
        with self._lock:
            self._flush_locked()
            queries = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, rf_probability,"
                " resolver, process FROM queries WHERE ts >= ? ORDER BY ts",
                (since,)).fetchall()
            events = self._conn.execute(
                "SELECT ts, src_ip, qname, risk_level, reasons, confirmed,"
                " decoded_preview, resolver, process, mitre"
                " FROM risk_events WHERE ts >= ? ORDER BY ts",
                (since,)).fetchall()
            blocks = self._conn.execute(
                "SELECT ts, target, risk_level, kind, trigger_src, qname,"
                " resolver, process, details FROM blocked_ips"
                " WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
            hits = self._conn.execute(
                "SELECT ts, qname, base FROM sinkhole_hits"
                " WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
        qk = ("ts", "src_ip", "qname", "risk_level", "rf_probability",
              "resolver", "process")
        ek = ("ts", "src_ip", "qname", "risk_level", "reasons", "confirmed",
              "decoded_preview", "resolver", "process", "mitre")
        bk = ("ts", "target", "risk_level", "kind", "trigger_src", "qname",
              "resolver", "process", "details")
        hk = ("ts", "qname", "base")
        return {
            "exported_at": now,
            "window_seconds": window_seconds,
            "queries": [dict(zip(qk, r)) for r in queries],
            "risk_events": [dict(zip(ek, r)) for r in events],
            "responses": [dict(zip(bk, r)) for r in blocks],
            "sinkhole_hits": [dict(zip(hk, r)) for r in hits],
        }

    # -- retention -------------------------------------------------------
    # Scopes are deliberately explicit and narrow. The allowlist and the
    # muted-domain list are NEVER purged by any scope: they are operator
    # configuration, not captured evidence, and silently forgetting them
    # would re-enable blocking of hosts the operator deliberately exempted.
    # Public so the API can validate a requested scope without duplicating
    # the list (or reaching into a private attribute).
    PURGE_SCOPES = {
        "queries": ("queries",),
        "evidence": ("queries", "risk_events", "sinkhole_hits"),
        "all": ("queries", "risk_events", "sinkhole_hits", "blocked_ips"),
    }

    def purge(self, scope: str = "queries") -> dict:
        """Delete captured rows; returns ``{table: rows_removed}``.

        The AUTOINCREMENT high-water mark is deliberately NOT reset. The
        dashboard's SSE stream trails ``max_query_id()`` in a closure, so if
        a purge rewound the ids that cursor would sit above every future row
        and the live feed would go permanently silent until the page was
        reloaded. Letting the sequence continue costs nothing.
        """
        tables = self.PURGE_SCOPES.get(scope)
        if tables is None:
            raise ValueError(f"unknown purge scope {scope!r}; expected one "
                             f"of {sorted(self.PURGE_SCOPES)}")
        removed: dict[str, int] = {}
        with self._lock:
            self._flush_locked()
            for table in tables:
                # `table` comes from the fixed dict above, never from input.
                cur = self._conn.execute(f"DELETE FROM {table}")
                removed[table] = max(0, cur.rowcount or 0)
            self._conn.commit()
        return removed

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            self._conn.close()


class NullStorage:
    """Drop-in no-op sink for --no-db runs and tests."""

    def log_query(self, assessment) -> None: ...
    def log_risk_event(self, assessment) -> None: ...
    def log_block(self, timestamp, target, risk_level, kind="source",
                  trigger_src="", qname="", resolver="", process="",
                  details="") -> None: ...
    def log_sinkhole_hit(self, timestamp, qname, base) -> None: ...
    def totals(self) -> dict:
        return {"queries": 0, "flagged": 0, "confirmed": 0, "blocked": 0,
                "sinkhole_hits": 0}

    def purge(self, scope: str = "queries") -> dict:
        return {}

    # Same scope names as Storage so the API can validate against either.
    PURGE_SCOPES = {"queries": (), "evidence": (), "all": ()}

    def recent_queries(self, limit=50) -> list: return []
    def recent_events(self, limit=50) -> list: return []
    def blocked_list(self) -> list: return []
    def sinkhole_hits_recent(self, limit=50) -> list: return []
    def timeseries(self, bucket_seconds=60, limit=120) -> list: return []
    def export_json(self, window_seconds=3600.0) -> dict:
        return {"exported_at": time.time(), "window_seconds": window_seconds,
                "queries": [], "risk_events": [], "responses": [],
                "sinkhole_hits": []}
    def close(self) -> None: ...
