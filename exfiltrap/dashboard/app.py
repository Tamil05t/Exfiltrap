"""M9 — Flask dashboard: live feed, block list, queries-vs-flagged chart.

Reads the SQLite database written by the pipeline. Run with:
    python3 -m exfiltrap.dashboard [--db PATH] [--port N]
"""

from __future__ import annotations

import argparse
import time

from flask import Flask, jsonify, render_template, request

from exfiltrap import config
from exfiltrap.storage import Storage


def create_app(db_path=None, status_provider=None, sessions_provider=None,
               unblock_provider=None, allowlist_provider=None,
               mute_provider=None) -> Flask:
    """Flask app serving the dashboard UI and its JSON API.

    ``status_provider`` (used by the service mode) returns a dict of live
    service facts — running mode, uptime, processed counts, privileges —
    surfaced at ``/api/status``. ``sessions_provider`` returns the live
    session-tracker snapshot for ``/api/sessions``. ``unblock_provider``,
    ``allowlist_provider`` and ``mute_provider`` are dicts of callables
    (``list``/``add``/``remove``) that let the service apply changes to its
    LIVE state; the DB is updated either way and stays the source of truth.
    """
    app = Flask(__name__)
    app.config["DB_PATH"] = str(db_path if db_path is not None else config.DB_PATH)
    app.config["STORAGE"] = Storage(app.config["DB_PATH"])

    @app.route("/")
    def index():
        storage: Storage = app.config["STORAGE"]
        return render_template(
            "index.html",
            totals=storage.totals(),
            events=storage.recent_events(50),
            queries=storage.recent_queries(50),
            blocked=storage.blocked_list(),
        )

    @app.route("/api/stats")
    def stats():
        # The dashboard polls this route every few seconds and each call
        # aggregates the whole queries table (measured 1.4 s at ~100k rows
        # on the shipped build) — under several pollers that alone
        # saturates the API and verdict reads start timing out. A 2 s TTL
        # cache collapses concurrent/rapid polls onto one computation.
        storage: Storage = app.config["STORAGE"]
        now = time.monotonic()
        cache = app.config.setdefault("_STATS_CACHE", {})
        hit = cache.get("v")
        if hit is not None and now - hit[0] < 2.0:
            return jsonify(hit[1])
        body = dict(
            totals=storage.totals(),
            levels=storage.risk_distribution(),
            response_flags=storage.response_flag_count(),
            timeseries=storage.timeseries(bucket_seconds=60, limit=120),
            top_sources=storage.top_sources(8),
        )
        cache["v"] = (now, body)
        return jsonify(body)

    @app.route("/api/status")
    def status():
        if status_provider is None:
            return jsonify(service="standalone-dashboard")
        return jsonify(status_provider())

    @app.route("/api/sessions")
    def sessions():
        if sessions_provider is None:
            return jsonify(sessions=[])
        return jsonify(sessions=sessions_provider())

    # ---- persistent allowlist + muted domains ---------------------------
    def _policy_edit(provider, payload, storage_fallback):
        if provider is not None:
            return provider(payload)
        return storage_fallback()

    @app.route("/api/allowlist")
    def allowlist_list():
        provider = (allowlist_provider or {}).get("list")
        rows = provider() if provider else \
            app.config["STORAGE"].allowlist_list()
        return jsonify(allowlist=rows)

    @app.route("/api/allowlist", methods=["POST"])
    def allowlist_add():
        p = (allowlist_provider or {}).get("add")
        body = request.get_json(silent=True) or {}
        ok = p(body) if p else app.config["STORAGE"].allowlist_add(
            (body.get("ip") or "").strip(), body.get("note", "dashboard"))
        return jsonify(ok=bool(ok))

    @app.route("/api/allowlist", methods=["DELETE"])
    def allowlist_remove():
        p = (allowlist_provider or {}).get("remove")
        body = request.get_json(silent=True) or {}
        ok = p(body) if p else app.config["STORAGE"].allowlist_remove(
            (body.get("ip") or "").strip())
        return jsonify(ok=bool(ok))

    @app.route("/api/mute")
    def mute_list():
        provider = (mute_provider or {}).get("list")
        rows = provider() if provider else \
            app.config["STORAGE"].muted_list()
        return jsonify(muted=rows)

    @app.route("/api/mute", methods=["POST"])
    def mute_add():
        p = (mute_provider or {}).get("add")
        body = request.get_json(silent=True) or {}
        ok = p(body) if p else app.config["STORAGE"].muted_add(
            (body.get("domain") or "").strip(), body.get("note", "dashboard"))
        return jsonify(ok=bool(ok))

    @app.route("/api/mute", methods=["DELETE"])
    def mute_remove():
        p = (mute_provider or {}).get("remove")
        body = request.get_json(silent=True) or {}
        ok = p(body) if p else app.config["STORAGE"].muted_remove(
            (body.get("domain") or "").strip())
        return jsonify(ok=bool(ok))

    @app.route("/api/queries")
    def queries():
        from flask import request

        storage: Storage = app.config["STORAGE"]
        limit = min(int(request.args.get("limit", 100)), 500)
        risk = request.args.get("risk") or None
        return jsonify(queries=storage.recent_queries_filtered(limit, risk))

    @app.route("/api/blocked")
    def blocked():
        storage: Storage = app.config["STORAGE"]
        return jsonify(blocked=storage.blocked_list())

    @app.route("/api/unblock", methods=["POST"])
    def unblock():
        # Localhost-bound console action (the service API never leaves the
        # machine); a deployment exposing it remotely must front it with auth.
        from flask import request

        ip = (request.get_json(silent=True) or {}).get("src_ip", "")
        if unblock_provider is not None:
            ok = unblock_provider({"src_ip": ip})
        else:
            # Standalone dashboard: no firewall to touch, but the list must
            # still be operable — the DB row is the UI's source of truth.
            storage: Storage = app.config["STORAGE"]
            ok = storage.remove_block(ip)
        return jsonify(ok=bool(ok)), (200 if ok else 400)

    @app.route("/api/events")
    def events():
        from flask import request

        storage: Storage = app.config["STORAGE"]
        limit = min(int(request.args.get("limit", 100)), 500)
        return jsonify(events=storage.recent_events(limit))

    @app.teardown_appcontext
    def _close(_exc):
        pass  # connection lives for the app lifetime; nothing per-request

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exfiltrap.dashboard")
    parser.add_argument("--db", default=None, help="SQLite path")
    parser.add_argument("--host", default=config.DASHBOARD_HOST)
    parser.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    args = parser.parse_args(argv)
    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
