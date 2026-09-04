"""M9 — Flask dashboard: live feed, block list, queries-vs-flagged chart.

Reads the SQLite database written by the pipeline. Run with:
    python3 -m exfiltrap.dashboard [--db PATH] [--port N]
"""

from __future__ import annotations

import argparse

from flask import Flask, jsonify, render_template

from exfiltrap import config
from exfiltrap.storage import Storage


def create_app(db_path=None, status_provider=None, sessions_provider=None,
               unblock_provider=None) -> Flask:
    """Flask app serving the dashboard UI and its JSON API.

    ``status_provider`` (used by the service mode) returns a dict of live
    service facts — running mode, uptime, processed counts, privileges —
    surfaced at ``/api/status``. ``sessions_provider`` returns the live
    session-tracker snapshot for ``/api/sessions``.
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
        storage: Storage = app.config["STORAGE"]
        return jsonify(
            totals=storage.totals(),
            levels=storage.risk_distribution(),
            response_flags=storage.response_flag_count(),
            timeseries=storage.timeseries(bucket_seconds=60, limit=120),
            top_sources=storage.top_sources(8),
        )

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

    @app.route("/api/queries")
    def queries():
        from flask import request

        storage: Storage = app.config["STORAGE"]
        limit = min(int(request.args.get("limit", 100)), 500)
        risk = request.args.get("risk") or None
        return jsonify(queries=storage.recent_queries_filtered(limit, risk))

    @app.route("/api/unblock", methods=["POST"])
    def unblock():
        # Localhost-bound console action (the service API never leaves the
        # machine); a deployment exposing it remotely must front it with auth.
        if unblock_provider is None:
            return jsonify(error="mitigation not active"), 400
        from flask import request

        ok = unblock_provider(request.get_json(silent=True) or {})
        return jsonify(ok=ok), (200 if ok else 400)

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
