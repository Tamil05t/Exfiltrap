"""M9 — Flask dashboard: live feed, block list, queries-vs-flagged chart.

Reads the SQLite database written by the pipeline. Run with:
    python3 -m exfiltrap.dashboard [--db PATH] [--port N]
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import webbrowser

from flask import Flask, jsonify, render_template, request

from exfiltrap import config
from exfiltrap.storage import Storage


def create_app(db_path=None, status_provider=None, sessions_provider=None,
               unblock_provider=None, allowlist_provider=None,
               mute_provider=None, sinkhole_provider=None) -> Flask:
    """Flask app serving the dashboard UI and its JSON API.

    ``status_provider`` (used by the service mode) returns a dict of live
    service facts — running mode, uptime, processed counts, privileges —
    surfaced at ``/api/status``. ``sessions_provider`` returns the live
    session-tracker snapshot for ``/api/sessions``. ``unblock_provider``,
    ``allowlist_provider`` and ``mute_provider`` are dicts of callables
    (``list``/``add``/``remove``) that let the service apply changes to its
    LIVE state; the DB is updated either way and stays the source of truth.
    ``sinkhole_provider`` exposes the domain sinkhole's live entries
    (``list``), its true armed state (``enabled``), a full clear
    (``clear``) and live arming/disarming (``set``) for the responses
    console.
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
        # Each call aggregates the whole queries table (measured 1.4 s at
        # ~100k rows on the shipped build) — under several pollers that alone
        # saturates the API and verdict reads start timing out, so rapid
        # polls are collapsed onto one computation.
        #
        # The TTL must stay WELL BELOW the console's poll interval. It was
        # 2.0 s against a 2 s client poll, which made consecutive polls
        # alternate between fresh and cache-hit: the counters sat still for
        # one beat and then jumped, which reads as "the numbers are stuck /
        # updating slowly". 0.5 s still absorbs a burst of concurrent
        # pollers (several tabs, a page load firing every route at once)
        # without ever serving anything older than half a second.
        storage: Storage = app.config["STORAGE"]
        now = time.monotonic()
        cache = app.config.setdefault("_STATS_CACHE", {})
        hit = cache.get("v")
        if hit is not None and now - hit[0] < 0.5:
            return jsonify(hit[1])
        body = dict(
            totals=storage.totals(),
            levels=storage.risk_distribution(),
            response_flags=storage.response_flag_count(),
            timeseries=storage.timeseries(bucket_seconds=60, limit=120),
            top_sources=storage.top_sources(8),
            top_domains=storage.top_flagged_domains(6),
        )
        cache["v"] = (now, body)
        return jsonify(body)

    @app.route("/api/status")
    def status():
        if status_provider is None:
            return jsonify(service="standalone-dashboard",
                           db_path=app.config.get("DB_PATH"))
        body = dict(status_provider())
        # The System → Storage card shows where the evidence lives. The
        # engine's own privilege report does not carry the DB path, and the
        # dashboard is the component that actually knows it, so merge it in
        # here instead of leaving the row blank.
        body.setdefault("db_path", app.config.get("DB_PATH"))
        return jsonify(body)

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

    # ---- sinkhole console + evidence export ------------------------------
    @app.route("/api/sinkhole")
    def sinkhole_list():
        prov = sinkhole_provider or {}
        live = prov.get("list")
        is_on = prov.get("enabled")
        storage: Storage = app.config["STORAGE"]
        return jsonify(domains=live() if live else [],
                       hits=storage.sinkhole_hits_recent(100),
                       # This must report the REAL state. The provider dict
                       # exists even when the sinkhole is disarmed, so the
                       # old bool(provider) check always said True and the
                       # console showed an armed sinkhole that was not there.
                       enabled=bool(is_on()) if is_on else False,
                       armable=bool(prov.get("set")))

    @app.route("/api/sinkhole", methods=["POST"])
    def sinkhole_set():
        """Arm or disarm the domain sinkhole from the console.

        ``{"enabled": true}`` arms it (hosts-file 0.0.0.0 intercepts for
        convicted domains), ``{"enabled": false}`` disarms it and removes
        every ExfilTrap-managed hosts entry. Applies live — the policy picks
        up the change on the next query, no restart.
        """
        prov = sinkhole_provider or {}
        setter = prov.get("set")
        if setter is None:
            return jsonify(ok=False, enabled=False,
                           error="sinkhole control is only available when "
                                 "the engine runs in service mode"), 501
        body = request.get_json(silent=True) or {}
        try:
            ok = bool(setter(body))
        except Exception as exc:  # noqa: BLE001 — report it to the console
            return jsonify(ok=False, error=str(exc)), 500
        live = prov.get("list")
        is_on = prov.get("enabled")
        storage: Storage = app.config["STORAGE"]
        return jsonify(ok=ok,
                       enabled=bool(is_on()) if is_on else ok,
                       domains=live() if live else [],
                       hits=storage.sinkhole_hits_recent(100))

    @app.route("/api/sinkhole", methods=["DELETE"])
    def sinkhole_clear():
        clear = (sinkhole_provider or {}).get("clear")
        freed = clear() if clear else 0
        return jsonify(ok=True, freed=freed)

    @app.route("/api/stream")
    def stream():
        """Server-Sent Events: new queries + alerts pushed as soon as they
        land, so the console feels live without hammering /api/queries.

        The poll interval is deliberately short. At 1.0 s a burst of DNS
        lookups (a page load fires 10-20 resolutions inside ~50 ms) all
        landed in the SAME frame, so the console appeared to sit still and
        then dump a dozen rows at once. A 0.25 s tick keeps the batch size
        down to a handful, which reads as a stream instead of a dump. The
        cost is one indexed `id > ?` lookup four times a second — trivial
        for SQLite.

        Reads trail the DB ids (the pipeline is the only writer), which
        keeps this decoupled from the detection code and working in
        standalone-dashboard mode too. Flask serves each stream from a
        worker thread — one console, one stream.
        """
        from flask import Response

        storage: Storage = app.config["STORAGE"]

        def gen():
            last_q = storage.max_query_id()
            last_e = storage.max_event_id()
            yield "retry: 3000\n\n"
            while True:
                try:
                    queries = storage.queries_since(last_q, 200)
                    events = storage.events_since(last_e, 50)
                    if queries or events:
                        last_q = queries[-1]["id"] if queries else last_q
                        last_e = events[-1]["id"] if events else last_e
                        for e in events:
                            e.pop("id", None)
                        payload = json.dumps({"queries": queries,
                                              "events": events})
                        yield f"data: {payload}\n\n"
                    else:
                        yield ": ping\n\n"
                except GeneratorExit:
                    raise
                except Exception:  # noqa: BLE001 — the stream must survive
                    yield ": err\n\n"
                time.sleep(0.25)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    @app.route("/api/export")
    def export_evidence():
        """Evidence pack (JSON): queries, alerts, responses, sinkhole hits
        inside the window — one citable artifact per incident."""
        from flask import Response, request as _req

        storage: Storage = app.config["STORAGE"]
        try:
            window = float(_req.args.get("window", 3600.0))
        except ValueError:
            window = 3600.0
        window = min(max(window, 60.0), 7 * 24 * 3600.0)
        body = storage.export_json(window_seconds=window)
        return Response(json.dumps(body, indent=2), mimetype="application/json")

    @app.route("/api/purge", methods=["POST"])
    def purge():
        """Delete captured evidence — the retention control on System.

        Destructive, so it is POST-only AND requires the caller to echo the
        scope back as ``confirm``. A stray request, a form post from another
        origin, or a truncated body can therefore never wipe the log.

        Scopes (see ``Storage._PURGE_SCOPES``): ``queries`` (the raw query
        log only — triage events and the response ledger survive),
        ``evidence`` (queries + risk events + sinkhole hits) and ``all``
        (those plus the response ledger). The operator allowlist and the
        muted-domain list are never touched by any scope.
        """
        from flask import request as _req

        storage: Storage = app.config["STORAGE"]
        body = _req.get_json(silent=True) or {}
        scope = str(body.get("scope") or "queries")
        if str(body.get("confirm") or "") != scope:
            return jsonify(ok=False,
                           error="confirmation missing — send "
                                 '{"scope": "<scope>", "confirm": "<scope>"}'), 400
        if scope not in storage.PURGE_SCOPES:
            return jsonify(ok=False,
                           error=f"unknown scope {scope!r}"), 400
        try:
            removed = storage.purge(scope)
        except Exception as exc:  # noqa: BLE001 — report, never 500 silently
            return jsonify(ok=False, error=str(exc)), 500
        # Drop the aggregate cache so the counters reflect the purge on the
        # very next poll instead of showing the old totals for one more beat.
        app.config.setdefault("_STATS_CACHE", {}).pop("v", None)
        return jsonify(ok=True, scope=scope, removed=removed)

    @app.teardown_appcontext
    def _close(_exc):
        pass  # connection lives for the app lifetime; nothing per-request

    return app


def _service_console_url(timeout: float = 0.8) -> str | None:
    """URL of the LIVE service console, or ``None`` if no service answers.

    The installed product runs the detection engine as a Windows Service /
    systemd unit, and that process already serves the dashboard UI on the
    service API port. That console is the real one — live status, sessions,
    sinkhole control — whereas a second standalone copy started by the
    launcher would show the same tables with no engine attached.

    Only a non-standalone ``/api/status`` counts, so a stray standalone
    dashboard on the same port can never masquerade as the service.
    """
    import urllib.error
    import urllib.request

    url = f"http://127.0.0.1:{config.SERVICE_API_PORT}"
    try:
        with urllib.request.urlopen(url + "/api/status", timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if body.get("service") == "standalone-dashboard":
        return None
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exfiltrap.dashboard")
    parser.add_argument("--db", default=None, help="SQLite path")
    parser.add_argument("--host", default=config.DASHBOARD_HOST)
    parser.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    parser.add_argument("--no-browser", action="store_true",
                        help="serve only — never launch a browser "
                             "(scripted / headless use)")
    args = parser.parse_args(argv)

    # Launcher path (Start Menu, `exfiltrap dashboard`, the installer's
    # postinstall step): if the engine service is up, open ITS console and
    # exit. Without this the shortcut spawned a second, data-less UI on a
    # different port and the browser was never opened at all — so the only
    # thing the user saw was Flask's "Running on http://..." log line.
    if args.db is None:
        service = _service_console_url()
        if service is not None:
            print(f"ExfilTrap engine is running — opening {service}")
            if not args.no_browser:
                webbrowser.open(service)
            return 0

    app = create_app(args.db)
    host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
    url = f"http://{host}:{args.port}"
    print(f"ExfilTrap standalone dashboard on {url}")
    if not args.no_browser:
        # Delayed so the browser cannot race the socket bind; Flask's own
        # banner is printed from the serving thread.
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
