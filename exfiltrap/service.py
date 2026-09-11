"""ExfilTrap service — the privileged detection daemon.

Architecture (the privilege-separation boundary):

* THIS process owns packet capture and firewall mitigation. On Linux it
  runs as a dedicated user with only ``CAP_NET_RAW``/``CAP_NET_ADMIN``
  (granted by the systemd unit — never as full root); on Windows it runs
  as the installed Windows Service.
* It exposes a localhost-only REST API + the dashboard UI. The desktop app
  and any browser are plain unprivileged readers of that API.
* Run it as root (or via the installed systemd/Windows service):
  ``sudo python3 -m exfiltrap.service --iface <iface>``
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import queue
import signal
import sys
import threading
import time
from pathlib import Path

try:
    from exfiltrap import config, privileges
    from exfiltrap.classifier import DNSClassifier
    from exfiltrap.dashboard.app import create_app
    from exfiltrap.events import DNSQuery, DNSResponse
    from exfiltrap.pipeline import ExfilTrapPipeline
    from exfiltrap.storage import Storage
except ModuleNotFoundError as exc:
    print(
        f"ExFilTrap dependencies are missing ({exc.name}).\n"
        "Install them with one of:\n"
        "  python3 -m pip install --break-system-packages -r requirements.txt"
        "   (system python)\n"
        "  .venv/bin/python -m exfiltrap.service ...        (project virtualenv)\n"
        "Then re-run this command."
    )
    raise SystemExit(1)

log = logging.getLogger("exfiltrap.service")

_TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _import_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ServiceRuntime:
    """Shared state between the capture thread and the API."""

    def __init__(self, mode: str):
        self.mode = mode
        self.started_at = time.time()
        self.queries_processed = 0
        self._last_beat = time.monotonic()
        # iface -> (last supervision tick, ok flag)
        self._capture: dict[str, tuple[float, bool]] = {}
        self._lock = threading.Lock()

    def count(self) -> None:
        with self._lock:
            self.queries_processed += 1

    def beat(self) -> None:
        """Capture-loop liveness heartbeat (called every drain iteration,
        even when no packets arrive — idle capture is healthy capture)."""
        with self._lock:
            self._last_beat = time.monotonic()

    def capture_beat(self, iface: str, ok: bool = True) -> None:
        """Per-interface liveness mark from the capture supervisor.

        ``ok=True`` only ever comes from a supervisor tick that found the
        interface's sniffer thread alive — never from spawn, so a sniffer
        that dies instantly cannot fake health by respawning.
        """
        with self._lock:
            self._capture[iface] = (time.monotonic(), ok)

    def capture_ages(self) -> dict[str, float]:
        with self._lock:
            now = time.monotonic()
            return {i: now - t for i, (t, _ok) in self._capture.items()}

    def capture_any_alive(self, stall_limit: float) -> bool:
        """True while at least one supervised interface is confirmed alive.

        Vacuously true before any interface has been supervised (and in
        unit tests with a bare runtime), so legacy callers keep their
        behaviour. Total capture loss — no interface confirmed alive —
        is what justifies suspending the systemd watchdog pings.
        """
        with self._lock:
            now = time.monotonic()
            states = [(now - t, ok) for t, ok in self._capture.values()]
        return not states or any(ok and age <= stall_limit
                                 for age, ok in states)

    def heartbeat_age(self) -> float:
        with self._lock:
            return time.monotonic() - self._last_beat

    def status(self) -> dict:
        with self._lock:
            processed = self.queries_processed
            capture = dict(self._capture)
            now = time.monotonic()
        ifaces = {i: {"age_s": round(now - t, 1),
                      "ok": bool(ok and now - t <= 30.0)}
                  for i, (t, ok) in capture.items()}
        return {
            "service": "exfiltrap",
            "mode": self.mode,
            "uptime_s": round(time.time() - self.started_at, 1),
            "queries_processed": processed,
            "capture_heartbeat_age_s": round(self.heartbeat_age(), 2),
            "capture_ifaces": ifaces,
            "capture_healthy": (all(v["ok"] for v in ifaces.values())
                                if ifaces else None),
            **privileges.privilege_report(),
        }


class SystemdWatchdog:
    """sd_notify watchdog tied to capture-thread liveness.

    Under systemd (``WatchdogSec`` in the unit) the supervisor expects
    WATCHDOG=1 pings or it restarts the service. We only ping while the
    capture loop's heartbeat is fresh, so a dead or stuck capture thread
    triggers a supervised restart — process-alive-but-blind is exactly the
    failure mode a plain watchdog misses. Without systemd (NOTIFY_SOCKET
    unset) this is a harmless no-op.
    """

    def __init__(self, runtime: ServiceRuntime, stall_limit: float = 90.0):
        self.runtime = runtime
        self.stall_limit = stall_limit
        self.notify_socket = os.environ.get("NOTIFY_SOCKET")
        usec = os.environ.get("WATCHDOG_USEC")
        interval = 30.0
        if usec and usec.isdigit() and int(usec) > 0:
            interval = min(interval, int(usec) / 1_000_000 / 2)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _notify(self, state: str) -> None:
        if not self.notify_socket:
            return
        path = self.notify_socket
        if path.startswith("@"):
            path = "\0" + path[1:]
        import socket as _socket

        try:
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM) as sock:
                sock.connect(path)
                sock.send(state.encode())
        except OSError:
            pass  # supervisor gone: pings are best-effort

    def start(self) -> None:
        if not self.notify_socket:
            return
        self._notify("READY=1")

        def loop() -> None:
            while not self._stop.wait(self.interval):
                cap_ok = self.runtime.capture_any_alive(self.stall_limit)
                if cap_ok and self.runtime.heartbeat_age() <= self.stall_limit:
                    self._notify("WATCHDOG=1")
                elif not cap_ok:
                    log.error(
                        "every capture interface stale for %.0fs — watchdog "
                        "pings suspended (supervisor will restart us)",
                        self.stall_limit,
                    )
                else:
                    log.error(
                        "capture heartbeat stale for %.0fs — watchdog "
                        "pings suspended (supervisor will restart us)",
                        self.runtime.heartbeat_age(),
                    )

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._notify("STOPPING=1")
        if self._thread:
            self._thread.join(timeout=2.0)


class CaptureSupervisor:
    """Per-interface capture supervision with self-healing restarts.

    scapy's AsyncSniffer silently removes a socket that dies mid-capture
    and keeps running on the remaining interfaces (observed live: the
    uplink socket failed and the engine kept claiming both interfaces
    while /proc/net/packet showed only loopback). One supervised sniffer
    per interface turns that silent blindness into a logged error and an
    automatic restart, and feeds per-interface liveness into the status.
    """

    def __init__(self, ifaces: list[str], spawn, runtime: ServiceRuntime,
                 stop_event: threading.Event, poll_interval: float = 2.0):
        self.ifaces = ifaces
        self._spawn = spawn            # iface -> sniffer object with .thread
        self.runtime = runtime
        self.stop_event = stop_event
        self.poll_interval = poll_interval
        self.sniffers: dict[str, object] = {}
        self._failures: dict[str, int] = {}
        self._thread: threading.Thread | None = None

    def _alive(self, sniffer) -> bool:
        th = getattr(sniffer, "thread", None)
        return th is not None and th.is_alive()

    def spawn_one(self, iface: str):
        sniffer = self._spawn(iface)
        # Unconfirmed until a supervision tick sees the thread alive.
        self.runtime.capture_beat(iface, ok=False)
        log.info("capture on %s started", iface)
        return sniffer

    def _supervise(self) -> None:
        while not self.stop_event.wait(self.poll_interval):
            for iface in self.ifaces:
                sniffer = self.sniffers.get(iface)
                if sniffer is not None and self._alive(sniffer):
                    self.runtime.capture_beat(iface, ok=True)
                    self._failures[iface] = 0
                    continue
                exc = getattr(sniffer, "exception", None) if sniffer else None
                self.runtime.capture_beat(iface, ok=False)
                n = self._failures.get(iface, 0) + 1
                self._failures[iface] = n
                if n == 1:
                    log.error(
                        "capture on %s DIED%s — packets on this interface "
                        "are being missed; restarting",
                        iface, f" ({exc})" if exc else "")
                elif n % 15 == 0:
                    log.warning("capture on %s still failing (attempt %d)",
                                iface, n)
                try:
                    self.sniffers[iface] = self.spawn_one(iface)
                except Exception as exc2:  # noqa: BLE001
                    log.error("capture on %s restart failed: %s",
                              iface, exc2)

    def start(self) -> None:
        for iface in self.ifaces:
            try:
                self.sniffers[iface] = self.spawn_one(iface)
            except Exception as exc:  # noqa: BLE001
                self.runtime.capture_beat(iface, ok=False)
                log.error("capture on %s failed to start: %s — will retry",
                          iface, exc)
        self._thread = threading.Thread(target=self._supervise, daemon=True,
                                        name="capture-supervisor")
        self._thread.start()

    def stop_all(self) -> None:
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        for sniffer in self.sniffers.values():
            try:
                sniffer.stop(join=False)
            except Exception:  # noqa: BLE001 — shutdown is best-effort
                pass


def run_capture_feed(pipeline: ExfilTrapPipeline, runtime: ServiceRuntime,
                     stop_event: threading.Event, iface: str,
                     batch_size: int = 64) -> None:
    """Capture loop with micro-batched scoring.

    Per-row sklearn dispatch caps the naive loop at ~17 q/s on this class
    of machine; draining up to ``batch_size`` queued events and scoring
    them in one vectorized call sustains ~8x that, so 20k+ query bursts
    drain in minutes instead of hours.

    Each interface gets its own supervised sniffer (see CaptureSupervisor)
    feeding one shared queue.
    """
    import exfiltrap.capture as capture

    out_queue: queue.Queue = queue.Queue()
    ifaces = iface if isinstance(iface, list) else [iface]

    def _spawn_running(name: str):
        """Factory contract: return an already-STARTED sniffer — the
        supervisor only checks liveness and replaces dead instances."""
        sniffer = capture.make_sniffer(name, out_queue)
        sniffer.start()
        return sniffer

    def worker() -> None:
        while not stop_event.is_set():
            runtime.beat()  # capture-loop liveness, even when idle
            try:
                first = out_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            events = [first]
            while len(events) < batch_size:
                try:
                    events.append(out_queue.get_nowait())
                except queue.Empty:
                    break
            queries = [e for e in events if isinstance(e, DNSQuery)]
            responses = [e for e in events if isinstance(e, DNSResponse)]
            # Resilience boundary: one bad packet must never kill the loop.
            try:
                if queries:
                    pipeline.process_many(queries)
                for r in responses:
                    pipeline.process_response(r)
            except Exception as exc:  # noqa: BLE001
                log.exception("processing failed for batch of %d: %s",
                              len(events), exc)
            for _ in events:
                runtime.count()

    thread = threading.Thread(target=worker, daemon=True)
    supervisor = CaptureSupervisor(ifaces, _spawn_running, runtime, stop_event)
    thread.start()
    supervisor.start()
    stop_event.wait()
    supervisor.stop_all()
    thread.join(timeout=3.0)


def resolve_interfaces(cli_iface: str | None) -> list[str] | None:
    """Resolve the capture target list from the --iface argument.

    Default: the internet (default-route) interface PLUS loopback — modern
    desktops answer applications from a local resolver stub on `lo`
    (systemd-resolved at 127.0.0.53), so watching only the uplink misses
    most queries. 'any' captures every interface; an explicit name wins.
    Returns None when auto-detection fails (caller exits cleanly).
    """
    from exfiltrap import netif

    if not cli_iface:
        detected = netif.default_interface()
        ifaces = [i for i in (detected, "lo") if i]
        if not ifaces:
            print(
                "could not auto-detect the internet interface.\n"
                "Available interfaces:\n  "
                + "\n  ".join(netif.list_interfaces())
                + "\nPass one explicitly with --iface."
            )
            return None
        return ifaces
    if cli_iface.lower() in ("any", "all"):
        return ["any"]
    if cli_iface.lower() in ("auto", "default"):
        detected = netif.default_interface()
        if not detected:
            print("could not auto-detect the internet interface.")
            return None
        return [detected]
    return [cli_iface]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m exfiltrap.service",
        description="ExfilTrap detection service (capture + API + dashboard)",
    )
    parser.add_argument("--iface", default=None,
                        help="interface to capture (default: 'any' — DNS on "
                             "every interface, including the local resolver "
                             "stub on loopback)")
    parser.add_argument("--db", default=None)
    parser.add_argument("--flush-every", type=int, default=50,
                        help="rows buffered before a SQLite commit")
    parser.add_argument("--api-host", default="127.0.0.1",
                        help="API bind address (default: localhost only)")
    parser.add_argument("--api-port", type=int, default=5050)
    parser.add_argument("--mitigation", choices=("log", "auto", "iptables", "netsh"),
                        default="log",
                        help="log: record only; auto/iptables/netsh: firewall rules")
    parser.add_argument("--execute", action="store_true",
                        help="actually execute firewall commands (default: dry-run)")
    parser.add_argument("--i-know-this-is-isolated", action="store_true",
                        help="explicit override for host-firewall paths (Linux)")
    parser.add_argument("--classifier", default=None)
    parser.add_argument("--fresh-db", action="store_true",
                        help="start with an empty database (removes old runs)")
    parser.add_argument("--block-ttl", type=float, default=3600.0,
                        help="seconds before a block auto-unbans (0=never)")
    parser.add_argument("--allowlist", default="",
                        help="comma-separated IPs never blocked")
    parser.add_argument("--mute-domain", default="",
                        help="comma-separated domains whose queries are "
                             "stored but capped at LOW (own-host telemetry)")
    parser.add_argument("--alert", choices=("none", "syslog"), default=None,
                        help="SIEM alerting for HIGH/CONFIRMED detections")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    resolved = resolve_interfaces(args.iface)
    if resolved is None:
        return 2
    args.iface = resolved
    print("capturing DNS on: " + ", ".join(resolved))

    # Environment fallbacks used by the systemd unit (packaging/linux):
    # the unit passes configuration via Environment= so operators can
    # override it with a drop-in without editing ExecStart.
    if not args.db:
        args.db = os.environ.get("EXFILTRAP_DB")
    if args.api_port == 5050 and os.environ.get("EXFILTRAP_API_PORT"):
        args.api_port = int(os.environ["EXFILTRAP_API_PORT"])
    if not args.execute and os.environ.get("EXFILTRAP_EXECUTE") == "1":
        args.execute = True
    if args.mitigation == "log" and os.environ.get("EXFILTRAP_MITIGATION"):
        args.mitigation = os.environ["EXFILTRAP_MITIGATION"]
    if args.alert is None:
        args.alert = os.environ.get("EXFILTRAP_ALERT", "none")
    if not args.db:
        if getattr(sys, "frozen", False):
            # Frozen engine launched from its package (AppImage mount, deb
            # resource dir): the executable's own directory can be READ-ONLY
            # (AppImage squashfs), so the database defaults to a system
            # data path instead of crashing SQLite at startup.
            for data_dir in ("/var/lib/exfiltrap",
                             os.path.expanduser("~/.local/share/exfiltrap"),
                             "/tmp"):
                try:
                    os.makedirs(data_dir, exist_ok=True)
                    args.db = os.path.join(data_dir, "exfiltrap.db")
                    break
                except OSError:
                    continue
        if not args.db:
            args.db = config.DB_PATH
    if args.fresh_db:
        import glob as _glob

        for stale in [args.db] + _glob.glob(args.db + "-*") + \
                     [str(Path(args.db).with_suffix("")) + ".state.json"]:
            try:
                os.remove(stale)
                print(f"fresh-db: removed {stale}")
            except OSError:
                pass

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not privileges.has_capture_capability():
        print(
            "ERROR: this process cannot capture packets on this interface.\n"
            "       Run me via the installed service"
            " (`systemctl start exfiltrap` on Linux, the Windows service on\n"
            "       Windows), or interactively with sudo for lab use.\n"
            "       Current privileges:\n"
            + "\n".join(f"         {k:18s} {v}"
                         for k, v in privileges.privilege_report().items()),
            file=sys.stderr,
        )
        return 2

    from exfiltrap.mitigation import LogOnlyMitigation, make_mitigation

    if args.mitigation == "log":
        # Log-only backend: detections and block decisions are recorded
        # (and reversible from the dashboard) without touching any firewall.
        mitigation = LogOnlyMitigation()
    else:
        mitigation = make_mitigation(
            args.mitigation if args.mitigation != "auto" else "auto",
            dry_run=not args.execute,
            override_flag=(config.IPTABLES_OVERRIDE_FLAG
                           if args.i_know_this_is_isolated else ""),
        )

    storage = Storage(args.db, flush_every=args.flush_every)
    from exfiltrap.alerting import make_alerter
    from exfiltrap import session_tracker as st_mod

    alerter = make_alerter(args.alert)
    from exfiltrap.policy import make_policy

    # Persistent allowlist/mute: CLI seeds merge into the DB (idempotent)
    # so operator decisions survive restarts; the DB is the source of truth.
    for ip in [ip for ip in args.allowlist.split(",") if ip]:
        storage.allowlist_add(ip, note="cli --allowlist")
    for dom in [d for d in args.mute_domain.split(",") if d]:
        storage.muted_add(dom, note="cli --mute-domain")
    mitigation = make_policy(
        mitigation,
        allowlist=[a["ip"] for a in storage.allowlist_list()],
        block_ttl=args.block_ttl or 1e18,
    )
    pipeline = ExfilTrapPipeline(
        classifier_path=args.classifier,
        mitigation=mitigation,
        storage=storage,
        alerter=alerter,
    )
    pipeline.set_muted_domains([m["domain"] for m in storage.muted_list()])
    # Warm restart: restore tracker/baseline state saved next to the DB.
    state_path = (args.db or "exfiltrap.db") + ".state.json"
    if args.iface and st_mod.load_state(pipeline.tracker, state_path):
        log.info("restored session/baseline state from %s", state_path)
    iface_label = (args.iface if isinstance(args.iface, str)
                   else "+".join(args.iface))
    runtime = ServiceRuntime(mode=f"live:{iface_label}")
    stop_event = threading.Event()

    def _request_stop(signum, _frame) -> None:
        stop_event.set()
        # werkzeug's serve loop only unwinds on KeyboardInterrupt; SIGTERM
        # otherwise leaves the process alive as an orphan (observed in the
        # live lab). Give graceful shutdown 5 seconds, then force-exit with
        # the database flushed.
        def _finalizer() -> None:
            time.sleep(5.0)
            try:
                storage.close()
            finally:
                os._exit(0)

        threading.Thread(target=_finalizer, daemon=True).start()

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    feed = threading.Thread(
        target=run_capture_feed,
        args=(pipeline, runtime, stop_event, args.iface),
        daemon=True,
    )
    feed.start()

    watchdog = SystemdWatchdog(runtime)
    watchdog.start()

    # TTL reaper + periodic state snapshot (both best-effort).
    def maintenance() -> None:
        while not stop_event.wait(30.0):
            if mitigation is not None and hasattr(mitigation, "reap_expired"):
                freed = mitigation.reap_expired()
                for ip in freed:
                    log.info("block TTL expired for %s — unbanned", ip)
                    storage.log_block(time.time(), ip, "UNBLOCKED")
            if args.iface:
                try:
                    st_mod.save_state(pipeline.tracker, state_path)
                except OSError as exc:
                    log.warning("state snapshot failed: %s", exc)

    threading.Thread(target=maintenance, daemon=True).start()

    def _sessions_snapshot() -> list[dict]:
        try:
            snap = pipeline.tracker.snapshot()
        except Exception:  # noqa: BLE001 — the dashboard can live without it
            return []
        return [
            {
                "src_ip": s.src_ip,
                "query_count": s.query_count,
                "mean_mass": round(s.mean_mass, 3),
                "cumulative_mass": round(s.cumulative_mass, 1),
                "interval_cv": (round(s.interval_cv, 3)
                                if s.interval_cv is not None else None),
                "slow_drip": s.slow_drip_candidate,
                "beacon": s.beacon_candidate,
                "last_seen": round(s.last_timestamp, 1),
            }
            for s in snap.values()
        ]

    def _unblock(payload: dict) -> bool:
        ip = (payload or {}).get("src_ip", "")
        ok = True
        try:
            ok = bool(mitigation.unblock(ip))
        except Exception as exc:  # noqa: BLE001 — the list must stay operable
            log.warning("firewall unblock failed for %s: %s", ip, exc)
        # The blocked-list UI reads this table; it is the source of truth.
        return storage.remove_block(ip) or ok

    # Persistent allowlist/mute: writes go to the DB (source of truth) AND
    # the live policy/pipeline state, so changes apply without a restart.
    def _allowlist_add(payload: dict) -> bool:
        p = payload or {}
        ip = (p.get("ip") or "").strip()
        if not ip:
            return False
        storage.allowlist_add(ip, note=p.get("note", "dashboard"))
        getattr(mitigation, "allowlist_add", lambda _: None)(ip)
        log.info("allowlist: %s added (persistent)", ip)
        return True

    def _allowlist_remove(payload: dict) -> bool:
        ip = (payload or {}).get("ip", "")
        getattr(mitigation, "allowlist_remove", lambda _: None)(ip)
        return storage.allowlist_remove(ip)

    def _mute_add(payload: dict) -> bool:
        p = payload or {}
        dom = (p.get("domain") or "").strip().lower()
        if not dom:
            return False
        storage.muted_add(dom, note=p.get("note", "dashboard"))
        muted = set(getattr(pipeline, "_muted", set())) | {dom}
        pipeline.set_muted_domains(muted)
        log.info("muted domain: %s added (persistent)", dom)
        return True

    def _mute_remove(payload: dict) -> bool:
        dom = (payload or {}).get("domain", "")
        muted = set(getattr(pipeline, "_muted", set())) - {dom.lower()}
        pipeline.set_muted_domains(muted)
        return storage.muted_remove(dom)

    app = create_app(args.db, status_provider=runtime.status,
                     sessions_provider=_sessions_snapshot,
                     unblock_provider=_unblock,
                     allowlist_provider={"list": storage.allowlist_list,
                                         "add": _allowlist_add,
                                         "remove": _allowlist_remove},
                     mute_provider={"list": storage.muted_list,
                                    "add": _mute_add,
                                    "remove": _mute_remove})
    log.info("API + dashboard on http://%s:%d (Ctrl+C to stop)",
             args.api_host, args.api_port)
    try:
        app.run(host=args.api_host, port=args.api_port,
                threaded=True, debug=False, use_reloader=False)
    finally:
        watchdog.stop()
        stop_event.set()
        feed.join(timeout=3.0)
        storage.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
