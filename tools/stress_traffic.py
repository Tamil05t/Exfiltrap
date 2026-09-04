#!/usr/bin/env python3
"""High-rate DNS traffic generator for stress testing (lab targets only).

Sends plain A-queries for a caller-supplied domain list at a target rate.
DNS messages are built once per unique qname and cached; only the 2-byte
transaction ID is rewritten per send, so a single Python process sustains
thousands of queries per second.

SAFETY: refuses non-RFC1918/loopback targets.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exfiltrap import config  # noqa: E402

PREFIXES = ("", "www.", "api.", "cdn.", "static.", "mail.", "assets.")

MALICIOUS_NAMES = (
    "ransomware.com", "c2server.com", "botnet-zombie.io",
    "malware-download.net", "darkweb-c2.ru", "keylogger-shop.com",
    "zeus-botnet.com", "trojan-drop.site", "paydecrypt-btc.top",
    "credentialharvest.biz",
)
EVERYDAY_NAMES = (
    "google.com", "youtube.com", "facebook.com", "github.com",
    "netflix.com", "cloudflare.com", "wikipedia.org", "reddit.com",
)
RANDOM_TLDS = ("com", "net", "io", "ru", "xyz", "top", "info", "biz")


def build_message(qname: str) -> bytes:
    from scapy.all import DNS, DNSQR

    return bytes(DNS(id=0, rd=1, qd=DNSQR(qname=qname)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stress_traffic")
    parser.add_argument("--target", required=True)
    parser.add_argument("--domains-file", type=Path, default=None,
                        help="one domain per line (else the built-in mix)")
    parser.add_argument("--profile", choices=("file", "random"), default="file",
                        help="file: --domains-file list; random: fresh DGA-style "
                             "domains mixed with malicious + everyday names")
    parser.add_argument("--qps", type=float, default=10.0)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--source-ip", default=None)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--port", type=int, default=config.DNS_PORT)
    args = parser.parse_args(argv)

    addr = ipaddress.ip_address(args.target)
    if not (addr.is_private or addr.is_loopback):
        print(f"REFUSING non-lab target {args.target}", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)

    # Pre-built corpus of messages; in random mode the corpus is DGA-fresh:
    # unique random labels that have never been seen before (the honest
    # worst case for a per-query detector), interleaved at send time with
    # malicious-LOOKING and everyday names.
    cache = {}
    if args.profile == "random":
        n_fresh = max(200, int(args.qps * args.duration * 0.5))
        for _ in range(n_fresh):
            label = "".join(rng.choices(
                "abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(6, 14)))
            name = f"{label}.{rng.choice(RANDOM_TLDS)}"
            cache[name] = bytearray(build_message(name))
        mix = ([d for d in MALICIOUS_NAMES for _ in range(8)]
               + [d for d in EVERYDAY_NAMES for _ in range(12)])
        rng.shuffle(mix)
        for d in mix:
            for p in ("", "www.", "api."):
                cache[f"{p}{d}"] = bytearray(build_message(f"{p}{d}"))
        weights = None  # uniform over the mixed corpus: ~fresh-heavy
    else:
        if args.domains_file:
            domains = [line.strip() for line
                       in args.domains_file.read_text().splitlines()
                       if line.strip()]
        else:
            domains = list(EVERYDAY_NAMES)
        for d in domains:
            for p in PREFIXES:
                cache[f"{p}{d}"] = bytearray(build_message(f"{p}{d}"))
    names = list(cache)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.source_ip:
        sock.bind((args.source_ip, 0))

    interval = 1.0 / args.qps if args.qps > 0 else 0.0
    n = max(1, int(args.duration * args.qps))
    sent = 0
    t0 = time.monotonic()
    # Organic pacing: +/-20% jitter so the stream is NOT a metronome —
    # perfectly periodic clients legitimately trip the beacon detector.
    gaps = [interval * rng.uniform(0.8, 1.2) for _ in range(n)]
    target_t = t0
    for i in range(n):
        target_t += gaps[i]
        delay = target_t - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        msg = cache[rng.choice(names)]
        msg[0:2] = rng.randbytes(2)  # fresh transaction ID
        sock.sendto(bytes(msg), (args.target, args.port))
        sent += 1
    sock.close()
    elapsed = time.monotonic() - t0
    print(f"sent {sent} queries in {elapsed:.1f}s "
          f"({sent / max(elapsed, 0.001):.0f} q/s effective)"
          + (f" from {args.source_ip}" if args.source_ip else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
