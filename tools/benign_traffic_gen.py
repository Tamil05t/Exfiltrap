#!/usr/bin/env python3
"""Benign DNS traffic generator — legit-looking resolver noise for the lab.

Queries sampled from a real top-50k domain corpus (data/tranco_top_1m_sample.csv,
sourced from the Cisco Umbrella top-1M) with a realistic label mix and Poisson
interarrivals. Deterministic given a seed; pure logic needs no network.

SAFETY: the send path refuses any --target outside RFC1918/loopback ranges.
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
from exfiltrap.events import DNSQuery, LabeledQuery  # noqa: E402

_FALLBACK_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "netflix.com", "reddit.com", "github.com", "stackoverflow.com", "cloudflare.com",
    "microsoft.com", "apple.com", "mozilla.org", "ubuntu.com", "debian.org",
    "pypi.org", "npmjs.com", "openstreetmap.org", "bbc.co.uk", "cnn.com",
    "nytimes.com", "example.com", "iana.org", "example.org", "example.net",
]

_COMMON_LABELS = ("www", "api", "mail", "cdn", "static", "assets", "img", "login")


def load_domains(csv_path=None) -> list[str]:
    """Parse the rank,domain corpus; fall back to a built-in list if absent."""
    csv_path = Path(csv_path if csv_path is not None else config.TRANCO_CSV)
    domains: list[str] = []
    try:
        with csv_path.open() as fh:
            for line in fh:
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0].isdigit() and parts[1]:
                    domains.append(parts[1])
    except OSError:
        pass
    return domains or list(_FALLBACK_DOMAINS)


def generate_traffic(duration: float, qps: float = config.BENIGN_BASE_QPS,
                     start_time: float = 0.0,
                     src_ip: str = config.ATTACKER_IP,
                     seed: int = config.BENIGN_RANDOM_SEED,
                     domains: list[str] | None = None) -> list[LabeledQuery]:
    """Poisson-arrival benign resolver traffic over a virtual time span."""
    if duration <= 0:
        raise ValueError("duration must be positive")
    rng = random.Random(seed)
    domain_pool = domains if domains else load_domains()
    # Hash-bucket hostnames live on registrable (2-label) domains, exactly
    # like a tunnel's fixed 2-label C2 domain — keeping the label-count
    # feature matched between the classes.
    flat_domains = [d for d in domain_pool if d.count(".") == 1] or domain_pool

    n = max(1, int(duration * qps))
    records: list[LabeledQuery] = []
    t = start_time
    for _ in range(n):
        t += rng.expovariate(qps)
        roll = rng.random()
        if roll < 0.60:
            domain = rng.choice(domain_pool)
            qname = domain
        elif roll < 0.95:
            domain = rng.choice(domain_pool)
            qname = f"{rng.choice(_COMMON_LABELS)}.{domain}"
        else:
            # Machine-generated labels (hash-bucket hostnames, CDN cache
            # keys, git-style SHAs): hex of 4..10 whole bytes (so 8..20
            # EVEN-length labels) on a 2-label domain — the SAME per-query
            # distribution a stealthy hex tunnel must adopt. A benign client
            # emits these occasionally (~5%); a tunnel emits one every query.
            # That difference lives only in per-session accumulation.
            domain = rng.choice(flat_domains)
            sub = "".join(rng.choices("0123456789abcdef",
                                      k=rng.randint(4, 10) * 2))
            qname = f"{sub}.{domain}"
        records.append(LabeledQuery(
            query=DNSQuery(src_ip=src_ip, qname=qname, timestamp=t),
            is_malicious=False,
            meta={"domain": domain},
        ))
    return records


# ----------------------------------------------------------------------
def _validate_lab_target(target: str) -> None:
    addr = ipaddress.ip_address(target)
    if not (addr.is_private or addr.is_loopback):
        print(f"REFUSING non-lab target {target}: only RFC1918/loopback allowed",
              file=sys.stderr)
        raise SystemExit(2)


def send_queries(records: list[LabeledQuery], target: str,
                 source_ip: str | None = None,
                 port: int = config.DNS_PORT) -> None:
    """Real-time UDP DNS send (DNS-message bytes only — see attacker_client)."""
    _validate_lab_target(target)
    try:
        from scapy.all import DNS, DNSQR
    except ImportError:
        print("scapy is required for live sending: pip install scapy",
              file=sys.stderr)
        raise SystemExit(3)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if source_ip:
        sock.bind((source_ip, 0))
    prev_ts = None
    try:
        for rec in records:
            if prev_ts is not None:
                delay = rec.query.timestamp - prev_ts
                if delay > 0:
                    time.sleep(delay)
            msg = bytes(DNS(rd=1, qd=DNSQR(qname=rec.query.qname)))
            sock.sendto(msg, (target, port))
            prev_ts = rec.query.timestamp
    finally:
        sock.close()
    print(f"sent {len(records)} benign queries to {target}" +
          (f" from {source_ip}" if source_ip else ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benign_traffic_gen")
    parser.add_argument("--target", help="lab DNS gateway IP (RFC1918/loopback only)")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--qps", type=float, default=config.BENIGN_BASE_QPS)
    parser.add_argument("--seed", type=int, default=config.BENIGN_RANDOM_SEED)
    parser.add_argument("--domains-csv", type=Path, default=None)
    parser.add_argument("--source-ip", default=None,
                        help="local address to send from (multi-IP labs)")
    args = parser.parse_args(argv)

    domains = load_domains(args.domains_csv)
    records = generate_traffic(args.duration, args.qps, seed=args.seed,
                               domains=domains)
    if args.target:
        send_queries(records, args.target, source_ip=args.source_ip)
    else:
        print(f"dry-run ({len(records)} queries from {len(domains)} domains):")
        for rec in records[:5]:
            print(f"  t={rec.query.timestamp:9.2f}  {rec.query.qname}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
