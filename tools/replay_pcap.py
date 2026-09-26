"""Replay DNS traffic from a pcap through the full detection pipeline.

The shipped evaluation drives SYNTHETIC streams (eval/run_evaluation.py);
this tool drives the detector over ANY captured or public-dataset pcap —
CIC-Bell-DNS-EXF-2021, DSNet captures, your own tcpdump/wireshark dumps —
so detection claims can be checked against real wire data without a live
interface or root.

    .venv/bin/python tools/replay_pcap.py capture.pcap
    .venv/bin/python tools/replay_pcap.py attack.pcap --rf-only   # control
    .venv/bin/python tools/replay_pcap.py mix.pcap --json out.json

UDP and TCP DNS both parse (the same path as live capture). Packets are
fed in capture order with their capture timestamps, so the stateful
layers (session windows, beacons, baselines) behave exactly as live.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exfiltrap.events import DNSQuery, DNSResponse  # noqa: E402
from exfiltrap.features import base_domain  # noqa: E402
from exfiltrap.mitigation import LogOnlyMitigation  # noqa: E402
from exfiltrap.pipeline import ExfilTrapPipeline  # noqa: E402
from exfiltrap.storage import NullStorage  # noqa: E402


def iter_dns_events(pcap_path: str):
    """Stream (query|response) events from a pcap in capture order."""
    from scapy.all import PcapReader

    import exfiltrap.capture as capture

    with PcapReader(pcap_path) as packets:
        for pkt in packets:
            # packet_to_query handles both UDP and the TCP length-prefix
            # de-framing (same path as live capture); anything else is None.
            q = capture.packet_to_query(pkt)
            if q is not None:
                yield q
                continue
            r = capture.packet_to_response(pkt)
            if r is not None:
                yield r


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="replay_pcap",
        description="Replay a pcap through the ExfilTrap detector")
    parser.add_argument("pcap", help="pcap/pcapng file to replay")
    parser.add_argument("--rf-only", action="store_true",
                        help="control run: RF probability only")
    parser.add_argument("--json", default=None,
                        help="write the full verdict list to a JSON file")
    parser.add_argument("--limit", type=int, default=200000,
                        help="max events to replay")
    args = parser.parse_args(argv)

    if not Path(args.pcap).exists():
        print(f"error: {args.pcap} not found")
        return 2

    pipeline = ExfilTrapPipeline(rf_only=args.rf_only,
                                 mitigation=LogOnlyMitigation(),
                                 storage=NullStorage())

    n_q = n_r = 0
    verdicts: Counter[str] = Counter()
    confirmed: list[dict] = []
    domain_flags: Counter[str] = Counter()
    blocked: set[str] = set()
    last = None

    for event in iter_dns_events(args.pcap):
        if n_q + n_r >= args.limit:
            break
        if isinstance(event, DNSQuery):
            n_q += 1
            a = pipeline.process_query(event)
            verdicts[a.risk_level] += 1
            last = a
            if a.risk_level in ("HIGH", "CONFIRMED"):
                domain_flags[base_domain(a.qname)] += 1
            if a.confirmed_exfiltration:
                confirmed.append({"ts": a.timestamp, "qname": a.qname,
                                  "src": a.src_ip,
                                  "decoded": a.decoded_preview})
            if pipeline.mitigation.is_blocked(getattr(a, "src_ip", "")):
                blocked.add(a.src_ip)
        else:
            n_r += 1
            out = pipeline.process_response(event)
            if out is not None:
                verdicts[out.risk_level] += 1

    print(f"replayed {args.pcap}")
    print(f"  queries:    {n_q}")
    print(f"  responses:  {n_r}")
    print(f"  verdicts:   " + ", ".join(
        f"{k}={v}" for k, v in sorted(verdicts.items())) or "none")
    if domain_flags:
        print("  flagged domains (top 10):")
        for dom, n in domain_flags.most_common(10):
            print(f"    {n:6d}  {dom}")
    if blocked:
        print(f"  blocked sources: {', '.join(sorted(blocked))}")
    if confirmed:
        print(f"  confirmed decodes ({len(confirmed)}):")
        for c in confirmed[:10]:
            print(f"    {c['qname']} -> {c['decoded']}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({
                "pcap": args.pcap, "queries": n_q, "responses": n_r,
                "verdicts": dict(verdicts),
                "flagged_domains": dict(domain_flags),
                "blocked_sources": sorted(blocked),
                "confirmed": confirmed,
                "last_assessment": str(last),
            }, fh, indent=2)
        print(f"  full results -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
