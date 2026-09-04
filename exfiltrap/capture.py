"""M1 — Traffic capture.

Scapy sniffer on a single interface (``veth-gw`` inside namespace ``nsA``
in the lab topology), filtered to UDP/53. Parsed queries are pushed onto a
thread-safe queue for the pipeline's processing thread.
"""

from __future__ import annotations

import queue
import threading

from scapy.all import AsyncSniffer  # noqa: F401  (re-exported for callers)
from scapy.all import DNS, IP, sniff

from exfiltrap import config
from exfiltrap.events import DNSQuery, DNSResponse


def packet_to_query(pkt) -> DNSQuery | None:
    """Pure scapy-packet -> DNSQuery conversion; None for anything else.

    # ASSUMPTION: the detector only needs queries (qr=0); responses carry
    # no exfiltrated payload and are ignored.
    """
    try:
        if DNS not in pkt or IP not in pkt:
            return None
        dns = pkt[DNS]
        if dns.qr != 0 or dns.qd is None:
            return None
        qname = bytes(dns.qd.qname).decode("utf-8", errors="replace")
        if qname.endswith("."):
            qname = qname[:-1]
        return DNSQuery(
            src_ip=pkt[IP].src,
            qname=qname,
            timestamp=float(pkt.time),
        )
    except Exception:
        # Malformed packets must never kill the capture loop.
        return None


def packet_to_response(pkt) -> DNSResponse | None:
    """Parse a DNS reply into its download-channel facts; None otherwise.

    A tunnel's C2 answers carry encoded data (TXT/NULL rdata): high
    per-answer byte mass and near-ceiling entropy. Ordinary answers
    (A/AAAA/CNAME) are small and low-entropy.
    """
    try:
        if DNS not in pkt or IP not in pkt:
            return None
        dns = pkt[DNS]
        if dns.qr != 1 or dns.qd is None or not dns.an:
            return None
        qname = bytes(dns.qd.qname).decode("utf-8", errors="replace")
        if qname.endswith("."):
            qname = qname[:-1]
        blob = bytearray()
        count = 0
        for rr in dns.an:
            try:
                raw = bytes(rr.rdata)
            except Exception:  # exotic types: fall back to the wire bytes
                raw = bytes(rr)[10:]
            blob += raw
            count += 1
        if not count:
            return None
        from exfiltrap.features import shannon_entropy

        return DNSResponse(
            client_ip=pkt[IP].dst,
            qname=qname,
            timestamp=float(pkt.time),
            answer_count=count,
            answer_bytes=len(blob),
            answer_entropy=shannon_entropy(blob.decode("latin-1")),
        )
    except Exception:
        return None


def _push(event, out_queue: queue.Queue) -> None:
    if event is not None:
        out_queue.put(event)


def _classify(pkt):
    """Sniffer callback body: queries and responses both reach the pipeline."""
    return packet_to_query(pkt) or packet_to_response(pkt)


def make_sniffer(iface: str, out_queue: queue.Queue) -> AsyncSniffer:
    """Build (do not start) an async sniffer feeding the queue."""
    return AsyncSniffer(
        iface=iface,
        filter=config.CAPTURE_BPF_FILTER,
        prn=lambda pkt: _push(_classify(pkt), out_queue),
        store=False,
    )


def run_blocking(iface: str, handler, duration: float | None = None) -> None:
    """Sniff on ``iface`` and call ``handler(DNSQuery)`` for every query.

    ``duration=None`` means until KeyboardInterrupt.
    """
    def callback(pkt):
        event = packet_to_query(pkt)
        if event is not None:
            handler(event)

    kwargs = {"iface": iface, "filter": config.CAPTURE_BPF_FILTER,
              "prn": callback, "store": False}
    if duration is not None:
        kwargs["timeout"] = duration
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        return


def drain_loop(out_queue: queue.Queue, handler, stop_event: threading.Event,
               poll_timeout: float = 0.5, on_tick=None) -> None:
    """Worker loop: pull DNSQuery events off the queue into the handler.

    ``on_tick`` (optional) fires every iteration — including idle timeouts —
    and drives the service's capture-liveness heartbeat/watchdog.
    """
    while not stop_event.is_set():
        if on_tick is not None:
            on_tick()
        try:
            event = out_queue.get(timeout=poll_timeout)
        except queue.Empty:
            continue
        handler(event)
