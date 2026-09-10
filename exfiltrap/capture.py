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


def make_deduper() -> "DuplicateFilter":
    """Build a capture-path duplicate filter (one per capture feed).

    AF_PACKET on loopback delivers EVERY packet twice (once as the
    outgoing copy, once as the incoming copy — observed live: 88 DNS
    queries produced 176 stored rows). Doubled queries destroy the
    inter-arrival statistics the beacon detector lives on (gaps alternate
    0.0 s / 5.5 s → CV ≈ 1) and inflate every per-source count. The filter
    drops an event identical to one seen within the last few seconds.
    """
    return DuplicateFilter()


class DuplicateFilter:
    """Content+time keyed sliding window of recently seen capture events."""

    _MAX_KEYS = 512

    def __init__(self) -> None:
        import collections

        self._recent: collections.OrderedDict[tuple, None] = \
            collections.OrderedDict()
        self._lock = threading.Lock()

    def is_duplicate(self, event) -> bool:
        """True when this exact event was already admitted (loopback echo).

        The key is (event type, source, qname, timestamp at 10 ms
        resolution) — two genuine different queries never collide; the two
        copies of one loopback packet always do.
        """
        ts = getattr(event, "timestamp", None)
        if ts is None:
            return False
        key = (type(event).__name__, getattr(event, "src_ip", None),
               getattr(event, "client_ip", None),
               getattr(event, "qname", None), round(float(ts), 2))
        with self._lock:
            if key in self._recent:
                return True
            self._recent[key] = None
            self._recent.move_to_end(key)
            while len(self._recent) > self._MAX_KEYS:
                self._recent.popitem(last=False)
            return False


def _classify(pkt):
    """Sniffer callback body: queries and responses both reach the pipeline."""
    return packet_to_query(pkt) or packet_to_response(pkt)


def make_sniffer(iface: str | list[str],
                 out_queue: queue.Queue,
                 dedup: bool = True) -> AsyncSniffer:
    """Build (do not start) an async sniffer feeding the queue.

    ``dedup=True`` (default) drops loopback TX/RX echo duplicates before
    they reach the pipeline — see DuplicateFilter.
    """
    deduper = make_deduper() if dedup else None

    def _prn(pkt) -> None:
        event = _classify(pkt)
        if event is None:
            return
        if deduper is not None and deduper.is_duplicate(event):
            return
        out_queue.put(event)

    return AsyncSniffer(
        iface=iface,
        filter=config.CAPTURE_BPF_FILTER,
        prn=_prn,
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
