"""M1 — Traffic capture.

Scapy sniffer on a single interface (``veth-gw`` inside namespace ``nsA``
in the lab topology), filtered to UDP/53. Parsed queries are pushed onto a
thread-safe queue for the pipeline's processing thread.

Every parsed event carries its **context**, because on a real single-host
deployment the source IP alone is always the machine itself:

* ``dst_ip`` — the resolver the query was sent to / the server that answered,
* ``sport`` — the UDP source port (the process-attribution key),
* ``iface`` — which capture interface the packet arrived on,
* ``process`` — best-effort socket owner via /proc (Linux only).
* responses additionally carry the A/AAAA answer IPs as evidence.
"""

from __future__ import annotations

import ipaddress
import queue
import threading

from scapy.all import AsyncSniffer  # noqa: F401  (re-exported for callers)
from scapy.all import DNS, IP, sniff

from exfiltrap import config
from exfiltrap.events import DNSQuery, DNSResponse


def _dns_layer(pkt):
    """Extract the DNS message from a UDP or TCP packet; None otherwise.

    DNS over TCP carries a 2-byte message-length prefix before the message
    (RFC 1035 §4.2.2). Scapy does not always bind the DNS dissector onto
    TCP payloads, so the prefix is stripped and the message parsed
    explicitly — without this, an entire TCP tunnel is invisible.
    """
    if DNS in pkt:
        return pkt[DNS]
    from scapy.all import TCP

    if TCP in pkt:
        raw = bytes(pkt[TCP].payload)
        if len(raw) <= 2:
            return None
        from scapy.all import DNS as _DNS

        try:
            return _DNS(raw[2:])   # strip the length prefix
        except Exception:
            return None
    return None


def _dns_qname(dns) -> str:
    qname = bytes(dns.qd.qname).decode("utf-8", errors="replace")
    return qname[:-1] if qname.endswith(".") else qname


def _answer_ips(dns) -> tuple[str, ...]:
    """A/AAAA records from the answer section — the resolved addresses.

    rdata form varies by scapy version (2.6 returns dotted strings for A;
    older builds return raw 4/16-byte blobs) — both are accepted.
    """
    import ipaddress

    ips: list[str] = []
    for rr in dns.an:
        try:
            if rr.type not in (1, 28) or rr.rdata is None:
                continue
            if rr.type == 1:
                data = rr.rdata
                if not isinstance(data, str):
                    data = str(ipaddress.IPv4Address(bytes(data)))
                ipaddress.IPv4Address(data)   # validation
                ips.append(data)
            else:
                data = rr.rdata
                if isinstance(data, str):
                    ipaddress.IPv6Address(data)  # validation
                    ips.append(data)
                else:
                    ips.append(str(ipaddress.IPv6Address(bytes(data))))
        except Exception:  # noqa: BLE001 — evidence is best effort
            continue
    return tuple(ips)


def packet_to_query(pkt, iface: str = "") -> DNSQuery | None:
    """Pure scapy-packet -> DNSQuery conversion; None for anything else.

    # ASSUMPTION: the detector only needs queries (qr=0); responses carry
    # no exfiltrated payload and are ignored.
    """
    try:
        dns = _dns_layer(pkt)
        if dns is None or IP not in pkt:
            return None
        if dns.qr != 0 or dns.qd is None:
            return None
        ip = pkt[IP]
        sport = int(getattr(ip, "sport", 0) or 0)
        from exfiltrap import procattr

        return DNSQuery(
            src_ip=ip.src,
            qname=_dns_qname(dns),
            timestamp=float(pkt.time),
            dst_ip=ip.dst,
            sport=sport,
            iface=iface,
            process=procattr.resolve(ip.src, sport) or "",
            qtype=int(dns.qd.qtype),
            qdcount=int(dns.qdcount or 1),
            opcode=int(dns.opcode),
            z=int(getattr(dns, "z", 0) or 0),
        )
    except Exception:
        # Malformed packets must never kill the capture loop.
        return None


def packet_to_response(pkt, iface: str = "") -> DNSResponse | None:
    """Parse a DNS reply into its download-channel facts; None otherwise.

    A tunnel's C2 answers carry encoded data (TXT/NULL rdata): high
    per-answer byte mass and near-ceiling entropy. Ordinary answers
    (A/AAAA/CNAME) are small and low-entropy.
    """
    try:
        dns = _dns_layer(pkt)
        if dns is None or IP not in pkt:
            return None
        if dns.qr != 1 or dns.qd is None:
            return None
        qname = _dns_qname(dns)
        # NXDOMAIN/SERVFAIL answers carry no records — they are kept anyway:
        # the rcode-ratio signal needs them (an attacker's fake zone refuses
        # everything while the client pumps labels at it).
        blob = bytearray()
        count = 0
        for rr in (dns.an or []):
            try:
                raw = bytes(rr.rdata)
            except Exception:  # exotic types: fall back to the wire bytes
                raw = bytes(rr)[10:]
            blob += raw
            count += 1
        from exfiltrap.features import shannon_entropy

        return DNSResponse(
            client_ip=pkt[IP].dst,
            qname=qname,
            timestamp=float(pkt.time),
            answer_count=count,
            answer_bytes=len(blob),
            answer_entropy=shannon_entropy(blob.decode("latin-1")),
            resolver_ip=pkt[IP].src,
            answer_ips=_answer_ips(dns),
            rcode=int(dns.rcode),
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
        # qtype + sport in the key: a normal getaddrinfo lookup sends an A
        # and an AAAA query back-to-back with the SAME qname well inside the
        # 10 ms window — keying on name alone silently discarded the AAAA.
        key = (type(event).__name__, getattr(event, "src_ip", None),
               getattr(event, "client_ip", None),
               getattr(event, "qname", None),
               getattr(event, "qtype", 0), getattr(event, "sport", 0),
               round(float(ts), 2))
        with self._lock:
            if key in self._recent:
                return True
            self._recent[key] = None
            self._recent.move_to_end(key)
            while len(self._recent) > self._MAX_KEYS:
                self._recent.popitem(last=False)
            return False


def _classify(pkt, iface: str = ""):
    """Sniffer callback body: queries and responses both reach the pipeline."""
    return packet_to_query(pkt, iface) or packet_to_response(pkt, iface)


def make_sniffer(iface: str | list[str],
                 out_queue: queue.Queue,
                 dedup: bool = True) -> AsyncSniffer:
    """Build (do not start) an async sniffer feeding the queue.

    ``dedup=True`` (default) drops loopback TX/RX echo duplicates before
    they reach the pipeline — see DuplicateFilter.
    """
    deduper = make_deduper() if dedup else None
    # A single-name iface tags every event with itself; 'any' or a list
    # cannot attribute the interface per packet, so events stay untagged.
    iface_tag = iface if isinstance(iface, str) and iface != "any" else ""

    def _prn(pkt) -> None:
        event = _classify(pkt, iface_tag)
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
        event = packet_to_query(pkt, iface)
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
