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
import os
import queue
import threading

from scapy.all import AsyncSniffer  # noqa: F401  (re-exported for callers)
from scapy.all import DNS, IP, sniff

from exfiltrap import config
from exfiltrap.events import DNSQuery, DNSResponse

# The driver scapy needs to see layer-2 frames on Windows (it is the same one
# Wireshark ships). Named here because its ABSENCE is the single most common
# way this product looks broken while being perfectly healthy: scapy imports
# fine, logs one "No libpcap provider available" warning at import, and then
# every AsyncSniffer start() fails. A Windows service has no console, so that
# warning goes nowhere and the operator's only symptom is a red banner.
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"

# Any one of these means Npcap/WinPcap is actually installed.
_PCAP_MARKERS = ("Npcap", r"drivers\npcap.sys", "wpcap.dll", "Packet.dll")


def _pcap_driver_present() -> bool:
    """Any trace of the Npcap/WinPcap driver in the system directory."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(root, "System32")
    return any(os.path.exists(os.path.join(system32, name))
               for name in _PCAP_MARKERS)


def capture_backend() -> dict:
    """Can this process open a sniffing socket — and if not, exactly why?

    Returns ``{"ok", "provider", "reason", "remedy", "url"}``. The four
    non-``ok`` keys are empty strings when ``ok`` is True.

    This exists because "capture degraded" on its own is unactionable. The
    engine reports the *cause* and the *fix* through /api/status so the
    console can say "the capture driver is not installed, get it here"
    instead of leaving the operator to guess — and to guess wrong, since the
    obvious guess ("run it as Administrator") cannot help when the driver
    itself is missing.
    """
    try:
        from scapy.config import conf

        use_pcap = bool(getattr(conf, "use_pcap", False))
    except Exception as exc:  # noqa: BLE001 — never raise from a status route
        return {"ok": False, "provider": None,
                "reason": f"scapy could not be loaded ({exc})",
                "remedy": "Reinstall ExFilTrap.", "url": ""}

    if use_pcap:
        return {"ok": True, "provider": "libpcap/npcap",
                "reason": "", "remedy": "", "url": ""}

    if os.name == "nt":
        if _pcap_driver_present():
            reason = ("scapy loaded no libpcap provider even though the Npcap "
                      "driver files are present — the driver install is "
                      "damaged, or the service started while it was still "
                      "being installed")
            remedy = ("Reinstall Npcap, then restart the ExFilTrap service.")
        else:
            reason = ("the Npcap packet-capture driver is not installed, so "
                      "scapy has no libpcap provider and capture cannot start")
            remedy = ("Install Npcap — the driver Wireshark uses — then "
                      "restart the ExFilTrap service. Running ExFilTrap as "
                      "Administrator does NOT help: the driver itself is "
                      "missing, so there is nothing to elevate.")
        return {"ok": False, "provider": None, "reason": reason,
                "remedy": remedy, "url": NPCAP_DOWNLOAD_URL}

    # POSIX: scapy's default backend here is a raw AF_PACKET socket, NOT
    # libpcap. scapy sets conf.use_pcap = True only on Windows
    # (scapy/arch/windows/__init__.py) and Solaris (scapy/arch/solaris.py), so
    # on Linux a False here is the NORMAL state and means nothing is wrong.
    # Reporting it as "capture cannot start" put a red "capture driver
    # unavailable" banner on a Linux sensor that was demonstrably capturing —
    # measured with that banner on screen: queries_processed 1280 and
    # capture_ifaces {enp18s0f4u1: ok, age 0.2 s}, {lo: ok, age 0.2 s}. This
    # same file already depends on the raw path (make_deduper documents
    # AF_PACKET double-delivery on loopback). Genuine POSIX capture failures
    # are permission errors (no CAP_NET_RAW) and already surface through
    # capture_ifaces[*].ok / capture_errors, so this route must not claim to
    # diagnose them.
    if os.name == "posix":
        provider = ("BPF" if getattr(conf, "use_bpf", False)
                    else "raw sockets (AF_PACKET)")
        return {"ok": True, "provider": provider,
                "reason": "", "remedy": "", "url": ""}

    return {
        "ok": False,
        "provider": None,
        "reason": "scapy reported no packet-capture backend on this platform",
        "remedy": "Report this with your OS and Python version.",
        "url": "",
    }


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


def _ip_layer(pkt):
    """The packet's IP layer, IPv4 or IPv6 — None when it carries neither.

    This must not be ``pkt[IP]``: scapy's ``IP`` is the **IPv4** layer, so a
    parser that asks for it silently returns None for every IPv6 packet and
    the sensor goes blind to half the internet. That is not hypothetical on
    a dual-stack host — measured on this machine, systemd-resolved held
    established UDP/53 sockets to ``[2620:fe::9]:53`` (Quad9 over IPv6)
    while the sensor recorded only IPv4 rows. An IPv6-only resolver is
    entirely invisible to an IPv4-only parser.

    IPv4 and IPv6 differ only in the address fields here: both expose
    ``src``/``dst`` and both carry the same UDP/TCP layer (with the same
    ``sport`` shortcut), so one accessor serves both families.
    """
    if IP in pkt:
        return pkt[IP]
    from scapy.all import IPv6

    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def packet_to_query(pkt, iface: str = "") -> DNSQuery | None:
    """Pure scapy-packet -> DNSQuery conversion; None for anything else.

    # ASSUMPTION: the detector only needs queries (qr=0); responses carry
    # no exfiltrated payload and are ignored.
    """
    try:
        dns = _dns_layer(pkt)
        ip = _ip_layer(pkt)
        if dns is None or ip is None:
            return None
        if dns.qr != 0 or dns.qd is None:
            return None
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
        ip = _ip_layer(pkt)
        if dns is None or ip is None:
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
            client_ip=ip.dst,
            qname=qname,
            timestamp=float(pkt.time),
            answer_count=count,
            answer_bytes=len(blob),
            answer_entropy=shannon_entropy(blob.decode("latin-1")),
            resolver_ip=ip.src,
            answer_ips=_answer_ips(dns),
            rcode=int(dns.rcode),
        )
    except Exception:
        return None


def _push(event, out_queue: queue.Queue) -> None:
    if event is not None:
        out_queue.put(event)


def make_deduper() -> "DuplicateFilter":
    """Build a capture-path duplicate filter (**one per capture feed**).

    AF_PACKET delivers the same frame twice (TX + RX copy) on loopback and on
    wireless interfaces — observed live: 88 DNS queries produced 176 stored
    rows. Doubled queries destroy the inter-arrival statistics the beacon
    detector lives on (gaps alternate 0.0 s / 5.5 s → CV ≈ 1) and inflate
    every per-source count.

    Build ONE of these per feed and pass it to every ``make_sniffer`` call of
    that feed; one per sniffer leaves cross-interface echoes unfiltered.
    """
    return DuplicateFilter()


class DuplicateFilter:
    """Content+time keyed sliding window of recently seen capture events."""

    _MAX_KEYS = 512
    # Two copies of ONE captured frame (the AF_PACKET TX+RX echo) are tens of
    # microseconds apart. The key used to round the timestamp into 10 ms
    # buckets, which only collides when both copies land in the same slot: a
    # pair straddling a boundary (…x.0049 / …x.0051) produced two keys and both
    # rows were stored. Measured on this host (2026-10-06): 213 near-pairs in
    # 826 rows, median delta 203 us, min 0 us — and every www.workbuddy.ai
    # lookup was stored twice. Comparing against the last time the key was
    # admitted is boundary-free.
    # 50 ms is far below a genuine retransmission (resolvers back off >=1 s, see
    # TestDuplicateFilter::test_distinct_events_kept) and far above the echo
    # jitter, so nothing real is discarded.
    _ECHO_WINDOW_S = 0.05

    def __init__(self) -> None:
        import collections

        # key -> the timestamp it was last admitted
        self._recent: collections.OrderedDict[tuple, float] = \
            collections.OrderedDict()
        self._lock = threading.Lock()

    def is_duplicate(self, event) -> bool:
        """True when this exact event was already admitted (frame echo).

        The key is (event type, source, qname, qtype, sport) plus a time
        comparison — two genuine different queries never collide; the two
        copies of one captured frame always do.
        """
        ts = getattr(event, "timestamp", None)
        if ts is None:
            return False
        ts = float(ts)
        # qtype + sport in the key: a normal getaddrinfo lookup sends an A
        # and an AAAA query back-to-back with the SAME qname well inside the
        # echo window — keying on name alone silently discarded the AAAA.
        key = (type(event).__name__, getattr(event, "src_ip", None),
               getattr(event, "client_ip", None),
               getattr(event, "qname", None),
               getattr(event, "qtype", 0), getattr(event, "sport", 0))
        with self._lock:
            last = self._recent.get(key)
            if last is not None and abs(ts - last) <= self._ECHO_WINDOW_S:
                return True
            self._recent[key] = ts
            self._recent.move_to_end(key)
            while len(self._recent) > self._MAX_KEYS:
                self._recent.popitem(last=False)
            return False


def _classify(pkt, iface: str = ""):
    """Sniffer callback body: queries and responses both reach the pipeline."""
    return packet_to_query(pkt, iface) or packet_to_response(pkt, iface)


def make_sniffer(iface: str | list[str],
                 out_queue: queue.Queue,
                 dedup: bool = True,
                 deduper: "DuplicateFilter | None" = None) -> AsyncSniffer:
    """Build (do not start) an async sniffer feeding the queue.

    ``dedup=True`` (default) drops TX/RX echo duplicates before they reach
    the pipeline — see DuplicateFilter.

    Pass ``deduper`` to SHARE one filter across every interface of a capture
    feed. That is the wiring the docstring of ``make_deduper`` has always
    described ("one per capture feed"); building one per sniffer instead meant
    a frame seen by two interfaces was admitted once per interface. Measured
    on this host (2026-10-06): 213 near-identical pairs in 826 rows, median
    delta 203 us. The class is lock-protected precisely so it can be shared.
    """
    if deduper is None:
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
