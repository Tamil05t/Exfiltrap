"""Unit tests for M1 — capture parsing (in-memory scapy packets, no root)."""

import os
import queue

import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP

from exfiltrap.capture import (
    _push,
    capture_backend,
    packet_to_query,
    packet_to_response,
)


def dns_query_packet(qname="abc.tunnel.example", src="10.99.0.2"):
    return IP(src=src) / UDP(sport=40000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )


def dns_query_packet_v6(qname="abc.tunnel.example", src="2001:db8::1",
                        dst="2620:fe::9"):
    return IPv6(src=src, dst=dst) / UDP(sport=40000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )


def _is_root() -> bool:
    """Cross-platform root check.

    ``os.geteuid`` does not exist on Windows, so a bare call at import time
    raised AttributeError during collection and aborted the ENTIRE test
    suite on Windows runners. The live-sniff test is Linux-only anyway.
    """
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


@pytest.mark.skipif(not _is_root(), reason="needs root for live sniffing")
class TestLiveSmoke:
    def test_loopback_sniff(self):
        # Only executed as root (e.g. inside the lab namespace).
        from scapy.all import sniff as live_sniff

        pkts = live_sniff(iface="lo", timeout=1, count=0)
        assert isinstance(pkts, list)


class TestPacketToQuery:
    def test_basic_query(self):
        pkt = dns_query_packet("abc.tunnel.example.")
        q = packet_to_query(pkt)
        assert q is not None
        assert q.src_ip == "10.99.0.2"
        assert q.qname == "abc.tunnel.example"  # trailing dot stripped
        assert q.timestamp > 0.0

    def test_qname_without_trailing_dot(self):
        pkt = dns_query_packet("x.example.com")
        q = packet_to_query(pkt)
        assert q.qname == "x.example.com"

    def test_response_ignored(self):
        pkt = dns_query_packet("abc.tunnel.example.")
        pkt[DNS].qr = 1
        assert packet_to_query(pkt) is None

    def test_no_dns_layer(self):
        assert packet_to_query(IP() / UDP()) is None

    def test_no_ip_layer(self):
        assert packet_to_query(DNS(rd=1, qd=DNSQR(qname="a.b.c"))) is None

    def test_garbage_does_not_raise(self):
        assert packet_to_query("not a packet") is None


class TestWireFormat:
    def test_udp_socket_delivery_parses_cleanly(self):
        # Regression: senders must send DNS-message bytes (not whole IP
        # packets) through the UDP socket. Double-wrapping produced
        # garbage qnames on the wire in the live lab.
        from scapy.all import DNS, DNSQR, IP, UDP

        msg = bytes(DNS(rd=1, qd=DNSQR(qname="4EI.GK4.tunnel.example")))
        # What the kernel puts on the wire after sock.sendto(msg, ...):
        # parse from raw bytes so the sniffer's port-based DNS dissection
        # applies, exactly as it does on a live capture.
        raw = bytes(IP(src="10.99.0.2") / UDP(sport=40000, dport=53) / msg)
        q = packet_to_query(IP(raw))
        assert q is not None
        assert q.qname == "4EI.GK4.tunnel.example"

    def test_double_wrapped_packet_is_not_validated(self):
        # The old buggy form: a whole IP packet as UDP payload. Whatever
        # comes out must never silently look like a sane qname used for
        # detection claims (best-effort parse, may be garbage or None —
        # the contract is that SENDERS don't produce this).
        from scapy.all import DNS, DNSQR, IP, UDP

        inner = IP(dst="10.99.0.1") / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname="4EI.GK4.tunnel.example"))
        wire = IP(src="10.99.0.2") / UDP(sport=40000, dport=53) / bytes(inner)
        q = packet_to_query(wire)
        assert q is None or q.qname != "4EI.GK4.tunnel.example"


class TestIPv6:
    """The sensor must not be blind to half the internet.

    ``packet_to_query`` used to guard with ``IP not in pkt`` — and scapy's
    ``IP`` is the **IPv4** layer, so every IPv6 packet returned None and
    IPv6 lookups were silently invisible. Measured on a dual-stack host:
    systemd-resolved held established UDP/53 sockets to ``[2620:fe::9]:53``
    (Quad9 over IPv6) while the sensor stored IPv4 rows only.
    """

    def test_ipv6_query_parsed(self):
        q = packet_to_query(dns_query_packet_v6("abc.tunnel.example."))
        assert q is not None
        assert q.src_ip == "2001:db8::1"
        assert q.dst_ip == "2620:fe::9"
        assert q.qname == "abc.tunnel.example"      # trailing dot stripped
        assert q.sport == 40000

    def test_ipv6_response_parsed(self):
        pkt = (
            IPv6(src="2620:fe::9", dst="2001:db8::1")
            / UDP(sport=53, dport=40000)
            / DNS(
                id=1, qr=1,
                qd=DNSQR(qname="abc.tunnel.example"),
                an=DNSRR(rrname="abc.tunnel.example", type="AAAA",
                         rdata="2606:2800:220:1:248:1893:25c8:1946"),
            )
        )
        r = packet_to_response(pkt)
        assert r is not None
        assert r.client_ip == "2001:db8::1"
        assert r.resolver_ip == "2620:fe::9"
        assert r.answer_ips == ("2606:2800:220:1:248:1893:25c8:1946",)

    def test_ipv6_tcp_query_parsed(self):
        # DNS over TCP on IPv6: the same 2-byte length prefix as IPv4, and
        # scapy still does not bind the DNS dissector onto the TCP payload.
        msg = bytes(DNS(rd=1, qd=DNSQR(qname="t6.tunnel.example")))
        pkt = (
            IPv6(src="2001:db8::1", dst="2620:fe::9")
            / TCP(sport=40000, dport=53)
            / (b"\x00" + bytes([len(msg)]) + msg)
        )
        q = packet_to_query(pkt)
        assert q is not None
        assert q.qname == "t6.tunnel.example"
        assert q.src_ip == "2001:db8::1"

    def test_ipv4_still_works(self):
        # The family-agnostic accessor must not regress the IPv4 path.
        q = packet_to_query(dns_query_packet("v4.tunnel.example"))
        assert q is not None
        assert q.src_ip == "10.99.0.2"
        assert q.sport == 40000

    def test_ipv6_without_dns_is_none(self):
        assert packet_to_query(IPv6() / UDP()) is None


class TestQueue:
    def test_push_puts_events(self):
        q = queue.Queue()
        _push(packet_to_query(dns_query_packet()), q)
        assert q.qsize() == 1
        _push(None, q)  # malformed never enqueued
        assert q.qsize() == 1


class TestDuplicateFilter:
    def test_loopback_echo_dropped(self):
        # AF_PACKET on lo delivers every packet twice (TX + RX copy):
        # the second identical event must be dropped (live soak finding:
        # 88 queries -> 176 stored rows, beacon CV destroyed by the
        # alternating 0.0 s / 5.5 s gaps).
        from exfiltrap.capture import make_deduper
        from exfiltrap.events import DNSQuery

        ded = make_deduper()
        a = DNSQuery("127.0.0.1", "hb001.c2beacon.example", 1000.0)
        b = DNSQuery("127.0.0.1", "hb001.c2beacon.example", 1000.0)
        assert ded.is_duplicate(a) is False
        assert ded.is_duplicate(b) is True      # same packet, second copy

    def test_distinct_events_kept(self):
        from exfiltrap.capture import make_deduper
        from exfiltrap.events import DNSQuery

        ded = make_deduper()
        assert ded.is_duplicate(DNSQuery("h1", "a.example", 1000.0)) is False
        # genuine retransmission 1 s later: different timestamp, kept
        assert ded.is_duplicate(DNSQuery("h1", "a.example", 1001.0)) is False
        # different source, same instant + qname: kept (per-src windows)
        assert ded.is_duplicate(DNSQuery("h2", "a.example", 1000.0)) is False

    def test_lru_bound(self):
        from exfiltrap.capture import DuplicateFilter
        from exfiltrap.events import DNSQuery

        ded = DuplicateFilter()
        for i in range(600):
            ded.is_duplicate(DNSQuery("h", f"x{i}.example", 1000.0 + i))
        # the first key was evicted by the LRU bound: re-admitted
        assert ded.is_duplicate(DNSQuery("h", "x0.example", 1000.0)) is False

    def test_sub_millisecond_echo_dropped(self):
        # The real defect. Two copies of ONE frame are tens of MICROSECONDS
        # apart — measured on this host: 213 near-pairs in 826 rows, median
        # delta 203 us, min 0 us. 26 us below is the exact delta between the
        # two stored www.workbuddy.ai rows at 16:33:23.
        from exfiltrap.capture import DuplicateFilter
        from exfiltrap.events import DNSQuery

        ded = DuplicateFilter()
        t = 1791284603.062714
        a = DNSQuery("10.94.139.7", "www.workbuddy.ai", t, qtype=1, sport=40000)
        b = DNSQuery("10.94.139.7", "www.workbuddy.ai", t + 0.000026,
                     qtype=1, sport=40000)
        assert ded.is_duplicate(a) is False
        assert ded.is_duplicate(b) is True

    def test_bucket_boundary_echo_dropped(self):
        # The case a 10 ms rounding bucket structurally cannot catch: two
        # copies straddling a boundary got two different keys, so both were
        # stored even though they are 0.2 ms apart.
        from exfiltrap.capture import DuplicateFilter
        from exfiltrap.events import DNSQuery

        assert round(1000.0049, 2) != round(1000.0051, 2)   # old key differed
        ded = DuplicateFilter()
        a = DNSQuery("10.94.139.7", "www.workbuddy.ai", 1000.0049,
                     qtype=1, sport=40000)
        b = DNSQuery("10.94.139.7", "www.workbuddy.ai", 1000.0051,
                     qtype=1, sport=40000)
        assert ded.is_duplicate(a) is False
        assert ded.is_duplicate(b) is True

    def test_real_retransmission_beyond_window_kept(self):
        # The 50 ms window must not swallow a genuine retransmission.
        from exfiltrap.capture import DuplicateFilter
        from exfiltrap.events import DNSQuery

        ded = DuplicateFilter()
        a = DNSQuery("10.94.139.7", "www.workbuddy.ai", 1000.0,
                     qtype=1, sport=40000)
        b = DNSQuery("10.94.139.7", "www.workbuddy.ai", 1000.2,
                     qtype=1, sport=40000)
        assert ded.is_duplicate(a) is False
        assert ded.is_duplicate(b) is False

    def test_one_filter_is_shared_across_interfaces(self):
        # A feed builds ONE filter and hands it to every interface's sniffer.
        # With a filter per sniffer the same frame was admitted once per
        # interface, which is how the duplicates reached the database.
        # scapy's AsyncSniffer keeps the callbacks it was built with in
        # ``.kwargs`` (there is no ``.opts``).
        import queue as _queue

        from exfiltrap.capture import make_deduper, make_sniffer

        ded = make_deduper()
        out = _queue.Queue()
        s1 = make_sniffer("lo", out, deduper=ded)
        s2 = make_sniffer("lo", out, deduper=ded)
        pkt = dns_query_packet(qname="dup.example", src="10.0.0.5")
        s1.kwargs["prn"](pkt)
        s2.kwargs["prn"](pkt)
        assert out.qsize() == 1, \
            "one frame seen by two sniffers of a feed must be stored once"


class TestCaptureBackend:
    """``capture_backend()`` must not cry wolf on a platform that is fine.

    The bug this guards: on Linux scapy's default backend is a raw AF_PACKET
    socket, so ``conf.use_pcap`` is False *by design* — scapy turns it on only
    for Windows and Solaris. Reporting that as "capture cannot start" put a red
    "capture driver unavailable" banner on a sensor that was demonstrably
    capturing. Measured live with that banner on screen: queries_processed
    1280, and capture_ifaces {enp18s0f4u1: ok, 0.2 s} / {lo: ok, 0.2 s}.
    """

    @staticmethod
    def _conf(monkeypatch, use_pcap=False, use_bpf=False):
        """Replace ``scapy.config.conf`` with a stub.

        ``capture_backend`` does ``from scapy.config import conf`` at call
        time, so patching the module attribute is enough — and it avoids
        assigning ``conf.use_pcap`` for real, which would make scapy try to
        load libpcap as a side effect.
        """
        import scapy.config

        class _StubConf:
            pass

        stub = _StubConf()
        stub.use_pcap = use_pcap
        stub.use_bpf = use_bpf
        monkeypatch.setattr(scapy.config, "conf", stub)

    def test_posix_raw_sockets_is_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=False)
        monkeypatch.setattr(os, "name", "posix")
        be = capture_backend()
        assert be["ok"] is True
        assert be["provider"] == "raw sockets (AF_PACKET)"
        assert be["reason"] == ""
        assert be["remedy"] == ""

    def test_posix_bpf_is_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=False, use_bpf=True)
        monkeypatch.setattr(os, "name", "posix")
        be = capture_backend()
        assert be["ok"] is True
        assert be["provider"] == "BPF"

    def test_libpcap_loaded_is_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=True)
        monkeypatch.setattr(os, "name", "nt")
        be = capture_backend()
        assert be["ok"] is True
        assert be["provider"] == "libpcap/npcap"

    def test_windows_without_npcap_is_not_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=False)
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr("exfiltrap.capture._pcap_driver_present",
                            lambda: False)
        be = capture_backend()
        assert be["ok"] is False
        assert "Npcap" in be["reason"]
        assert be["url"]          # the download link is the actionable part

    def test_windows_with_damaged_driver_is_not_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=False)
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr("exfiltrap.capture._pcap_driver_present",
                            lambda: True)
        be = capture_backend()
        assert be["ok"] is False
        assert "damaged" in be["reason"]

    def test_unexpected_platform_is_not_ok(self, monkeypatch):
        self._conf(monkeypatch, use_pcap=False)
        monkeypatch.setattr(os, "name", "java")
        be = capture_backend()
        assert be["ok"] is False
