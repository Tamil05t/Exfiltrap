"""Unit tests for M1 — capture parsing (in-memory scapy packets, no root)."""

import os
import queue

import pytest
from scapy.all import DNS, DNSQR, IP, UDP

from exfiltrap.capture import _push, packet_to_query


def dns_query_packet(qname="abc.tunnel.example", src="10.99.0.2"):
    return IP(src=src) / UDP(sport=40000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root for live sniffing")
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


class TestQueue:
    def test_push_puts_events(self):
        q = queue.Queue()
        _push(packet_to_query(dns_query_packet()), q)
        assert q.qsize() == 1
        _push(None, q)  # malformed never enqueued
        assert q.qsize() == 1
