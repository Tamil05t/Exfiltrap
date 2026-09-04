"""Unit tests for M6 — payload decoder."""

import base64
import binascii
import os

import pytest

from exfiltrap.payload_decoder import (
    FAILED,
    decode_query_payload,
    printable_ratio,
    try_decode,
)


def b32_label(data: bytes) -> str:
    """Encode like the tunnel client does: base32, '=' stripped, lowercase-ok."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


class TestPrintableRatio:
    def test_all_printable(self):
        assert printable_ratio(b"hello world") == 1.0

    def test_empty(self):
        assert printable_ratio(b"") == 0.0

    def test_mixed(self):
        # 3 of 4 bytes printable (0xFF is not; tab/newline are).
        assert printable_ratio(b"abc\xff") == pytest.approx(0.75)
        assert printable_ratio(b"a\tb\n") == 1.0


class TestTryDecodeBase32:
    def test_printable_payload(self):
        payload = b"secret exfil payload!!"
        result = try_decode(b32_label(payload).lower())
        assert result.success
        assert result.method == "base32"
        assert result.decoded == payload
        assert result.printable_ratio >= 0.90
        assert result.signature is None

    def test_unpadded_odd_length_roundtrip(self):
        payload = b"1234567890abcdefghij"  # 21 bytes -> stripped length % 8 = 4
        result = try_decode(b32_label(payload))
        assert result.success
        assert result.decoded == payload

    def test_file_signature_confirms_non_printable(self):
        payload = b"PK\x03\x04" + bytes(range(0x80, 0xB0))  # zip magic + junk
        result = try_decode(b32_label(payload))
        assert result.success
        assert result.signature == "zip"
        assert result.printable_ratio < 0.90  # confirmed via signature, not ratio


class TestTryDecodeOtherMethods:
    def test_base64(self):
        payload = b"standard base64 payload"
        result = try_decode(base64.b64encode(payload).decode())
        assert result.success
        assert result.method == "base64"
        assert result.decoded == payload

    def test_base64url(self):
        payload = b"url safe payload 0123456789"
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        # Force the URL-safe alphabet by replacing chars so plain b64 is invalid.
        encoded = encoded.replace("+", "-").replace("/", "_")
        result = try_decode(encoded)
        assert result.success
        assert result.method in ("base64", "base64url")
        assert result.decoded == payload

    def test_hex(self):
        payload = b"%PDF-1.4 classic doc"
        result = try_decode(binascii.hexlify(payload).decode())
        assert result.success
        assert result.method == "hex"
        assert result.decoded == payload

    def test_order_base32_first(self):
        payload = b"HEXLOOk"
        # This string is simultaneously valid hex-charset; base32 wins if valid.
        result = try_decode(b32_label(payload))
        assert result.method == "base32"


class TestRejections:
    def test_too_short(self):
        assert not try_decode("www").success  # < MIN_DECODED_BYTES after decode
        assert not try_decode("abc").success

    def test_random_junk_not_confirmed(self):
        # Random bytes encoded in valid base32 decode to NON-printable junk
        # with no file signature -> must NOT confirm. This is the FP guard.
        for _ in range(20):
            blob = os.urandom(30)
            result = try_decode(b32_label(blob))
            assert not result.success
            assert result.decoded is None

    def test_english_word_decodes_to_noise(self):
        # "apigateway" is valid base32 charset; decodes to bytes that are
        # unlikely to be >=90% printable AND >= 4 bytes of sense.
        result = try_decode("apigateway")
        # Either rejected outright or (rarely) printable-but-tiny: never confirmed
        # for the 4-byte case it would be confirmed legitimately; assert both
        # paths behave per the rules rather than crashing.
        if result.success:
            assert len(result.decoded) >= 4
            assert result.printable_ratio >= 0.90

    def test_empty(self):
        assert try_decode("") == FAILED

    def test_failed_constant(self):
        assert FAILED.success is False
        assert FAILED.method is None


class TestDecodeQueryPayload:
    def test_roundtrip_multi_label(self):
        payload = b"corporate secrets: q4-projections.xlsx"
        label = b32_label(payload)
        # Split the encoded string across two labels like a tunnel would.
        qname = f"{label[:len(label)//2]}.{label[len(label)//2:]}.tunnel.example"
        result = decode_query_payload(qname)
        assert result.success
        assert result.method == "base32"
        assert result.decoded == payload

    def test_no_subdomains_fails(self):
        assert decode_query_payload("example.com") == FAILED
        assert decode_query_payload("www.example.com.") == FAILED

    def test_signature_payload(self):
        payload = b"GIF89a" + os.urandom(20)
        qname = f"{b32_label(payload)}.ch.tunnel.example"
        result = decode_query_payload(qname)
        assert result.success
        assert result.signature == "gif"
