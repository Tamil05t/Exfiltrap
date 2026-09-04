"""M6 — Payload decoder.

Triggered only for suspicious queries (high RF probability or a slow-drip
flag): tries to reverse the tunnel's encoding (Base32, then Base64 in both
alphabets, then Hex) on the subdomain labels and accepts a decode as
confirmed exfiltration only when the plaintext looks like real payload —
>= 90% printable ASCII or a known file signature.

The false-positive guard matters as much as the decoding: a random
high-entropy label is usually *valid* base32 but decodes to noise, and must
NOT be treated as confirmation.
"""

from __future__ import annotations

import base64
import binascii
import string
from dataclasses import dataclass

from exfiltrap import config
from exfiltrap.features import base_domain

_SIGNATURE_NAMES = ("zip", "pdf", "jpeg", "gif")

# Printable ASCII per the spec: 0x20-0x7E plus tab, CR, LF.
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


@dataclass
class DecodeResult:
    """Outcome of one decode attempt."""

    success: bool
    method: str | None  # "base32" | "base64" | "base64url" | "hex" | None
    decoded: bytes | None
    printable_ratio: float
    signature: str | None  # "zip" | "pdf" | "jpeg" | "gif" | None


FAILED = DecodeResult(False, None, None, 0.0, None)


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (incl. \\t \\n \\r)."""
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def _signature_name(decoded: bytes) -> str | None:
    for sig, name in zip(config.FILE_SIGNATURES, _SIGNATURE_NAMES):
        if decoded.startswith(sig):
            return name
    return None


def _accept(label_method: str, decoded: bytes) -> DecodeResult | None:
    """Return a successful DecodeResult if the plaintext looks like payload."""
    if len(decoded) < config.MIN_DECODED_BYTES:
        return None
    ratio = printable_ratio(decoded)
    signature = _signature_name(decoded)
    if ratio >= config.DECODE_MIN_PRINTABLE_RATIO or signature is not None:
        return DecodeResult(True, label_method, decoded, ratio, signature)
    return None


def try_decode(label: str) -> DecodeResult:
    """Attempt Base32 -> Base64 -> Base64url -> Hex, in that strict order.

    Charset is validated before each attempt so e.g. a hex-looking string is
    never mis-parsed by a lenient base64 decoder.
    """
    if not label:
        return FAILED
    best_ratio = 0.0

    # Base32: A-Z, 2-7 (case-insensitive). Tunnel clients strip the '='
    # padding because '=' is illegal in hostnames, so re-attach it before
    # decoding: a stripped encoding of whole bytes is always reconstructible.
    candidate = label.upper()
    if candidate and all(c in string.ascii_uppercase + "234567=" for c in candidate):
        stripped = candidate.rstrip("=")
        padded = stripped + "=" * (-len(stripped) % 8)
        try:
            decoded = base64.b32decode(padded)
            result = _accept("base32", decoded)
            if result is not None:
                return result
            best_ratio = max(best_ratio, printable_ratio(decoded))
        except (binascii.Error, ValueError):
            pass

    # Base64 standard / URL-safe: strict charset check first.
    b64_alphabet = set(string.ascii_letters + string.digits + "+/=")
    b64url_alphabet = set(string.ascii_letters + string.digits + "-_=")
    if set(label) <= b64_alphabet:
        try:
            decoded = base64.b64decode(label, validate=True)
            result = _accept("base64", decoded)
            if result is not None:
                return result
            best_ratio = max(best_ratio, printable_ratio(decoded))
        except (binascii.Error, ValueError):
            pass
    if set(label) <= b64url_alphabet and not set(label) <= b64_alphabet:
        try:
            decoded = base64.urlsafe_b64decode(label)
            result = _accept("base64url", decoded)
            if result is not None:
                return result
            best_ratio = max(best_ratio, printable_ratio(decoded))
        except (binascii.Error, ValueError):
            pass

    # Hex: even length, hex digits only.
    if len(label) % 2 == 0 and all(c in string.hexdigits for c in label):
        try:
            decoded = bytes.fromhex(label)
            result = _accept("hex", decoded)
            if result is not None:
                return result
            best_ratio = max(best_ratio, printable_ratio(decoded))
        except ValueError:
            pass

    return DecodeResult(False, None, None, best_ratio, None)


def decode_query_payload(qname: str) -> DecodeResult:
    """Decode the tunneled payload out of a query name.

    # ASSUMPTION: the candidate payload is every label to the left of the
    # base domain (last two labels), leftmost first, concatenated WITHOUT
    # dots — this is how the reference attacker client packs chunks.
    """
    clean = qname[:-1] if qname.endswith(".") else qname
    labels = clean.split(".")
    if len(labels) <= 2:
        return FAILED
    candidate = "".join(labels[:-2])
    return try_decode(candidate)
