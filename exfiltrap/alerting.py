"""SIEM alerting — structured syslog events for HIGH/CONFIRMED detections.

Sends single-line ``key=value`` records through the local syslog socket
(`/dev/log`), which journald forwards on systemd hosts — the standard
ingestion point for SIEMs. The alerter owns a raw datagram socket and does
its own framing (RFC 3164-style PRI + tag) so delivery failures return
False quietly instead of raising or spraying logging tracebacks into the
detection loop.
"""

from __future__ import annotations

import socket
import time

_IDENTIFIER = "exfiltrap"
# local4.notice -> facility 20 << 3 | severity 5
_PRI = "<165>"


class NullAlerter:
    """No-op alerter (default when alerting is disabled)."""

    def send(self, assessment) -> bool:
        return False


class SyslogAlerter:
    """Emits ``EXFILTRAP_ALERT ...`` lines via the local syslog socket."""

    def __init__(self, address: str = "/dev/log"):
        self.address = address
        self._sock: socket.socket | None = None
        self._last_sent: dict[tuple[str, str], float] = {}
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(address)
            self._sock = sock
        except OSError:
            # No syslog socket (container, non-systemd lab): silent no-op.
            self._sock = None

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def send(self, assessment) -> bool:
        """One structured line per alert; never raises."""
        if self._sock is None:
            return False
        # Alert-fatigue control: at most one line per (source, level) per
        # hour — a 45s tunnel burst must not generate 664 syslog lines.
        key = (assessment.src_ip, assessment.risk_level)
        now = time.time()
        if now - self._last_sent.get(key, 0.0) < 3600.0:
            return False
        self._last_sent[key] = now
        try:
            reasons = "; ".join(assessment.reasons)[:120]
            preview = (assessment.decoded_preview or "")[:40]
            line = (
                f"{_PRI}{_IDENTIFIER}: EXFILTRAP_ALERT risk={assessment.risk_level}"
                f" src={assessment.src_ip} qname={assessment.qname[:100]}"
                f" prob={assessment.rf_probability:.3f}"
                f" confirmed={int(assessment.confirmed_exfiltration)}"
                f" decoded={preview} reasons={reasons}\n"
            )
            self._sock.send(line.encode())
            return True
        except OSError:
            return False


def make_alerter(kind: str = "none", **kwargs):
    """Factory: 'none' | 'syslog'."""
    if kind == "none":
        return NullAlerter()
    if kind == "syslog":
        return SyslogAlerter(**kwargs)
    raise ValueError(f"unknown alerter kind {kind!r}")
