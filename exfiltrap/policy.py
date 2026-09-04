"""Block policy: TTLs, allowlist, reversal — mitigation becomes operable.

A detector that blocks and never unblocks is a self-inflicted outage
waiting for its first false positive. PolicyMitigation wraps any
mitigation backend with:

* an allowlist (never blocked — resolvers, DCs, the CTO's laptop),
* a TTL per block (auto-unban),
* an explicit unblock() for the dashboard button.
"""

from __future__ import annotations

import time


class PolicyMitigation:
    def __init__(self, inner, allowlist: tuple[str, ...] = (),
                 block_ttl: float = 3600.0, clock=time.time):
        self.inner = inner
        self.allowlist = set(allowlist)
        self.block_ttl = block_ttl
        self.clock = clock
        self._expires: dict[str, float] = {}

    def notify(self, assessment) -> bool:
        if assessment.risk_level not in getattr(
                self.inner, "risk_levels", ("HIGH", "CONFIRMED")):
            return False
        return self.block_ip(assessment.src_ip)

    def block_ip(self, ip: str, timestamp: float = 0.0,
                 risk_level: str = "HIGH") -> bool:
        if ip in self.allowlist:
            return False  # policy decision, not a detection miss
        blocked = self.inner.block_ip(ip, timestamp, risk_level)
        if blocked:
            self._expires[ip] = self.clock() + self.block_ttl
        return blocked

    def unblock(self, ip: str) -> bool:
        """Manual reversal (dashboard button); idempotent."""
        self._expires.pop(ip, None)
        un = getattr(self.inner, "unblock_ip", None)
        return bool(un(ip)) if un else True

    def reap_expired(self) -> list[str]:
        """Unblock everything past its TTL; returns the freed IPs."""
        now = self.clock()
        freed = [ip for ip, exp in self._expires.items() if exp <= now]
        for ip in freed:
            self.unblock(ip)
        return freed

    def is_blocked(self, ip: str) -> bool:
        return self.inner.is_blocked(ip)

    def blocked_ips(self) -> set[str]:
        return set(getattr(self.inner, "blocked_ips", set()))


def make_policy(inner, allowlist=(), block_ttl=3600.0) -> PolicyMitigation:
    return PolicyMitigation(inner, tuple(allowlist), block_ttl)
