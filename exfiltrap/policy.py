"""Block policy: TTLs, allowlist, reversal — mitigation becomes operable.

A detector that blocks and never unblocks is a self-inflicted outage
waiting for its first false positive. PolicyMitigation wraps any
mitigation backend with:

* an allowlist (never blocked — resolvers, DCs, the CTO's laptop),
* a TTL per block (auto-unban),
* an explicit unblock() for the dashboard button,
* **response targeting** — the answer to "act on the right thing":

  - a REMOTE source (lab nsB attacker, or clients seen by a gateway
    deployment) is the right target for a firewall DROP — as before;
  - the host's OWN source (loopback, the LAN IP — every query on a
    single-host deployment) is never firewalled. Blocking it cuts the
    operator's own connectivity, which is what shipped 1.4.0 did with
    ``--sinkhole``. Instead the optional sinkhole responds at the domain
    level, and it decides internally whether the evidence on that domain
    is strong enough (decode confirmation / strike accumulation).
"""

from __future__ import annotations

import ipaddress
import time


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class PolicyMitigation:
    def __init__(self, inner, allowlist: tuple[str, ...] = (),
                 block_ttl: float = 3600.0, clock=time.time,
                 sinkhole=None, own_ips: tuple[str, ...] = ()):
        self.inner = inner
        self.allowlist = set(allowlist)
        self.block_ttl = block_ttl
        self.clock = clock
        self._expires: dict[str, float] = {}
        # Optional domain-level response (single-host deployments: block
        # the exact DNS identity instead of the whole machine).
        self.sinkhole = sinkhole
        # The addresses of THIS host: sources that must never be firewalled.
        self.own_ips = frozenset(own_ips)
        # Last response decision, for the storage ledger and the UI:
        # "none" | "source" | "domain" | "deferred" (evidence not yet
        # strong enough to act). ``last_target`` is what it acted on —
        # the sunk hostname or the blocked source IP.
        self.last_response = "none"
        self.last_target = ""
        self.last_defer_reason = ""

    # -- targeting ---------------------------------------------------------
    def is_own_source(self, ip: str) -> bool:
        """True when the source is this machine itself (never firewalled)."""
        return bool(ip) and (ip in self.own_ips or _is_loopback(ip))

    def notify(self, assessment) -> bool:
        if assessment.risk_level not in getattr(
                self.inner, "risk_levels", ("HIGH", "CONFIRMED")):
            self.last_response = "none"
            return False

        src = assessment.src_ip
        own = self.is_own_source(src)
        domain_response = False

        if self.sinkhole is not None and src not in self.allowlist:
            try:
                domain_response = bool(self.sinkhole.notify(assessment))
            except Exception as exc:  # noqa: BLE001 — never blocks detection,
                # but a response that silently never lands is an outage the
                # operator cannot see (soak finding: missing hosts file).
                import logging

                logging.getLogger("exfiltrap.policy").error(
                    "sinkhole response FAILED for %s: %s",
                    assessment.qname, exc)

        if own:
            # Single-host deployment: the "attacker" is this machine.
            # Firewalling the source = self-DoS (the 1.4.0 --sinkhole
            # outage). The domain sink above is the surgical response;
            # without a sinkhole we deliberately do nothing and say why.
            self.last_response = ("domain" if domain_response
                                  else "deferred")
            self.last_target = (assessment.qname if domain_response else "")
            self.last_defer_reason = (
                "" if domain_response
                else "self-host source — domain-level response only")
            if not domain_response:
                import logging

                logging.getLogger("exfiltrap.policy").info(
                    "HIGH/CONFIRMED from own host (%s) on %s — no source "
                    "block (self-DoS guard); enable the sinkhole for a "
                    "domain-level response", src, assessment.qname)
            return domain_response

        blocked = self.block_ip(src)
        self.last_response = "source" if blocked else "none"
        self.last_target = src if blocked else ""
        return blocked or domain_response

    def block_ip(self, ip: str, timestamp: float = 0.0,
                 risk_level: str = "HIGH") -> bool:
        if ip in self.allowlist or self.is_own_source(ip):
            return False  # policy decision, not a detection miss
        blocked = self.inner.block_ip(ip, timestamp, risk_level)
        if blocked:
            self._expires[ip] = self.clock() + self.block_ttl
        return blocked

    def allowlist_add(self, ip: str) -> None:
        """Live addition (dashboard/persistent allowlist) — O(1) set op."""
        if ip:
            self.allowlist.add(ip)

    def allowlist_remove(self, ip: str) -> None:
        self.allowlist.discard(ip)

    def unblock(self, target: str) -> bool:
        """Manual reversal (dashboard button); idempotent.

        ``target`` may be a source IP or a sunk domain — both kinds land
        in the same blocked ledger.
        """
        self._expires.pop(target, None)
        undone = False
        un = getattr(self.inner, "unblock_ip", None)
        if un:
            undone = bool(un(target))
        if self.sinkhole is not None:
            try:
                undone = bool(self.sinkhole.unblock_domain(target)) or undone
            except Exception:
                pass
        return undone

    def reap_expired(self) -> list[str]:
        """Unblock everything past its TTL; returns the freed targets."""
        now = self.clock()
        freed = [t for t, exp in self._expires.items() if exp <= now]
        for t in freed:
            self.unblock(t)
        if self.sinkhole is not None:
            self.sinkhole.reap_expired()
        return freed

    def is_blocked(self, target: str) -> bool:
        if self.sinkhole is not None:
            try:
                if self.sinkhole.is_sunk(target):
                    return True
            except Exception:
                pass
        return self.inner.is_blocked(target)

    def blocked_ips(self) -> set[str]:
        return set(getattr(self.inner, "blocked_ips", set()))


def make_policy(inner, allowlist=(), block_ttl=3600.0, sinkhole=None,
                own_ips=()) -> PolicyMitigation:
    return PolicyMitigation(inner, tuple(allowlist), block_ttl,
                            sinkhole=sinkhole, own_ips=tuple(own_ips))
