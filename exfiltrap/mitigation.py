"""M8 — Automated mitigation, with hard safety rails.

Two platform backends behind one interface:

* **Linux/iptables** — the original namespace-scoped implementation. Ground
  rule 1 of the build spec: adversarial traffic and firewall changes only
  ever happen inside the isolated ``nsA`` network namespace — never on the
  host's real firewall. Every code path enforces that:

  * If we are running *inside* the target namespace, a plain ``iptables``
    invocation is emitted (we are already in the isolated ruleset).
  * If we are on the host but the namespace exists, the rule is applied via
    ``ip netns exec nsA iptables ...`` which targets ONLY nsA's ruleset.
  * If the namespace does not exist at all, we refuse — unless the operator
    passes the explicit ``--i-know-this-is-isolated`` override, which is
    opt-in by design and still refuses when running inside some *other*
    non-host namespace.

* **Windows/netsh** — Windows has no namespaces or iptables; the firewall
  is Windows Defender Firewall, manipulated through ``netsh advfirewall``.
  Safety rails here: administrator context is REQUIRED (the installed
  service provides it; a plain user process gets a SafetyError, never a
  UAC prompt from deep inside a detector loop), rules carry a searchable
  ``ExfilTrap-`` prefix, and dry_run defaults to True exactly like Linux.

* ``dry_run`` defaults to True on both platforms: commands are validated
  and logged, never executed.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import threading
import time

from exfiltrap import config

_VALID_IP = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


class SafetyError(RuntimeError):
    """Raised whenever a mitigation action would leave the safety boundary."""


def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "unknown"


def _ns_key(path: str) -> tuple[int, int] | None:
    """Namespace identity as (st_dev, st_ino) — the robust form.

    readlink() on nsfs bind mounts fails outright in some restricted
    contexts (containers, sandboxes), but stat(2) keeps working and the
    device/inode pair of /run/netns/<name> equals the one of
    /proc/<pid>/ns/net for processes inside that namespace.
    """
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def current_netns_id() -> str:
    """Namespace identity of THIS process (e.g. 'net:[4026531840]')."""
    return _readlink("/proc/self/ns/net")


def host_netns_id() -> str:
    """Namespace identity of PID 1 — the host's default namespace."""
    return _readlink("/proc/1/ns/net")


def current_netns_key() -> tuple[int, int] | None:
    return _ns_key("/proc/self/ns/net")


def host_netns_key() -> tuple[int, int] | None:
    return _ns_key("/proc/1/ns/net")


def named_netns_key(name: str) -> tuple[int, int] | None:
    for base in ("/run", "/var/run"):
        key = _ns_key(os.path.join(base, "netns", name))
        if key is not None:
            return key
    return None


def namespace_exists(name: str) -> bool:
    return any(
        os.path.exists(os.path.join(base, "netns", name))
        for base in ("/run", "/var/run")
    )


def running_inside_namespace(name: str) -> bool:
    """True iff this process's netns IS the named namespace."""
    mine = current_netns_key()
    target = named_netns_key(name)
    return mine is not None and target is not None and mine == target


def validate_ip(ip: str) -> str:
    match = _VALID_IP.match(ip)
    if not match or any(int(o) > 255 for o in match.groups()):
        raise SafetyError(f"refusing to block malformed IP {ip!r}")
    return ip


def _ipt_argv(iptables_path: str, ip: str) -> list[str]:
    return [iptables_path, "-A", "INPUT", "-s", ip, "-j", "DROP"]


class LogOnlyMitigation:
    """Records blocks in memory; never executes anything.

    Used by the evaluation harness (metrics must observe decisions without
    changing the traffic mix mid-run) and by dry deployments.
    """

    def __init__(self, risk_levels=config.MITIGATION_RISK_LEVELS):
        self.risk_levels = risk_levels
        self.events: list[dict] = []
        self._blocked: set[str] = set()

    def notify(self, assessment) -> bool:
        if assessment.risk_level not in self.risk_levels:
            return False
        return self.block_ip(assessment.src_ip, assessment.timestamp,
                             assessment.risk_level)

    def block_ip(self, ip: str, timestamp: float = 0.0,
                 risk_level: str = "HIGH") -> bool:
        if ip in self._blocked:
            return False
        self._blocked.add(ip)
        self.events.append({"ts": timestamp, "src_ip": ip, "risk_level": risk_level})
        return True

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self._blocked:
            return False
        self._blocked.discard(ip)
        return True

    @property
    def blocked_ips(self) -> set[str]:
        return set(self._blocked)


class NetshMitigation:
    """Windows Defender Firewall backend (``netsh advfirewall``).

    Used only on Windows hosts where the namespace model does not exist.
    Requires an elevated process (the installed Windows service); a normal
    desktop process must never silently elevate itself mid-detection.
    """

    RULE_PREFIX = "ExfilTrap-block-"

    def __init__(self, dry_run: bool = True, require_admin: bool = True):
        self.dry_run = dry_run
        self.require_admin = require_admin
        self._blocked: set[str] = set()
        self._commands: list[list[str]] = []
        self._errors: list[str] = []

    def notify(self, assessment) -> bool:
        if assessment.risk_level not in config.MITIGATION_RISK_LEVELS:
            return False
        return self.block_ip(assessment.src_ip, assessment.timestamp,
                             assessment.risk_level)

    def _admin_check(self) -> None:
        if not self.require_admin:
            return
        from exfiltrap import privileges

        if not privileges.is_root():
            raise SafetyError(
                "netsh firewall rules require an elevated process; run the"
                " installed ExfilTrap service (it runs as the service"
                " account), not an interactive desktop process"
            )

    def block_ip(self, ip: str, timestamp: float = 0.0,
                 risk_level: str = "HIGH") -> bool:
        ip = validate_ip(ip)
        if ip in self._blocked:
            return False
        self._admin_check()
        argv = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self.RULE_PREFIX}{ip}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes",
        ]
        if self.dry_run:
            self._commands.append(argv)
            self._blocked.add(ip)
            return True
        result = subprocess.run(argv, capture_output=True, text=False)
        if result.returncode != 0:
            self._errors.append(
                f"{' '.join(argv)} -> rc={result.returncode}"
                f" stderr={result.stderr.decode(errors='replace')}"
            )
            return False
        self._blocked.add(ip)
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove this tool's rule for an IP (own prefix only)."""
        argv = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={self.RULE_PREFIX}{ip}",
        ]
        if self.dry_run:
            self._commands.append(argv)
            return True
        result = subprocess.run(argv, capture_output=True, text=False)
        return result.returncode == 0

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def pending_commands(self) -> list[list[str]]:
        return [list(c) for c in self._commands]

    def errors(self) -> list[str]:
        return list(self._errors)


class DomainSinkhole:
    """Domain-level response: answer flagged hostnames with 0.0.0.0 locally.

    Source-IP blocks are the right response for a REMOTE compromised client
    (the lab's nsB), but on a single-host deployment the source is the
    operator's own machine — blocking it cuts ALL DNS. The domain response
    is surgical: flagged hostnames go into the hosts file (0.0.0.0), killing
    that exact channel while everything else keeps working. Entries carry
    the block TTL and are removed on expiry.

    Escalation rules (the response acts on the right thing at the right
    time — a single suspicious-looking query can never take a machine
    offline, which was the shipped 1.4.0 failure mode):

    * ``CONFIRMED`` (payload decoded from THIS qname) sinks immediately —
      direct evidence on the exact hostname.
    * ``HIGH`` needs ``strikes`` (default 3) verdicts accumulating on the
      same BASE domain before the channel is convicted; on conviction the
      base domain AND the observed labels sink, and every future label
      under the base sinks on sight until the TTL expires.
    * HIGH verdicts carrying ONLY session-level evidence (per-source
      slow-drip/beacon timing, no domain-specific signal) never sink
      anything — on a single host that evidence describes the operator's
      own machine's traffic mix, and acting on it was what sank google.com.
    * Popular infrastructure (Tranco corpus + built-ins) is refused always.

    Entries cover BOTH address families (``0.0.0.0`` for A and ``::`` for
    AAAA) — a hosts file with only the IPv4 sink lets the query fall
    through to real DNS over IPv6. ``cleanup()`` removes every managed
    entry (graceful shutdown and the dashboard button); a crashed engine
    therefore never leaves the hosts file poisoned beyond the TTL reaper.

    Injection-safe: a qname must match [A-Za-z0-9._-] (no whitespace or
    newlines can reach the hosts file).
    """

    MARKER = "# exfiltrap-managed"
    _QNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

    # Entries carry their expiry IN the hosts line ("...managed;exp=<epoch>")
    # so the TTL survives an engine restart. v1.5 wrote a bare marker: those
    # legacy lines have unknown expiry and are REMOVED at startup — the old
    # code seeded them as "sunk until reaped" while the reaper only walks
    # its in-memory expiry map, so a restarted engine could keep a domain
    # blocked FOREVER. Expiry must live on the wire, not in RAM.

    @classmethod
    def _entry_line(cls, qname: str, expiry: float, family: str) -> str:
        return f"{family} {qname} {cls.MARKER};exp={int(expiry)}"

    def __init__(self, hosts_path: str = "/etc/hosts",
                 ttl: float = 3600.0, clock=time.time,
                 risk_levels=config.MITIGATION_RISK_LEVELS,
                 strikes: int = 3,
                 reputation=None, flush_enabled: bool | None = None):
        self.hosts_path = hosts_path
        self.ttl = ttl
        self.clock = clock
        # Cache flushing only makes sense for the REAL hosts file (tests
        # and offline tools use private copies); overridable for tests.
        self.flush_enabled = (platform.system() == "Linux"
                              and hosts_path == "/etc/hosts"
                              if flush_enabled is None else flush_enabled)
        self.risk_levels = risk_levels
        self.strikes = max(1, int(strikes))
        if reputation is None:
            from exfiltrap import reputation as _rep
            reputation = _rep
        self.reputation = reputation
        self._expires: dict[str, float] = {}
        # base domain -> verdict timestamps (strike accumulation window)
        self._strikes: dict[str, list[float]] = {}
        # base domain -> conviction expiry (while set, labels sink on sight)
        self._convicted_until: dict[str, float] = {}
        # qname -> expiry of entries actually written (in-memory index of
        # the hosts file; seeded from it at construction)
        self._sunk: dict[str, float] = {}
        self._hits: dict[str, int] = {}
        self._lock = threading.Lock()
        self._adopt_persisted_entries()

    def _adopt_persisted_entries(self) -> None:
        """Load sinks from a previous run: live entries resume their
        persisted TTL; expired and legacy (expiry-less) lines are swept."""
        import re as _re

        now = self.clock()
        try:
            with open(self.hosts_path, encoding="utf-8",
                      errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        stale: set[str] = set()
        kept: list[str] = []
        for ln in lines:
            if self.MARKER not in ln:
                kept.append(ln)
                continue
            parts = ln.split()
            qname = parts[1] if len(parts) >= 2 else ""
            match = _re.search(r"exp=(\d+)", ln)
            if qname and match and int(match.group(1)) > now:
                exp = float(match.group(1))
                self._sunk.setdefault(qname, exp)
                self._expires.setdefault(qname, exp)
                kept.append(ln)
            else:
                stale.add(qname)
        if stale:
            with open(self.hosts_path, "w", encoding="utf-8",
                      errors="replace") as fh:
                fh.writelines(kept)
            self._flush_resolver_cache()

    # -- hosts-file plumbing ------------------------------------------------
    def _write_entry(self, qname: str, expiry: float) -> None:
        with open(self.hosts_path, "r+", encoding="utf-8", errors="replace") as fh:
            have = [ln for ln in fh.readlines()
                    if self.MARKER in ln and f" {qname} " in f" {ln.strip()} "]
            pending = []
            for family in ("0.0.0.0", "::"):
                line = self._entry_line(qname, expiry, family)
                if not any(ln.strip() == line for ln in have):
                    pending.append(line + "\n")
            if not pending:
                return
            fh.seek(0, 2)   # append; hosts files are read top-to-bottom
            fh.writelines(pending)

    def _remove_entry(self, qname: str) -> None:
        with open(self.hosts_path, "r+", encoding="utf-8", errors="replace") as fh:
            lines = [ln for ln in fh.readlines()
                     if not (self.MARKER in ln
                             and f" {qname} " in f" {ln.strip()} ")]

        with open(self.hosts_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.writelines(lines)

    # -- response decision ----------------------------------------------
    def notify(self, assessment) -> bool:
        """Evidence-gated sink decision (see class docstring)."""
        if assessment.risk_level not in self.risk_levels:
            return False
        confirmed = bool(getattr(assessment, "confirmed_exfiltration", False))
        domain_signal = bool(getattr(assessment, "domain_signal", False))
        prob = float(getattr(assessment, "rf_probability", 0.0))
        from exfiltrap import config as _cfg
        prob_evidence = prob > _cfg.RISK_HIGH_THRESHOLD
        if not (confirmed or domain_signal or prob_evidence):
            # Session-level timing evidence only: describes the SOURCE (on a
            # single host, the operator's own machine). Alert, never sink.
            return False
        return self._escalate(assessment.qname, assessment.timestamp,
                              immediate=confirmed)

    def _escalate(self, qname: str, timestamp: float, immediate: bool) -> bool:
        from exfiltrap.features import base_domain

        qname = (qname or "").strip().rstrip(".")
        if not self._QNAME_RE.fullmatch(qname):
            return False                      # injection attempt: refuse
        base = base_domain(qname)
        if self.reputation.is_popular(qname) or self.reputation.is_popular(base):
            return False                      # popular infrastructure: never
        now = self.clock()
        # Strike windows are judged on VERDICT timestamps (packet time) so
        # the accumulation is independent of this process's clock — mixing
        # the two time bases silently reset the counter every verdict.
        with self._lock:
            if immediate:
                self._convicted_until[base] = now + self.ttl
                return self._sink(qname, base, now)
            if now < self._convicted_until.get(base, 0.0):
                return self._sink(qname, base, now)   # convicted: on sight
            times = [t for t in self._strikes.setdefault(base, [])
                     if t > timestamp - self.ttl]
            times.append(timestamp)
            self._strikes[base] = times
            if len(times) >= self.strikes:
                self._convicted_until[base] = now + self.ttl
                self._strikes.pop(base, None)
                return self._sink(qname, base, now)
        return False

    def _sink(self, qname: str, base: str, now: float) -> bool:
        expiry = now + self.ttl
        self._write_entry(qname, expiry)
        self._expires[qname] = expiry
        self._sunk[qname] = expiry
        if base != qname and not self.reputation.is_popular(base):
            self._write_entry(base, expiry)
            self._expires.setdefault(base, expiry)
            self._sunk[base] = expiry
        self._flush_resolver_cache()
        return True

    # -- DNS-cache hygiene -------------------------------------------------
    _last_flush = 0.0

    def _flush_resolver_cache(self) -> None:
        """Best-effort resolver-cache flush after a hosts-file change.

        Editing /etc/hosts does not synchronously invalidate every local
        resolver: systemd-resolved caches host lookups, and dnsmasq (from
        NetworkManager) caches longer still. Blocklist managers (Pi-hole,
        AdGuard Home) flush caches explicitly after every list change for
        exactly this reason — without it a fresh sink can appear ineffective
        on a domain the user visited seconds ago. Throttled to one attempt
        per 5s; failures are swallowed (the TTL reaper still applies).
        """
        import time as _time

        now = _time.monotonic()
        if now - DomainSinkhole._last_flush < 5.0:
            return
        DomainSinkhole._last_flush = now
        if not self.flush_enabled:
            return
        for argv in (("resolvectl", "flush-caches"),
                     ("systemd-resolve", "--flush-caches")):
            try:
                result = subprocess.run(argv, capture_output=True, timeout=5)
                if result.returncode == 0:
                    break
            except Exception:  # noqa: BLE001 — hygiene is best effort
                continue

    # -- public API -------------------------------------------------------
    def block_domain(self, qname: str, timestamp: float = 0.0) -> bool:
        """Manual/operator sink: immediate, reputation-checked."""
        return self._escalate(qname, timestamp or self.clock(), immediate=True)

    def unblock_domain(self, qname: str) -> bool:
        """Reverse a sink: frees the name AND its base conviction (the
        base was sunk as part of the same channel response)."""
        from exfiltrap.features import base_domain

        qname = (qname or "").strip().rstrip(".")
        base = base_domain(qname)
        with self._lock:
            self._expires.pop(qname, None)
            self._sunk.pop(qname, None)
            self._convicted_until.pop(base, None)
            self._strikes.pop(base, None)
            freed_base = base != qname and base in self._sunk
            if freed_base:
                self._expires.pop(base, None)
                self._sunk.pop(base, None)
        self._remove_entry(qname)
        if freed_base and not self.reputation.is_popular(base):
            self._remove_entry(base)
        self._flush_resolver_cache()
        return True

    def is_sunk(self, qname: str) -> bool:
        """True while a query for this name will be answered 0.0.0.0."""
        from exfiltrap.features import base_domain

        q = (qname or "").strip().rstrip(".")
        now = self.clock()
        with self._lock:
            exp = self._sunk.get(q)
            if exp is not None and (exp == 0.0 or exp > now):
                return True
            base = base_domain(q)
            return (now < self._convicted_until.get(base, 0.0)
                    or base in self._sunk)

    def register_hit(self, qname: str) -> int:
        """A query reached a sunk domain — count the attempt (evidence the
        response is working). Returns the running total for that name."""
        from exfiltrap.features import base_domain

        key = base_domain(qname)
        with self._lock:
            self._hits[key] = self._hits.get(key, 0) + 1
            return self._hits[key]

    def hits(self) -> dict[str, int]:
        with self._lock:
            return dict(self._hits)

    def cleanup(self) -> int:
        """Remove EVERY managed entry from the hosts file (shutdown /
        dashboard clear). Returns the number of hostnames freed."""
        freed = self.blocked_domains()
        try:
            with open(self.hosts_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                lines = fh.readlines()
            kept = [ln for ln in lines if self.MARKER not in ln]
            with open(self.hosts_path, "w", encoding="utf-8",
                      errors="replace") as fh:
                fh.writelines(kept)
        except OSError:
            return 0
        with self._lock:
            self._expires.clear()
            self._sunk.clear()
            self._convicted_until.clear()
            self._strikes.clear()
        self._flush_resolver_cache()
        return len(freed)

    def reap_expired(self) -> list[str]:
        now = self.clock()
        with self._lock:
            freed = [q for q, exp in self._expires.items() if exp <= now]
            convicted = [b for b, exp in self._convicted_until.items()
                         if exp <= now]
            for b in convicted:
                self._convicted_until.pop(b, None)
            for q in freed:
                self._expires.pop(q, None)
                self._sunk.pop(q, None)
        for q in freed:
            self._remove_entry(q)
        return freed

    def blocked_domains(self) -> list[str]:
        try:
            with open(self.hosts_path, encoding="utf-8", errors="replace") as fh:
                seen: list[str] = []
                for ln in fh.readlines():
                    if not (self.MARKER in ln and len(ln.split()) >= 2):
                        continue
                    name = ln.split()[1]
                    if name not in seen:   # A + AAAA lines share the name
                        seen.append(name)
                return seen
        except OSError:
            return []


def make_mitigation(kind: str = "auto", **kwargs):
    """Factory: 'auto' picks the platform backend, 'log'/'iptables'/'netsh' force one."""
    if kind == "log":
        return LogOnlyMitigation(**kwargs)
    if kind == "iptables":
        return IptablesMitigation(**kwargs)
    if kind == "netsh":
        return NetshMitigation(**kwargs)
    if kind == "auto":
        if platform.system() == "Windows":
            return NetshMitigation(**kwargs)
        return IptablesMitigation(**kwargs)
    raise ValueError(f"unknown mitigation kind {kind!r}")


class IptablesMitigation:
    """Applies DROP rules — strictly inside the isolated namespace."""

    def __init__(self, namespace: str = config.NAMESPACE_NAME, dry_run: bool = True,
                 override_flag: str = "", iptables_path: str = "iptables"):
        self.namespace = namespace
        self.dry_run = dry_run
        self.override_flag = override_flag
        self.iptables_path = iptables_path
        self._blocked: set[str] = set()
        self._commands: list[list[str]] = []
        self._errors: list[str] = []

    def notify(self, assessment) -> bool:
        if assessment.risk_level not in config.MITIGATION_RISK_LEVELS:
            return False
        return self.block_ip(assessment.src_ip, assessment.timestamp,
                             assessment.risk_level)

    def block_ip(self, ip: str, timestamp: float = 0.0,
                 risk_level: str = "HIGH") -> bool:
        ip = validate_ip(ip)
        if ip in self._blocked:
            return False  # in-memory set guarantees no duplicate rules

        inside = running_inside_namespace(self.namespace)
        mine, host, target = (
            current_netns_key(), host_netns_key(),
            named_netns_key(self.namespace),
        )
        proven_elsewhere = (
            mine is not None and host is not None and target is not None
            and mine != target and mine != host
        )
        if inside:
            # Already inside the isolated ruleset; plain iptables is scoped
            # to it by the kernel.
            argv = _ipt_argv(self.iptables_path, ip)
        elif namespace_exists(self.namespace) and not proven_elsewhere:
            # On the host, or unable to prove our position (restricted
            # readlink/stat): the netns-exec route targets the named
            # namespace's ruleset EXPLICITLY, so it is safe either way.
            argv = ["ip", "netns", "exec", self.namespace] + _ipt_argv(
                self.iptables_path, ip
            )
        elif namespace_exists(self.namespace):
            # Provably inside some OTHER namespace: refuse rather than guess.
            raise SafetyError(
                f"process is in a non-host namespace that is not"
                f" {self.namespace!r} (self={mine}, host={host},"
                f" target={target}); refusing to execute iptables"
            )
        elif self.override_flag == config.IPTABLES_OVERRIDE_FLAG:
            # Explicit opt-in. This is the ONLY path that can ever touch a
            # real host firewall, and it requires the literal flag.
            argv = _ipt_argv(self.iptables_path, ip)
        else:
            raise SafetyError(
                f"namespace {self.namespace!r} does not exist and no override"
                f" given; the host firewall is never touched without"
                f" {config.IPTABLES_OVERRIDE_FLAG}"
            )

        if self.dry_run:
            self._commands.append(argv)
            self._blocked.add(ip)
            return True

        result = subprocess.run(argv, capture_output=True, text=False)
        if result.returncode != 0:
            self._errors.append(
                f"{' '.join(argv)} -> rc={result.returncode}"
                f" stderr={result.stderr.decode(errors='replace')}"
            )
            return False
        self._blocked.add(ip)
        return True

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def unblock_ip(self, ip: str) -> bool:
        """Policy-engine reversal: DELETE this tool's DROP rule."""
        ip = validate_ip(ip)
        if ip not in self._blocked:
            return False
        base = [self.iptables_path, "-D", "INPUT", "-s", ip, "-j", "DROP"]
        if running_inside_namespace(self.namespace):
            argv = base
        elif namespace_exists(self.namespace):
            argv = ["ip", "netns", "exec", self.namespace] + base
        else:
            return False  # nothing we (safely) created remains
        if self.dry_run:
            self._commands.append(argv)
            self._blocked.discard(ip)
            return True
        result = subprocess.run(argv, capture_output=True, text=False)
        if result.returncode == 0:
            self._blocked.discard(ip)
            return True
        self._errors.append(f"unblock {ip} rc={result.returncode}")
        return False

    def pending_commands(self) -> list[list[str]]:
        """Commands recorded while in dry-run mode."""
        return [list(c) for c in self._commands]

    def errors(self) -> list[str]:
        return list(self._errors)
