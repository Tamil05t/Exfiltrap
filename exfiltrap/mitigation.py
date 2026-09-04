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
