"""Network interface auto-detection.

The detector should not ask the operator which interface carries the
internet — it can know: the default-route interface (the one the kernel
uses for 0.0.0.0/0) is the right one, whether that is eth0, wlan0, wlo1 or
anything else. Detection is best-effort and returns None when it cannot
decide, in which case callers list the candidates instead of guessing.

Two host facts drive the response policy and a detection signal:

* ``own_addresses()`` — every address that belongs to THIS machine. The
  policy layer must never firewall these (blocking the operator's own
  source IP is the self-DoS failure mode, not a mitigation).
* ``system_nameservers()`` — the resolvers the OS is configured to use
  (``/etc/resolv.conf`` / PowerShell). A query addressed anywhere else is
  a resolver-bypass signal (covert channels skip the monitored stub).
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess


def default_interface() -> str | None:
    """The interface currently used for the default route, or None."""
    if platform.system() == "Windows":
        return _windows_default()
    return _linux_default()


def _run_powershell(script: str, timeout: int = 15):
    """Run a PowerShell snippet and return its stdout, or "".

    Windows PowerShell 5.1 ships as ``powershell``; PowerShell 7+ ships as
    ``pwsh`` and some hardened/Server Core images only have one of the two,
    so try both before giving up. Never raises — detection must not crash
    the caller.
    """
    for exe in ("powershell", "pwsh"):
        try:
            out = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=timeout)
            text = (out.stdout or "").strip()
            if text:
                return text
        except Exception:  # noqa: BLE001
            continue
    return ""


def _linux_default() -> str | None:
    # /proc/net/route: a row with Destination 00000000 is the default route.
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError:
        pass
    # Fallback: iproute2
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5)
        match = re.search(r"dev\s+(\S+)", out.stdout)
        if match:
            return match.group(1)
    except Exception:  # noqa: BLE001 — detection must never crash the setup
        pass
    return None


def _windows_default() -> str | None:
    ps = ("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
          "Sort-Object RouteMetric | Select-Object -First 1 | "
          "Get-NetAdapter).Name")
    name = _run_powershell(ps)
    if not name:
        # Fallback for hosts without the NetTCPIP module (rare, Server Core).
        ps_alt = ("(Get-NetIPConfiguration | Where-Object "
                  "{ $_.NetProfile.IPv4Connectivity -eq 'Internet' } | "
                  "Select-Object -First 1).InterfaceAlias")
        name = _run_powershell(ps_alt)
    return name or None


def list_interfaces() -> list[str]:
    """All non-loopback interfaces, for the 'could not detect' message."""
    if platform.system() == "Windows":
        text = _run_powershell(
            "(Get-NetAdapter | Where-Object Status -eq 'Up').Name")
        return [ln.strip() for ln in text.splitlines() if ln.strip()]
    try:
        with open("/proc/net/dev") as fh:
            names = [line.split(":")[0].strip()
                     for line in fh.readlines() if ":" in line]
        return [n for n in names if n != "lo"]
    except OSError:
        return []


def own_addresses() -> list[str]:
    """Every unicast address that belongs to this host (best effort).

    Sources, in order: the connect-trick (the kernel picks the source
    address it would use for the default route), hostname resolution, and
    a SIOCGIFADDR ioctl per interface. Loopback is handled separately by
    the policy (any 127/8 or ::1), and nothing here is load-bearing for
    detection — a miss only means the policy may fall back to asking the
    operator, never to blocking something blindly.
    """
    found: set[str] = set()

    # 1. connect-trick: which source would the kernel use right now?
    for probe in ("8.8.8.8", "2001:4860:4860::8888"):
        try:
            family = socket.AF_INET if ":" not in probe else socket.AF_INET6
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((probe, 53))
                found.add(s.getsockname()[0])
        except OSError:
            continue

    # 2. hostname resolution
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass

    if platform.system() != "Windows":
        # 3. per-interface ioctl
        import fcntl
        import struct
        import array

        max_ifaces = 128
        bytes_ = max_ifaces * 40
        names = array.array("B", b"\0" * bytes_)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            out_bytes_len, _ = struct.unpack(
                "iL", fcntl.ioctl(
                    sock.fileno(), 0x8912,
                    struct.pack("iL", bytes_, names.buffer_info()[0])))
            name_list = names.tobytes()
            for i in range(0, out_bytes_len, 40):
                iface = name_list[i:i + 16].split(b"\0", 1)[0].decode()
                try:
                    addr = fcntl.ioctl(sock.fileno(), 0x8915,
                                       struct.pack("256s", iface[:15].encode()))
                    found.add(socket.inet_ntoa(addr[20:24]))
                except OSError:
                    continue
    return sorted(a for a in found if a and not a.startswith("fe80"))


def system_nameservers() -> set[str]:
    """Resolvers the OS is configured to use (best effort, empty on doubt).

    Linux: ``/etc/resolv.conf`` nameserver lines (systemd-resolved shows up
    as 127.0.0.53). Windows: Get-DnsClientServerAddress via PowerShell.
    """
    servers: set[str] = set()
    if platform.system() == "Windows":
        text = _run_powershell(
            "(Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Select-Object -ExpandProperty ServerAddresses)")
        servers |= {ln.strip() for ln in text.splitlines() if _is_ip(ln.strip())}
        return servers
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1]
                    if _is_ip(candidate):
                        servers.add(candidate)
    except OSError:
        pass
    return servers


def _is_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False
