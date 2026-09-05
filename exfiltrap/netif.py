"""Network interface auto-detection.

The detector should not ask the operator which interface carries the
internet — it can know: the default-route interface (the one the kernel
uses for 0.0.0.0/0) is the right one, whether that is eth0, wlan0, wlo1 or
anything else. Detection is best-effort and returns None when it cannot
decide, in which case callers list the candidates instead of guessing.
"""

from __future__ import annotations

import platform
import re
import subprocess


def default_interface() -> str | None:
    """The interface currently used for the default route, or None."""
    if platform.system() == "Windows":
        return _windows_default()
    return _linux_default()


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
    try:
        ps = ("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
              "Sort-Object RouteMetric | Select-Object -First 1 | "
              "Get-NetAdapter).Name")
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15)
        if out.stdout.strip():
            return out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return None


def list_interfaces() -> list[str]:
    """All non-loopback interfaces, for the 'could not detect' message."""
    if platform.system() == "Windows":
        try:
            ps = "(Get-NetAdapter | Where-Object Status -eq 'Up').Name"
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=15)
            return [line.strip() for line in out.stdout.splitlines()
                    if line.strip()]
        except Exception:  # noqa: BLE001
            return []
    try:
        with open("/proc/net/dev") as fh:
            names = [line.split(":")[0].strip()
                     for line in fh.readlines() if ":" in line]
        return [n for n in names if n != "lo"]
    except OSError:
        return []
