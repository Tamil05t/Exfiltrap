"""Privilege and capability discovery.

The service needs exactly two elevated abilities on Linux (packet capture
and firewall manipulation) and administrator context on Windows. This
module reports — without ever granting — what the current process can do,
so every entrypoint can fail fast with an actionable message instead of a
deep stack trace, and the installer/docs can verify the deployment.

Runtime model (the "install once, run like a normal app" requirement):

* Linux: the systemd unit runs the daemon as a dedicated unprivileged user
  with ``AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`` — the process is
  never root, it only carries the two capabilities it needs.
* Windows: the service runs as the installed Windows Service (SYSTEM); the
  dashboard/desktop app is a plain unprivileged reader of the local API.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys

# Capability bit numbers from linux/capability.h
CAP_NET_RAW = 13
CAP_NET_ADMIN = 12


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_root() -> bool:
    """True when running as root/Administrator/SYSTEM."""
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _cap_eff_bits() -> int:
    """Effective capability set as a bitmask (Linux only, best-effort)."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except OSError:
        pass
    return 0


def has_capability(bit: int) -> bool:
    return bool(_cap_eff_bits() & (1 << bit))


def has_capture_capability() -> bool:
    """Can open raw/sniffing sockets (CAP_NET_RAW or root)."""
    if is_windows():
        return is_root()  # Npcap capture requires elevation on Windows
    return is_root() or has_capability(CAP_NET_RAW)


def has_firewall_capability() -> bool:
    """Can install firewall rules (CAP_NET_ADMIN/root on Linux, admin on Windows)."""
    if is_windows():
        return is_root()
    return is_root() or has_capability(CAP_NET_ADMIN)


def privilege_report() -> dict:
    return {
        "platform": platform.system(),
        "python": sys.version.split()[0],
        "uid": None if is_windows() else os.geteuid(),
        "is_root": is_root(),
        "capabilities": {
            "CAP_NET_RAW": has_capability(CAP_NET_RAW) if is_linux() else None,
            "CAP_NET_ADMIN": has_capability(CAP_NET_ADMIN) if is_linux() else None,
        },
        "can_capture": has_capture_capability(),
        "can_modify_firewall": has_firewall_capability(),
        "capture_hint": (
            "run via `systemctl start exfiltrap` (the service carries "
            "CAP_NET_RAW/CAP_NET_ADMIN), or with sudo for interactive use"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m exfiltrap.privileges",
        description="report what the current process is allowed to do",
    )
    parser.parse_args(argv)
    for key, value in privilege_report().items():
        print(f"{key:20s} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
