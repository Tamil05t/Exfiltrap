"""Per-process attribution of DNS queries — who owns the querying socket.

The papers this project is measured against stop at "suspicious source IP".
On a real single-host deployment that is useless: the source is always the
machine itself (loopback stub or the host's LAN IP). The question an
operator actually asks is **which application** opened this socket. On
Linux the kernel answers it in /proc:

1. ``/proc/net/udp`` + ``/proc/net/udp6`` map ``(local addr, local port)``
   to the socket's kernel inode.
2. ``/proc/<pid>/fd/*`` symlinks of the form ``socket:[<inode>]`` map the
   inode back to the owning process.
3. ``/proc/<pid>/comm`` (fallback: the ``exe`` link basename) names it.

All reads are best effort: anything unreadable (permissions, race with
process exit, exotic namespaces) yields ``None`` and the caller simply
shows "unknown" — attribution must never break detection. The socket-owner
scan walks every PID, so results are cached with short TTLs: UDP sockets
of running applications persist for minutes, and a query burst reuses the
same socket, so the amortized cost of a busy host is a couple of /proc
passes per second at most, not per packet.
"""

from __future__ import annotations

import os
import threading
import time

_UDP_TABLES = ("/proc/net/udp", "/proc/net/udp6")
_PORTMAP_TTL = 2.0        # /proc/net/udp re-read cadence
_SCAN_TTL = 2.0           # /proc/*/fd socket-inode scan cadence
_RESULT_TTL = 30.0        # a resolved (ip, port) -> process stays valid
_MISS_TTL = 5.0           # unknown sockets re-probed sooner (they appear/disappear)

_lock = threading.Lock()
_port_inodes: dict[tuple[str, int], int] = {}
_port_inodes_at = 0.0
_inode_pids: dict[int, tuple[int, str]] = {}
_inode_pids_at = 0.0
_results: dict[tuple[str, int], tuple[float, str | None]] = {}


def _hex_ipv4(h: str) -> str:
    """'0100007F' -> '127.0.0.1' (kernel prints IPv4 little-endian)."""
    raw = bytes.fromhex(h)[::-1]
    return ".".join(str(b) for b in raw)


def _hex_ipv6(h: str) -> str:
    """32 hex chars -> IPv6 string (four little-endian u32 words)."""
    import ipaddress

    words = [int(h[i:i + 8], 16) for i in range(0, 32, 8)]
    raw = b"".join(w.to_bytes(4, "little") for w in words)
    return str(ipaddress.IPv6Address(raw))


def _read_udp_tables() -> dict[tuple[str, int], int]:
    """(local addr, local port) -> socket inode, from both UDP tables."""
    found: dict[tuple[str, int], int] = {}
    for path in _UDP_TABLES:
        try:
            with open(path) as fh:
                next(fh)  # header
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, _, port = parts[1].rpartition(":")
                    try:
                        inode = int(parts[9])
                        port = int(port, 16)
                    except ValueError:
                        continue
                    if len(local) == 8:
                        addr = _hex_ipv4(local)
                    elif len(local) == 32:
                        addr = _hex_ipv6(local)
                    else:
                        continue
                    found[(addr, port)] = inode
        except OSError:
            continue  # table unreadable (container, hardening): skip it
    return found


def _socket_inode_pid(inode: int) -> tuple[int, str] | None:
    """Scan /proc/<pid>/fd for the socket:[inode] symlink -> (pid, name)."""
    try:
        pids = [e for e in os.scandir("/proc") if e.name.isdigit()]
    except OSError:
        return None
    for entry in pids:
        pid = int(entry.name)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.scandir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd.name))
            except OSError:
                continue
            if target == f"socket:[{inode}]":
                name = _process_name(pid)
                return (pid, name)
    return None


def _process_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip() or "unknown"
    except OSError:
        pass
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        return os.path.basename(exe) or "unknown"
    except OSError:
        return "unknown"


def resolve(src_ip: str, sport: int) -> str | None:
    """Socket owner for (source IP, UDP source port): ``"name (pid N)"``.

    Returns None when the platform cannot answer (Windows, restricted
    /proc, socket already gone). Cached per key.
    """
    if not src_ip or not sport or os.name != "posix":
        return None
    key = (src_ip, sport)
    now = time.monotonic()
    with _lock:
        hit = _results.get(key)
        if hit is not None and now - hit[0] <= (_RESULT_TTL if hit[1] else _MISS_TTL):
            return hit[1]

    result = _resolve_uncached(src_ip, sport)
    with _lock:
        _results[key] = (now, result)
        while len(_results) > 1024:
            _results.pop(next(iter(_results)))
    return result


def _resolve_uncached(src_ip: str, sport: int) -> str | None:
    global _port_inodes, _port_inodes_at, _inode_pids, _inode_pids_at

    now = time.monotonic()
    with _lock:
        if now - _port_inodes_at > _PORTMAP_TTL or not _port_inodes:
            _port_inodes = _read_udp_tables()
            _port_inodes_at = now
        inode = _port_inodes.get((src_ip, sport))
        if inode is None:
            # One retry after a forced refresh: a socket opened within the
            # last TTL window is absent from the cached table.
            _port_inodes = _read_udp_tables()
            _port_inodes_at = now
            inode = _port_inodes.get((src_ip, sport))
        if inode is None:
            return None
        if now - _inode_pids_at > _SCAN_TTL or inode not in _inode_pids:
            owner = _socket_inode_pid(inode)
            if owner is not None:
                _inode_pids[inode] = owner
                _inode_pids_at = now
        owner = _inode_pids.get(inode)
    if owner is None:
        return None
    pid, name = owner
    return f"{name} (pid {pid})"
