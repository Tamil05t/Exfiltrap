"""Windows Service wrapper for the ExfilTrap detection service.

Registers the detection daemon as a proper Windows Service so it runs at
boot under the service account (SYSTEM) — matching the "install once with
UAC, then it behaves like every other application" deployment model. The
desktop app never elevates; it only talks to the localhost API.

Requires ``pywin32`` (imported lazily so the rest of the project works
untouched on Linux). Service parameters (interface, mitigation mode) come
from ``%PROGRAMDATA%\\ExfilTrap\\service.ini``:

    [service]
    iface = Ethernet
    mitigation = log
    execute = no

Usage (elevated prompt):
    exfiltrap.exe winservice install     (also: remove / start / stop / run)
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger("exfiltrap.winservice")

SERVICE_NAME = "ExfilTrapSvc"
SERVICE_DISPLAY = "ExfilTrap DNS Exfiltration Detection"
INI_DIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\\ProgramData"),
                       "ExfilTrap")
INI_PATH = os.path.join(INI_DIR, "service.ini")


def service_args() -> list[str]:
    """Build the service-mode argv from service.ini (falls back to demo)."""
    import configparser

    cp = configparser.ConfigParser()
    cp.read(INI_PATH)
    if cp.has_section("service") and cp.get("service", "iface", fallback=None):
        return ["--iface", cp.get("service", "iface"),
                "--mitigation", cp.get("service", "mitigation", "log"),
                ] + (["--execute"] if cp.getboolean(
                    "service", "execute", fallback=False) else [])
    # No configured interface: pick the first active adapter (root service
    # runs live capture — the installed product is always live).
    iface = cp.get("service", "iface", fallback=None) if cp.has_section("service") else None
    if not iface or iface.lower() == "auto":
        iface = _first_interface()
    return ["--iface", iface,
            "--mitigation", cp.get("service", "mitigation", "log")] + (
            ["--execute"] if cp.getboolean("service", "execute",
                                           fallback=False) else [])


def _first_interface() -> str:
    """First active non-loopback adapter (Windows)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetAdapter | Where-Object Status -eq 'Up' | "
             "Select-Object -First 1).Name"],
            capture_output=True, text=True, timeout=15)
        name = out.stdout.strip()
        if name:
            return name
    except Exception:
        pass
    return "Ethernet"


def _get_service_class():
    import win32serviceutil  # noqa: F401  (lazy: Windows + pywin32 only)
    import servicemanager
    import win32event
    import win32service

    class ExfilTrapWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = (
            "Detects DNS tunneling and slow-drip data exfiltration and "
            "applies firewall mitigation. Local API on 127.0.0.1:5050."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""),
            )
            from exfiltrap import service as svc

            # The service loop reacts to the Windows stop event by raising
            # the same SIGTERM the POSIX path uses.
            import threading

            def _stop_and_signal():
                win32event.WaitForSingleObject(self.stop_event, -1)
                # Interrupt the Flask server thread with KeyboardInterrupt.
                import signal as _signal

                _signal.raise_signal(_signal.SIGTERM)

            threading.Thread(target=_stop_and_signal, daemon=True).start()
            svc.main(service_args())

    return ExfilTrapWindowsService


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if "--run" in argv or not argv:
        # SCM-started path: hand control to pywin32's dispatcher.
        servicemanager = __import__("servicemanager")
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(_get_service_class())
        servicemanager.StartServiceCtrlDispatcher()
        return 0

    cls = _get_service_class()
    import win32serviceutil

    cmd = argv[0]
    if cmd == "install":
        win32serviceutil.InstallService(None, cls._svc_name_,
                                        cls._svc_display_name_,
                                        description=cls._svc_description_,
                                        starttype=2)  # auto start at boot
        print(f"installed {SERVICE_NAME} (auto-start). Configure "
              f"{INI_PATH} then: exfiltrap winservice start")
        return 0
    if cmd == "remove":
        win32serviceutil.RemoveService(cls._svc_name_)
        print(f"removed {SERVICE_NAME}")
        return 0
    if cmd == "start":
        win32serviceutil.StartService(cls._svc_name_)
        print(f"started {SERVICE_NAME}")
        return 0
    if cmd == "stop":
        win32serviceutil.StopService(cls._svc_name_)
        print(f"stopped {SERVICE_NAME}")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
