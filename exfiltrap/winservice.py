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
    """Build the service-mode argv from service.ini.

    The INSTALLED product is always live capture (per the project's
    root-only, no-demo ground rule), so the resulting argv never selects a
    demo mode. ``iface = auto`` (what the installer writes) is resolved to
    the real default-route adapter here, at service start.
    """
    import configparser

    cp = configparser.ConfigParser()
    cp.read(INI_PATH)
    has = cp.has_section("service")
    iface = cp.get("service", "iface", fallback="") if has else ""
    mitigation = cp.get("service", "mitigation", fallback="log") if has else "log"
    execute = cp.getboolean("service", "execute", fallback=False) if has else False

    # Unset, blank, or the installer's "auto" -> detect the default-route
    # adapter now. This is the ONE place auto is resolved; the engine also
    # understands --iface auto, but resolving here means a failure surfaces
    # in the service log with a concrete candidate list.
    if not iface or iface.strip().lower() == "auto":
        iface = _first_interface()
    return ["--iface", iface, "--mitigation", mitigation] + (
        ["--execute"] if execute else [])


def _first_interface() -> str:
    """The adapter carrying the default route (Windows).

    Falls back to the first UP adapter, then to the historical "Ethernet"
    literal, so a service start never dies on detection alone — the engine
    itself reports a clear error if the name is wrong, and the operator can
    correct service.ini.
    """
    try:
        from exfiltrap import netif

        name = netif.default_interface()
        if name:
            return name
        up = netif.list_interfaces()
        if up:
            return up[0]
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

            # The service loop is stopped through svc.request_stop(), NOT by
            # raising SIGTERM. SvcDoRun runs on a worker thread, where
            # signal.signal() is illegal, so no handler is ever installed and
            # raise_signal(SIGTERM) would take SIGTERM's default action: an
            # immediate process kill that skips the hosts-file cleanup in
            # service._request_stop. request_stop() runs that cleanup.
            import threading
            import time

            def _stop_service():
                win32event.WaitForSingleObject(self.stop_event, -1)
                # A stop can arrive while the engine is still building its
                # pipeline, before the hook is published. Wait briefly for it
                # rather than leaving the service hanging on stop — but do
                # not outlast the SCM's own stop timeout.
                for _ in range(100):
                    if svc.request_stop():
                        return
                    time.sleep(0.1)
                log.warning(
                    "stop requested but the service loop never published a "
                    "shutdown hook"
                )

            threading.Thread(target=_stop_service, daemon=True).start()
            svc.main(service_args())

    return ExfilTrapWindowsService


def try_host_service() -> bool:
    """Host the Windows service, but only if the SCM really started us.

    Returns True when this process actually ran as the service — the call
    blocks for the whole service lifetime, so True means the service has now
    stopped — and False when the process was started some other way.

    The distinction is unavoidable: the SCM launches the registered binary
    with no arguments, which looks exactly like a user double-clicking it.
    pywin32's own HandleCommandLine resolves it the same way we do:
    StartServiceCtrlDispatcher fails immediately with
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) when the process was not
    started by the SCM, and blocks until the service stops when it was.
    """
    import win32service

    servicemanager = __import__("servicemanager")
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_get_service_class())
    try:
        servicemanager.StartServiceCtrlDispatcher()
    except win32service.error as exc:
        # 1063 == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, written literally
        # rather than imported from `winerror` so this keeps working if that
        # constant ever moves.
        if exc.winerror == 1063:
            return False
        raise
    return True


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if "--run" in argv or not argv:
        # SCM-started path: hand control to pywin32's dispatcher.
        try_host_service()
        return 0

    cls = _get_service_class()
    import win32service
    import win32serviceutil

    cmd = argv[0]
    if cmd == "install":
        # NOTE: pywin32's keyword is `startType` (camelCase). Passing
        # `starttype` (all lowercase) raises TypeError and aborts the
        # install, so the Windows service never registers — the single
        # reason the packaged Windows product used to fail at deploy time.
        # SERVICE_AUTO_START == 2. `pythonClassString=None` is intentional:
        # the frozen exe hosts itself (SCM launches it with no args and we
        # dispatch), so no PythonClass registry value is needed.
        win32serviceutil.InstallService(
            None, cls._svc_name_, cls._svc_display_name_,
            description=cls._svc_description_,
            startType=win32service.SERVICE_AUTO_START)
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
