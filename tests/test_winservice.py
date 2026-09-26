"""Regression tests for the Windows Service wrapper.

These tests exist because ``exfiltrap/winservice.py`` shipped a bug that
made the packaged Windows product dead on arrival: ``main()`` called::

    win32serviceutil.InstallService(..., starttype=2)

but pywin32's keyword is ``startType`` (camelCase). The mismatch raised
``TypeError: InstallService() got an unexpected keyword argument
'starttype'`` inside the installer's ``[Run]`` step, so the service was
never registered. There was no test covering this module at all.

The tests run on every platform by stubbing the pywin32 surface: they
verify *our* call sites against the documented pywin32 signatures rather
than requiring a real Windows install.
"""

from __future__ import annotations

import inspect
import sys
import types

import pytest

# The real parameter names of pywin32's InstallService (verbatim from
# win32/Lib/win32serviceutil.py). Hard-coded here so the test fails loudly
# if our call site ever passes a keyword pywin32 does not accept — which is
# exactly the failure class that broke the Windows deploy.
PYWIN32_INSTALLSERVICE_PARAMS = {
    "pythonClassString", "serviceName", "displayName", "startType",
    "errorControl", "bRunInteractive", "serviceDeps", "userName",
    "password", "exeName", "perfMonIni", "perfMonDll", "exeArgs",
    "description", "delayedstart",
}


def _install_fake_pywin32(monkeypatch, calls: list):
    """Install minimal win32service / win32serviceutil stubs.

    Records every call so the test can assert on the exact kwargs our code
    forwards, and rejects keywords that are not in the real signature.
    """

    win32service = types.ModuleType("win32service")
    win32service.SERVICE_AUTO_START = 2
    win32service.SERVICE_DEMAND_START = 3
    win32service.SERVICE_STOP_PENDING = 3

    def _install_service(*args, **kwargs):
        bad = set(kwargs) - PYWIN32_INSTALLSERVICE_PARAMS
        if bad:
            raise TypeError(
                "InstallService() got an unexpected keyword argument "
                f"{sorted(bad)[0]!r}")
        calls.append(("install", args, kwargs))

    win32serviceutil = types.ModuleType("win32serviceutil")

    class _ServiceFramework:  # pragma: no cover - trivial shim
        def __init__(self, args):
            self.args = args

    win32serviceutil.ServiceFramework = _ServiceFramework
    win32serviceutil.InstallService = _install_service
    win32serviceutil.RemoveService = (
        lambda *a, **k: calls.append(("remove", a, k)))
    win32serviceutil.StartService = (
        lambda *a, **k: calls.append(("start", a, k)))
    win32serviceutil.StopService = (
        lambda *a, **k: calls.append(("stop", a, k)))

    win32event = types.ModuleType("win32event")
    win32event.CreateEvent = lambda *a, **k: object()
    win32event.SetEvent = lambda *a, **k: None
    win32event.WaitForSingleObject = lambda *a, **k: None

    servicemanager = types.ModuleType("servicemanager")
    servicemanager.Initialize = lambda: None
    servicemanager.PrepareToHostSingle = lambda *a, **k: None
    servicemanager.StartServiceCtrlDispatcher = lambda *a, **k: None
    servicemanager.LogMsg = lambda *a, **k: None
    servicemanager.EVENTLOG_INFORMATION_TYPE = 1
    servicemanager.PYS_SERVICE_STARTED = 0

    for name, mod in (
        ("win32service", win32service),
        ("win32serviceutil", win32serviceutil),
        ("win32event", win32event),
        ("servicemanager", servicemanager),
    ):
        monkeypatch.setitem(sys.modules, name, mod)


class TestWinserviceInstall:
    def test_install_uses_camelcase_starttype(self, monkeypatch):
        """The exact bug: `starttype=` must be `startType=`."""
        calls: list = []
        _install_fake_pywin32(monkeypatch, calls)

        from exfiltrap import winservice

        rc = winservice.main(["install"])
        assert rc == 0

        action, args, kwargs = calls[-1]
        assert action == "install"
        # pywin32's 4th parameter is camelCase; a lowercase kwarg would
        # have raised TypeError inside the stub above.
        assert "startType" in kwargs
        assert kwargs["startType"] == 2  # SERVICE_AUTO_START
        assert "starttype" not in kwargs
        # pythonClassString is intentionally None (frozen exe self-hosts).
        assert args[0] is None

    def test_install_never_leaks_unknown_kwargs(self, monkeypatch):
        """Every kwarg we forward must exist on the real pywin32 API."""
        calls: list = []
        _install_fake_pywin32(monkeypatch, calls)

        from exfiltrap import winservice

        winservice.main(["install"])
        _action, _args, kwargs = calls[-1]
        assert set(kwargs) <= PYWIN32_INSTALLSERVICE_PARAMS


class TestWinserviceDispatch:
    def test_no_args_routes_to_scm_dispatcher(self, monkeypatch):
        """SCM launches the frozen exe with NO arguments; that must take
        the service-hosting path, never the CLI path."""
        calls: list = []
        _install_fake_pywin32(monkeypatch, calls)
        dispatcher_called = {"n": 0}

        servicemanager = sys.modules["servicemanager"]

        def _dispatch():
            dispatcher_called["n"] += 1

        monkeypatch.setattr(servicemanager, "StartServiceCtrlDispatcher",
                            _dispatch)
        # _get_service_class() imports pywin32 inside the function body.
        from exfiltrap import winservice

        rc = winservice.main([])  # SCM passes no args
        assert rc == 0
        assert dispatcher_called["n"] == 1

    def test_run_flag_routes_to_scm_dispatcher(self, monkeypatch):
        calls: list = []
        _install_fake_pywin32(monkeypatch, calls)
        dispatcher_called = {"n": 0}
        sys.modules["servicemanager"].StartServiceCtrlDispatcher = (
            lambda: dispatcher_called.__setitem__("n", 1))

        from exfiltrap import winservice

        assert winservice.main(["--run"]) == 0
        assert dispatcher_called["n"] == 1


class TestServiceArgs:
    def test_service_ini_drives_argv(self, monkeypatch, tmp_path):
        """service.ini [service] iface/mitigation map to service argv."""
        ini = tmp_path / "service.ini"
        ini.write_text("[service]\niface = Ethernet\nmitigation = log\n")
        monkeypatch.setattr("exfiltrap.winservice.INI_PATH", str(ini))

        from exfiltrap import winservice

        args = winservice.service_args()
        assert args[:3] == ["--iface", "Ethernet", "--mitigation"]
        assert "--execute" not in args

    def test_execute_flag_is_opt_in(self, monkeypatch, tmp_path):
        ini = tmp_path / "service.ini"
        ini.write_text(
            "[service]\niface = Ethernet\nmitigation = netsh\nexecute = yes\n")
        monkeypatch.setattr("exfiltrap.winservice.INI_PATH", str(ini))

        from exfiltrap import winservice

        args = winservice.service_args()
        assert "--execute" in args
        assert "netsh" in args

    def test_missing_section_falls_back(self, monkeypatch, tmp_path):
        """A service.ini without a [service] section must not raise
        (NoSectionError) — it falls back to auto-detection."""
        ini = tmp_path / "service.ini"
        ini.write_text("; empty\n")
        monkeypatch.setattr("exfiltrap.winservice.INI_PATH", str(ini))
        monkeypatch.setattr("exfiltrap.winservice._first_interface",
                            lambda: "Ethernet")

        from exfiltrap import winservice

        args = winservice.service_args()
        assert "--iface" in args
        assert "Ethernet" in args
