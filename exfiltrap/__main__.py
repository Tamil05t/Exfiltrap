"""Single-entry dispatcher: ``exfiltrap <subcommand> ...``.

Lets the packaged executables (PyInstaller on Windows, the installed
launcher on Linux) expose one binary for everything:

    exfiltrap service ...        detection service (capture + API + UI)
    exfiltrap winservice ...     Windows service install/remove/start/stop
    exfiltrap dashboard ...       standalone dashboard against a DB file
    exfiltrap privileges          privilege report
    exfiltrap eval ...            evaluation harness
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        # No arguments at all. Two very different callers land here and they
        # want opposite things:
        #
        #   - the Service Control Manager, which launches the binary
        #     registered for ExfilTrapSvc with exactly the command line in
        #     its ImagePath (currently a bare path, no arguments) and then
        #     waits 30 s for the process to call StartServiceCtrlDispatcher;
        #   - a user double-clicking exfiltrap.exe or typing `exfiltrap` in
        #     Win+R, who wants the console.
        #
        # This branch used to print the docstring and return 0, which made
        # every service start fail: the SCM saw the process exit without
        # ever registering, and logged Event 7009/7000 "did not respond to
        # the start or control request in a timely fashion". The dispatcher
        # in winservice.main was correct but unreachable — __main__ swallowed
        # the empty argv before it got there.
        #
        # pywin32's own HandleCommandLine resolves the ambiguity the same
        # way we do now: try to host the service, and read
        # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) as "the SCM did not
        # start us". StartServiceCtrlDispatcher blocks for the whole service
        # lifetime when it does succeed, so the fall-through only happens on
        # an ordinary interactive launch.
        if os.name == "nt":
            from exfiltrap.winservice import try_host_service
            if try_host_service():
                return 0
            from exfiltrap.dashboard.app import main as run
            return run([])
        print(__doc__)
        return 0
    if argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]

    try:
        return _dispatch(cmd, rest)
    except ModuleNotFoundError as exc:
        print(
            f"ExFilTrap dependencies are missing ({exc.name}).\n"
            "Install them with:\n"
            "  python3 -m pip install --break-system-packages -r requirements.txt\n"
            "or run through the project virtualenv (.venv/bin/python)."
        )
        return 1


def _dispatch(cmd, rest):
    if cmd == "service":
        from exfiltrap.service import main as run
        return run(rest)
    if cmd == "winservice":
        from exfiltrap.winservice import main as run
        return run(rest)
    if cmd == "dashboard":
        from exfiltrap.dashboard.app import main as run
        return run(rest)
    if cmd == "privileges":
        from exfiltrap.privileges import main as run
        return run(rest)
    if cmd in ("pipeline", "eval"):
        # pipeline takes the classic module CLI (live mode).
        if cmd == "pipeline":
            from exfiltrap.pipeline import main as run
            return run(rest)
        import importlib.util
        from pathlib import Path

        # Frozen builds (PyInstaller) unpack datas under sys._MEIPASS;
        # source runs resolve relative to this file.
        base = Path(getattr(sys, "_MEIPASS",
                            Path(__file__).resolve().parent.parent))
        eval_path = base / "eval" / "run_evaluation.py"
        if not eval_path.exists():
            eval_path = (Path(__file__).resolve().parent.parent / "eval"
                         / "run_evaluation.py")
        spec = importlib.util.spec_from_file_location("run_evaluation",
                                                      eval_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.main(rest)
    print(f"unknown subcommand {cmd!r}\n\n{__doc__}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
