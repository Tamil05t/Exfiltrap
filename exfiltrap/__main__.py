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

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]

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

        spec = importlib.util.spec_from_file_location(
            "run_evaluation", Path(__file__).parent.parent / "eval"
            / "run_evaluation.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.main(rest)
    print(f"unknown subcommand {cmd!r}\n\n{__doc__}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
