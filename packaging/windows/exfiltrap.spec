# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the Windows ExfilTrap build.
#
# IMPORTANT (antivirus posture): we use --onedir, NEVER --onefile.
# onefile bundles self-extract to a temp dir at every launch — behavior
# heuristics associate with packed malware, and it slows every start.
# onedir output is a normal directory of DLLs like any installed app.
#
# Build (from repo root, on Windows, inside the venv):
#   pyinstaller packaging/windows/exfiltrap.spec --noconfirm
#
# Sign the outputs afterwards (see packaging/windows/build_windows.bat) —
# Authenticode signing is the single biggest factor in Defender
# SmartScreen heuristics for software that touches raw sockets and the
# firewall.

import sys
from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent.parent  # repo root

a = Analysis(
    [str(ROOT / "exfiltrap" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        # Templates + benign corpus ship inside the package data.
        (str(ROOT / "exfiltrap" / "dashboard" / "templates"),
         "exfiltrap/dashboard/templates"),
        (str(ROOT / "data" / "tranco_top_1m_sample.csv"), "data"),
        (str(ROOT / "data" / "model" / "rf_model.joblib"), "data/model"),
        (str(ROOT / "eval" / "run_evaluation.py"), "eval"),
        (str(ROOT / "tools" / "attacker_client.py"), "tools"),
        (str(ROOT / "tools" / "benign_traffic_gen.py"), "tools"),
    ],
    hiddenimports=[
        "sklearn", "scipy", "joblib",
        "exfiltrap.service",
        "exfiltrap.winservice",
        "exfiltrap.dashboard.app",
        "win32serviceutil",
        "servicemanager",
        "win32event",
        "win32service",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="exfiltrap",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX compression is another classic AV heuristic trigger
    console=True,  # the service path needs a console subsystem
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="exfiltrap",
)
