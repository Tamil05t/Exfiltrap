# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the LINUX SERVICE build (standalone root binary).
#
# Produces dist/exfiltrap/ — a self-contained `exfiltrap` executable that
# runs the detection service without any Python installation:
#     sudo ./exfiltrap service --iface wlan0
#
# Build (CI or locally, from repo root):
#   pyinstaller packaging/linux/exfiltrap-linux.spec --noconfirm

import sys
from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent.parent  # repo root

a = Analysis(
    [str(ROOT / "exfiltrap" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
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
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pywin32"],
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
    upx=False,
    console=True,
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
