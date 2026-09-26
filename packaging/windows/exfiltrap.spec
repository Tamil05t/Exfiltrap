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
        # private modules referenced by the pickled RandomForest
        "sklearn.ensemble", "sklearn.ensemble._forest",
        "sklearn.tree", "sklearn.tree._classes", "sklearn.tree._utils",
        "sklearn.utils._weight_vector", "sklearn.utils._seq_dataset",
        # scipy lazy submodules the pickle import graph touches at model-load
        # time. These are NOT discoverable statically, so PyInstaller drops
        # them and the frozen engine dies on load_rf_model() with
        # "dependencies are missing". Kept identical to the Linux spec.
        "scipy._external.array_api_compat.numpy",
        "scipy._external.array_api_compat.numpy.fft",
        "scipy.fft",
        "scipy.integrate",
        "scipy.linalg",
        "scipy.sparse",
        "exfiltrap.service",
        "exfiltrap.winservice",
        "exfiltrap.dashboard.app",
        # pywin32 service stack. pywintypes and win32api are imported
        # indirectly (dynamically by name) inside win32serviceutil and
        # servicemanager, so PyInstaller's static analysis misses them and
        # the frozen `winservice install` dies with
        # "No module named 'pywintypes'".
        "win32api",
        "win32serviceutil",
        "servicemanager",
        "win32event",
        "win32service",
        "pywintypes",
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
