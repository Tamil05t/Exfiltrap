@echo off
REM ExfilTrap Windows build script.
REM Run INSIDE the repo root on a Windows machine with Python 3.11+.
REM
REM Produces:
REM   dist\exfiltrap\            PyInstaller --onedir output (service+CLI+dashboard)
REM   dist\ExfilTrap-Setup.exe   Inno Setup installer (if Inno Setup found)
REM
REM Antivirus posture (read this before changing anything):
REM   * --onedir, no UPX: no self-extraction, no packing heuristics.
REM   * Authenticode-sign EVERY exe/dll before shipping (fill in SIGN_CERT
REM     below). Unsigned network+firewall software WILL attract SmartScreen.
REM   * The installer registers a normal Windows Service and writes logs to
REM     %PROGRAMDATA%\ExfilTrap — transparent, documented behavior.

setlocal enabledelayedexpansion
cd /d "%~dp0..\.."

REM === 0. signing configuration (fill in when you have a certificate) ===
set SIGN_CERT=
set SIGN_TSA=http://timestamp.digicert.com
if defined SIGN_CERT set SIGN_CMD=signtool sign /fd SHA256 /tr %SIGN_TSA% /f "%SIGN_CERT%"

REM === version (must match desktop/src-tauri/tauri.conf.json) ===
if not defined APPVER set APPVER=1.4.0

if not exist .venv (python -m venv .venv)
call .venv\Scripts\activate.bat

pip install -r requirements.txt pyinstaller pywin32
if not exist data\model\rf_model.joblib python tools\train_classifier.py

echo === building exfiltrap.exe (onedir)
pyinstaller packaging\windows\exfiltrap.spec --noconfirm --distpath dist --workpath build

if defined SIGN_CMD (
  echo === signing binaries
  for %%F in (dist\exfiltrap\exfiltrap.exe) do %SIGN_CMD% %%F
)

echo === building the desktop shell (Tauri app window)
where cargo >nul 2>nul
if %errorlevel%==0 (
  REM tauri-build VALIDATES bundle.resources at COMPILE time, so the engine
  REM must be staged into resources\ before cargo runs - exactly what the
  REM Linux AppImage script does. On Windows the shell does not launch the
  REM engine (the installed Windows Service does), but the path must exist.
  if exist desktop\src-tauri\resources\exfiltrap-engine rmdir /s /q desktop\src-tauri\resources\exfiltrap-engine
  if not exist desktop\src-tauri\resources mkdir desktop\src-tauri\resources
  xcopy /e /i /q /y dist\exfiltrap desktop\src-tauri\resources\exfiltrap-engine >nul
  pushd desktop\src-tauri
  cargo build --release
  if defined SIGN_CMD for %%F in (target\release\exfiltrap-desktop.exe) do %SIGN_CMD% %%F
  popd
  if exist desktop\src-tauri\target\release\exfiltrap-desktop.exe (
    echo Shell: desktop\src-tauri\target\release\exfiltrap-desktop.exe
  ) else (
    echo WARNING: the shell build produced no exe - the installer will fall
    echo          back to opening the dashboard in a browser.
  )
) else (
  echo cargo not found - SKIPPING the desktop shell.
  echo   Install Rust ^(https://rustup.rs^) and re-run to get the app window.
  echo   The installer still builds, but its Start Menu entry will open the
  echo   console in a browser instead of a real application window.
)

echo === building installer (requires Inno Setup 6: https://jrsoftware.org/isinfo.php)
where iscc >nul 2>nul
if %errorlevel%==0 (
  iscc /DMyAppVersion=%APPVER% packaging\windows\exfiltrap.iss
  if defined SIGN_CMD %SIGN_CMD% dist\ExfilTrap-Setup.exe
  echo Installer: dist\ExfilTrap-Setup.exe
) else (
  echo Inno Setup (iscc) not found - run the service directly from dist\exfiltrap:
  echo   dist\exfiltrap\exfiltrap.exe service --iface "Ethernet"
  echo   dist\exfiltrap\exfiltrap.exe dashboard        ^(standalone UI^)
  echo   dist\exfiltrap\exfiltrap.exe winservice install  ^(elevated, then: start^)
)

endlocal
