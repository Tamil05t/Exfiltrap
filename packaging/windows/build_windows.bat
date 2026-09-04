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

echo === building installer (requires Inno Setup 6: https://jrsoftware.org/isinfo.php)
where iscc >nul 2>nul
if %errorlevel%==0 (
  iscc packaging\windows\exfiltrap.iss
  if defined SIGN_CMD %SIGN_CMD% dist\ExfilTrap-Setup.exe
  echo Installer: dist\ExfilTrap-Setup.exe
) else (
  echo Inno Setup (iscc) not found - run the service directly from dist\exfiltrap:
  echo   dist\exfiltrap\exfiltrap.exe service --demo
)

endlocal
