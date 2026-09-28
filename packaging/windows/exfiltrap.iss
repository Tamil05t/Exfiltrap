; ExfilTrap Windows installer (Inno Setup 6).
;
; One elevated moment (the UAC prompt of this installer), then everything
; runs like a normal application:
;   - installs to Program Files (x86)\ExfilTrap — the installer is 32-bit, so
;     {autopf} resolves to the x86 tree, not "C:\Program Files"
;   - silently installs the Npcap redistributable if absent (scapy's
;     capture driver on Windows; same driver Wireshark uses)
;   - writes %PROGRAMDATA%\ExfilTrap\service.ini
;   - registers and STARTS the ExfilTrapSvc Windows Service (auto-start)
;   - Start Menu + desktop shortcuts, and an App Paths entry so a bare
;     `exfiltrap` resolves from Win+R
;
; The evidence database lives in %PROGRAMDATA%\ExfilTrap (see
; config._default_db_path), NOT under Program Files: WAL journaling creates
; -wal/-shm siblings next to the file, and Program Files is read-only for
; the unprivileged console.
;
; Npcap is the packet-capture driver scapy needs on Windows (the same driver
; Wireshark uses) and the engine cannot see a single DNS query without it.
;
; TWO separate facts, both learned the hard way:
;
; 1. The FREE Npcap installer REFUSES to install silently. Running it with
;    "/S" pops a dialog reading "Silent installation is only supported in
;    Npcap OEM. Please run the installer normally." and then does nothing.
;    Only the licensed Npcap OEM build supports unattended install, so this
;    script must never present the driver as something setup quietly takes
;    care of — it either ships an OEM build (drop it here as npcap.exe) or it
;    tells the user to install Npcap themselves.
; 2. It is NOT bundled by default: redistributing the free installer
;    requires Npcap's OEM/special licence. Drop an OEM (or otherwise
;    redistributable) npcap.exe next to this script to bundle it — see
;    HaveNpcap below.
;
; What the user sees when the driver is missing is a console that opens
; normally and then sits on "Capture degraded" forever, with no explanation
; anywhere: the service has no console, so the engine's own log lines went
; nowhere. Running the app as Administrator does not help — the driver is
; missing, so there is nothing to elevate. Hence the message box at the end
; of setup (CurStepChanged) and the honest banner in the console.

#define MyAppName "ExfilTrap"
; Version is overridable from the command line (CI passes the pushed tag):
;   iscc -DMyAppVersion=1.4.0 packaging\windows\exfiltrap.iss
; The #ifndef guard is REQUIRED — ISCC -D emulates `#define public`, and a
; bare #define here would collide with it ("Symbol already defined"),
; failing the compile. Without the guard CI could never override the
; version and every release installer silently shipped this default.
#ifndef MyAppVersion
  #define MyAppVersion "1.4.0"
#endif
#define MyAppPublisher "ExfilTrap Project"
#define MyAppExeName "exfiltrap.exe"

; The Tauri desktop shell — the actual application WINDOW, the Windows
; equivalent of the Linux AppImage's `ex-fil-trap`. Relative to this script,
; the same base the [Files] Source entries below already use.
#define ShellRel "..\..\desktop\src-tauri\target\release\exfiltrap-desktop.exe"

; Installed name of the shell. It MUST NOT be "ExFilTrap.exe": NTFS is
; case-insensitive, so that is the SAME file as the engine's exfiltrap.exe in
; the same directory, and installing the shell would silently OVERWRITE the
; engine with it. (Which also destroys the service, whose ImagePath is that
; exact path.) A distinct name is the only safe answer — the Start Menu entry
; still reads "ExFilTrap", and the App Paths key is still `exfiltrap`.
#define ShellExeName "ExFilTrap-Desktop.exe"

; Was the shell actually compiled? This has to be answered at COMPILE time.
;
; A runtime check cannot work here either. Windows paths are case-insensitive,
; so
;     FileExists(ExpandConstant('{app}\ExFilTrap.exe'))
; also matches the engine's `exfiltrap.exe`. The old ShellBuilt() therefore
; always answered TRUE: every shortcut, every App Paths key and the postinstall
; launch pointed at the ENGINE and ran it with no arguments. The engine's
; no-argument behaviour is to print its CLI help and exit, so clicking the
; Start Menu entry flashed a console window and vanished. That is the whole bug.
#if FileExists(AddBackslash(SourcePath) + ShellRel)
  #define HaveShell
#else
  #pragma warning "ExFilTrap: Tauri shell not built (desktop\src-tauri\target\release\exfiltrap-desktop.exe missing) - producing an ENGINE-ONLY installer; the Start Menu entry will run `exfiltrap dashboard`."
#endif

; Is a redistributable Npcap installer sitting next to this script?
;
; Also a COMPILE-time question, for exactly the reason HaveShell is: the
; [Files]/[Run] entries for it carried skipifsourcedoesntexist and
; skipifdoesntexist, so with no npcap.exe staged the whole driver install was
; a silent no-op. Setup reported success, the product shipped without the one
; driver it cannot work without, and the user was left staring at "Capture
; degraded" with nothing anywhere to explain it.
#define NpcapRel "npcap.exe"
#if FileExists(AddBackslash(SourcePath) + NpcapRel)
  #define HaveNpcap
#endif

[Setup]
AppId={{77C5661C-BBB1-4A21-902F-6EF86D4E7F32}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=admin
OutputBaseFilename=ExfilTrap-Setup
; Write the setup .exe to <repo>\dist, NOT next to this script.
; Without OutputDir, Inno Setup defaults to the directory containing the
; script, so the installer landed in packaging\windows\ while everything else
; in the repo expects dist\ExfilTrap-Setup.exe:
;   - build_windows.bat signs and prints dist\ExfilTrap-Setup.exe
;   - CI asserts dist/ExfilTrap-Setup.exe exists after ISCC
;   - the upload-artifact step globs dist/*.exe
; The old CI step hid this by ending in `|| echo "iscc skipped (optional)"`,
; so the installer was silently never produced into dist/ and never uploaded.
; Relative paths here resolve against the script's own directory (same base
; the [Files] Source below already relies on), so ..\..\dist is the repo dist.
OutputDir=..\..\dist
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Fill these in when you have a certificate:
; SignTool=mysigntool

[Files]
Source: "..\..\dist\exfiltrap\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
; The Tauri desktop shell, shipped as {#ShellExeName}. Guarded by the
; compile-time HaveShell check above — no skipifsourcedoesntexist, so a
; missing shell can never silently produce a half-broken install again.
#ifdef HaveShell
Source: "{#ShellRel}"; DestDir: "{app}"; DestName: "{#ShellExeName}"; \
    Flags: ignoreversion
#endif
; A redistributable Npcap installer, when the maintainer supplied one. It is
; embedded in setup rather than read from disk at install time (no `external`
; flag): only compiled in when it actually exists, so setup can never again
; claim to install a driver it does not carry.
#ifdef HaveNpcap
Source: "{#NpcapRel}"; DestDir: "{tmp}"; DestName: "npcap.exe"; \
    Flags: deleteafterinstall ignoreversion
#endif

[Dirs]
Name: "{commonappdata}\ExfilTrap"; Permissions: users-modify

[Tasks]
; The Start Menu entry is not optional; the desktop icon is opt-out, like
; every other installer.
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Icons]
; Launch the DESKTOP SHELL so the Start Menu opens a real application
; window — the same experience the Linux AppImage gives via ex-fil-trap.
; The shell polls the service on :5050 and navigates itself.
;
; When no shell was compiled the entry falls back to `exfiltrap dashboard`,
; which probes the service on :5050 and opens that console. Both branches
; use the SAME icon Name, so re-running the installer after building the
; shell replaces the entry rather than adding a second one.
;
; Inno creates NO group folder unless an [Icons] section exists, so the
; documented "Start Menu -> ExFilTrap" step used to lead nowhere at all —
; the only thing that ever ran was the [Run] postinstall entry below.
#ifdef HaveShell
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#ShellExeName}"; \
    Comment: "Open the ExFilTrap detection console"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#ShellExeName}"; \
    Tasks: desktopicon
#else
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "dashboard"; Comment: "Open the ExFilTrap detection console"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "dashboard"; Tasks: desktopicon
#endif
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Registry]
; App Paths is the mechanism that lets Win+R resolve a bare name to the
; installed exe — the same one `chrome` uses. Both spellings are registered
; so typing either `exfiltrap` or `ExFilTrap` opens the desktop app.
#ifdef HaveShell
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ExFilTrap.exe"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#ShellExeName}"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ExFilTrap.exe"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#ShellExeName}"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey
#else
; Engine-only build. App Paths carries no arguments, and a bare `exfiltrap`
; now opens the console by itself (__main__ falls through to the dashboard
; when it is not started by the SCM), so pointing at the engine is enough.
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey
#endif

[Ini]
Filename: "{commonappdata}\ExfilTrap\service.ini"; Section: "service"; \
    Key: "iface"; String: "{code:GetIface}"
Filename: "{commonappdata}\ExfilTrap\service.ini"; Section: "service"; \
    Key: "mitigation"; String: "log"

[Run]
; Install the bundled capture driver if the machine has none.
;
; "/S" is only honoured by the licensed Npcap OEM build — the free installer
; answers it with "Silent installation is only supported in Npcap OEM" and
; exits without installing anything. That is why bundling is opt-in and why
; the message box in CurStepChanged exists for the default (unbundled) case.
#ifdef HaveNpcap
Filename: "{tmp}\npcap.exe"; Parameters: "/S /winpcap_mode=no"; \
    Flags: skipifdoesntexist runhidden; Check: NpcapMissing
#endif
; Register + start the detection service (SYSTEM context, auto-start).
Filename: "{app}\{#MyAppExeName}"; Parameters: "winservice install"; \
    Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "winservice start"; \
    Flags: runhidden; AfterInstall: WaitForService
; Open the product at the end of setup. The desktop shell is preferred: it
; is the real application window (as on Linux). Without a compiled shell
; the `dashboard` command is used instead — it probes the service on :5050
; and opens THAT console, so the installer can no longer strand the user on
; a second, data-less UI on :5000. runasoriginaluser keeps the window in
; the user's own session, not the elevated installer's.
;
; Exactly one of the two branches is compiled in, so the Finished page shows
; a single "Launch ExFilTrap" check box.
#ifdef HaveShell
Filename: "{app}\{#ShellExeName}"; Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser
#else
Filename: "{app}\{#MyAppExeName}"; Parameters: "dashboard"; \
    Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser
#endif
; No capture driver and none bundled: leave the fix one click away. The Check
; is evaluated while the Finished page is built — i.e. AFTER the [Run]
; entries above — so it is still correct when a bundled installer just ran
; and failed.
Filename: "https://npcap.com/#download"; \
    Description: "Download Npcap (required before capture can work)"; \
    Flags: shellexec nowait postinstall skipifsilent; Check: NpcapMissing

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "winservice stop"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{app}\{#MyAppExeName}"; Parameters: "winservice remove"; Flags: runhidden; RunOnceId: "RemoveSvc"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\ExfilTrap"

[Code]
function NpcapMissing(): Boolean;
begin
  Result := not DirExists(ExpandConstant('{sys}') + '\Npcap');
end;

// Say the capture driver out loud.
//
// Setup used to complete "successfully" on a machine with no Npcap, and the
// only symptom was a console that opened and then sat on "Capture degraded"
// forever — no error, no hint, nothing in any log. The engine cannot see a
// single DNS query without this driver, so a setup that stays quiet about its
// absence hands the user a product that looks broken.
//
// ssDone, not ssPostInstall: the [Run] section (including a bundled Npcap
// installer) has already been processed by then, so NpcapMissing() reports
// the truth rather than "not installed yet".
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssDone) and (not WizardSilent) and NpcapMissing() then
    MsgBox(
      'ExFilTrap is installed, but its packet-capture driver (Npcap) is not.'
      + #13#10 + #13#10
      + 'Npcap is the driver Wireshark also uses. Without it the detection '
      + 'engine cannot see any DNS traffic, so the console will open and '
      + 'then stay on "Capture degraded" — and running ExFilTrap as '
      + 'Administrator will not change that, because the driver itself is '
      + 'what is missing.' + #13#10 + #13#10
      + 'Download and install the free Npcap installer from:'
      + #13#10 + '    https://npcap.com/#download' + #13#10 + #13#10
      + 'Then restart the ExFilTrap service, or simply reboot.',
      mbInformation, MB_OK);
end;

// There is deliberately no ShellBuilt()/ShellMissing() here any more.
// "Was the shell built?" is a compile-time question (see HaveShell at the
// top): a runtime FileExists('{app}\ExFilTrap.exe') is case-insensitive on
// Windows and therefore also matches the engine's exfiltrap.exe, so it
// always answered TRUE and every shortcut pointed at the console engine.

function GetIface(Param: String): String;
var
  Names: TStringList;
  I: Integer;
begin
  // First non-loopback interface name; users can edit service.ini later.
  Result := '';
  Names := TStringList.Create;
  try
    // Simplest robust source: route print's first 0.0.0.0 interface index
    // is overkill here; use the default from scapy at first run instead.
    Result := 'auto';
  finally
    Names.Free;
  end;
end;

procedure WaitForService;
var
  I: Integer;
begin
  for I := 1 to 10 do
  begin
    if RegValueExists(HKLM, 'SYSTEM\CurrentControlSet\Services\ExfilTrapSvc', 'ImagePath') then
      Break;
    Sleep(500);
  end;
end;
