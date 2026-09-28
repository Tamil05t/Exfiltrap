; ExfilTrap Windows installer (Inno Setup 6).
;
; One elevated moment (the UAC prompt of this installer), then everything
; runs like a normal application:
;   - installs to Program Files
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
; The Npcap installer must be placed next to this script as npcap.exe
; before compiling (download the "Installer for Windows" from
; https://npcap.com/#download — redistribution requires their
; OEM/special installer license; for a college deployment the normal
; free installer also works interactively).

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

; Was the shell actually compiled? This has to be answered at COMPILE time.
;
; A runtime check cannot work here. Windows paths are case-insensitive, so
;     FileExists(ExpandConstant('{app}\ExFilTrap.exe'))
; also matches the engine's `exfiltrap.exe`, which lands in the very same
; directory. The old ShellBuilt() therefore always answered TRUE: every
; shortcut, every App Paths key and the postinstall launch pointed at
; "{app}\ExFilTrap.exe" — that is, at the ENGINE — and ran it with no
; arguments. The engine's no-argument behaviour is to print its CLI help and
; exit, so clicking the Start Menu entry flashed a console window and
; vanished. That is the whole bug.
#if FileExists(AddBackslash(SourcePath) + ShellRel)
  #define HaveShell
#else
  #pragma warning "ExFilTrap: Tauri shell not built (desktop\src-tauri\target\release\exfiltrap-desktop.exe missing) - producing an ENGINE-ONLY installer; the Start Menu entry will run `exfiltrap dashboard`."
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
; The Tauri desktop shell, shipped as ExFilTrap.exe. Guarded by the
; compile-time HaveShell check above — no skipifsourcedoesntexist, so a
; missing shell can never silently produce a half-broken install again.
#ifdef HaveShell
Source: "{#ShellRel}"; DestDir: "{app}"; DestName: "ExFilTrap.exe"; \
    Flags: ignoreversion
#endif
; Place the Npcap redist next to this script as npcap.exe:
Source: "npcap.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall skipifsourcedoesntexist external

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
Name: "{group}\{#MyAppName}"; Filename: "{app}\ExFilTrap.exe"; \
    Comment: "Open the ExFilTrap detection console"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\ExFilTrap.exe"; \
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
    ValueType: string; ValueName: ""; ValueData: "{app}\ExFilTrap.exe"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ExFilTrap.exe"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\ExFilTrap.exe"; \
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
; Npcap silent install (skip WinPcap compatibility mode) if no driver yet.
Filename: "{tmp}\npcap.exe"; Parameters: "/S /winpcap_mode=no"; \
    Flags: skipifdoesntexist runhidden; Check: NpcapMissing
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
Filename: "{app}\ExFilTrap.exe"; Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser
#else
Filename: "{app}\{#MyAppExeName}"; Parameters: "dashboard"; \
    Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser
#endif

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
