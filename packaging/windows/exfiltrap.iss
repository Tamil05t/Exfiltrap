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
; The Tauri desktop shell — the actual WINDOW the user launches, the Windows
; equivalent of the Linux AppImage's `ex-fil-trap`. It polls the service on
; :5050 and navigates to the dashboard itself, so the Start Menu entry opens
; an application window rather than a browser tab. Built by
; build_windows.bat (cargo build --release in desktop/src-tauri).
Source: "..\..\desktop\src-tauri\target\release\exfiltrap-desktop.exe"; \
    DestDir: "{app}"; DestName: "ExFilTrap.exe"; \
    Flags: ignoreversion skipifsourcedoesntexist
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
; The shell polls the service on :5050 and navigates itself. When no shell
; was compiled, the entry falls back to the dashboard command, which opens
; the service console in the default browser.
;
; Inno creates NO group folder unless an [Icons] section exists, so the
; documented "Start Menu -> ExFilTrap" step used to lead nowhere at all —
; the only thing that ever ran was the [Run] postinstall entry below.
Name: "{group}\{#MyAppName}"; Filename: "{app}\ExFilTrap.exe"; \
    Comment: "Open the ExFilTrap detection console"; Check: ShellBuilt
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "dashboard"; Comment: "Open the ExFilTrap detection console"; \
    Check: ShellMissing
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\ExFilTrap.exe"; \
    Tasks: desktopicon; Check: ShellBuilt
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "dashboard"; Tasks: desktopicon; Check: ShellMissing

[Registry]
; App Paths is the mechanism that lets Win+R resolve a bare name to the
; installed exe — the same one `chrome` uses. Both spellings are registered
; so typing either `exfiltrap` or `ExFilTrap` opens the desktop app.
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ExFilTrap.exe"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\ExFilTrap.exe"; \
    Flags: uninsdeletekey; Check: ShellBuilt
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ExFilTrap.exe"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey; Check: ShellBuilt
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\ExFilTrap.exe"; \
    Flags: uninsdeletekey; Check: ShellBuilt
Root: HKLM; \
    Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"; \
    Flags: uninsdeletekey; Check: ShellBuilt

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
; and opens THAT console in the browser, so the installer can no longer
; strand the user on a second, data-less UI on :5000. runasoriginaluser
; keeps the window in the user's own session, not the elevated installer's.
;
; Both entries share one Description so the Finished page shows a SINGLE
; "Launch ExFilTrap" check box; their Checks make exactly one of them run.
Filename: "{app}\ExFilTrap.exe"; Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser; Check: ShellBuilt
Filename: "{app}\{#MyAppExeName}"; Parameters: "dashboard"; \
    Description: "Launch ExFilTrap"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser; Check: ShellMissing

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

// Was the Tauri desktop shell shipped? [Files] copies it with
// skipifsourcedoesntexist, so this is the single source of truth for every
// conditional shortcut / registry entry / launch step. [Files] is processed
// before [Icons], [Registry] and [Run], so the answer is already final.
function ShellBuilt(): Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\ExFilTrap.exe'));
end;

function ShellMissing(): Boolean;
begin
  Result := not ShellBuilt();
end;

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
