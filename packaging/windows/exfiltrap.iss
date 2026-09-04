; ExfilTrap Windows installer (Inno Setup 6).
;
; One elevated moment (the UAC prompt of this installer), then everything
; runs like a normal application:
;   - installs to Program Files
;   - silently installs the Npcap redistributable if absent (scapy's
;     capture driver on Windows; same driver Wireshark uses)
;   - writes %PROGRAMDATA%\ExfilTrap\service.ini
;   - registers and STARTS the ExfilTrapSvc Windows Service (auto-start)
;   - Start Menu shortcut launches the unprivileged dashboard
;
; The Npcap installer must be placed next to this script as npcap.exe
; before compiling (download the "Installer for Windows" from
; https://npcap.com/#download — redistribution requires their
; OEM/special installer license; for a college deployment the normal
; free installer also works interactively).

#define MyAppName "ExfilTrap"
#define MyAppVersion "1.0.0"
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
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Fill these in when you have a certificate:
; SignTool=mysigntool

[Files]
Source: "..\..\dist\exfiltrap\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
; Place the Npcap redist next to this script as npcap.exe:
Source: "npcap.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall skipifsourcedoesntexist external

[Dirs]
Name: "{commonappdata}\ExfilTrap"; Permissions: users-modify

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
; Unprivileged dashboard shortcut target (just opens the local API UI).
Filename: "{app}\{#MyAppExeName}"; Parameters: "dashboard"; Flags: nowait postinstall skipifsilent

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
