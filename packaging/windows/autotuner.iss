; Inno Setup script: iscc /DAppVersion=1.0.0 /DPublishDir=... /DOutDir=... autotuner.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6C1E5D0B-6A4E-4B53-9B8F-2A1D2B7E9C41}
AppName=Zapret2 AutoTuner
AppVersion={#AppVersion}
AppPublisher=Zapret2_AutoTuner contributors
AppPublisherURL=https://github.com/avatarDD/Zapret2_AutoTuner
DefaultDirName={autopf}\Zapret2 AutoTuner
DefaultGroupName=Zapret2 AutoTuner
OutputDir={#OutDir}
OutputBaseFilename=ZapretAutoTuner-{#AppVersion}-win-x64-setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\ZapretAutoTuner.exe

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Zapret2 AutoTuner"; Filename: "{app}\ZapretAutoTuner.exe"
Name: "{group}\{cm:UninstallProgram,Zapret2 AutoTuner}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Zapret2 AutoTuner"; Filename: "{app}\ZapretAutoTuner.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ZapretAutoTuner.exe"; Description: "{cm:LaunchProgram,Zapret2 AutoTuner}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; the Agent removes its WinDivert filters on exit; make sure no engine of ours is left behind. Only processes started
; from {app}: a winws2.exe of another zapret install keeps running.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""$d = '{app}\'; Get-Process -Name winws2,ztuner-agent -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -and $_.Path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase) }} | Stop-Process -Force"""; Flags: runhidden; RunOnceId: "KillOurs"
