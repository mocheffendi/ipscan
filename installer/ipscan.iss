; Inno Setup 6 script for ipscan (setup.exe).
; Version can be overridden with: ISCC.exe /dAppVersion=0.3.0 ipscan.iss
#ifndef AppVersion
  #define AppVersion "0.3.0"
#endif

#define MyAppName "ipscan"
#define MyAppPublisher "meffendi"
#define MyAppExeName "ipscan.exe"
#define MyAppId "{{578ECF06-779A-447E-A2F2-2826C52850F8}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppVerName={#MyAppName} {#AppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/meffendi/ipscan
AppSupportURL=https://github.com/meffendi/ipscan/issues
AppUpdatesURL=https://github.com/meffendi/ipscan/releases
DefaultDirName={autopf}\ipscan
DefaultGroupName=ipscan
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=out
OutputBaseFilename=ipscan-{#AppVersion}-setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
