; Gecko Installer - Professional Setup Configuration
; Creates a complete installation package for Gecko encrypted vault utility

#define MyAppName "Gecko"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "kpawnd"
#define MyAppExeName "gecko.exe"
#define MyAppDescription "Encrypted USB Vault - Secure File Storage with AES-256-GCM"
#define MyAppURL "https://github.com/kpawnd/gecko"

[Setup]
AppId={{8F3B2A1C-5D4E-6F7A-8B9C-0D1E2F3A4B5C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppComments={#MyAppDescription}
AppCopyright=Copyright © 2025 {#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=no
LicenseFile=..\LICENSE
OutputDir=output
OutputBaseFilename=gecko-{#MyAppVersion}-setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=yes
WizardSizePercent=120
PrivilegesRequired=admin
ChangesEnvironment=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppDescription}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCopyright=Copyright © 2025 {#MyAppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add Gecko to system PATH (recommended)"; GroupDescription: "Additional options:"; Flags: checkedonce
Name: "createdesktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional options:"; Flags: unchecked
Name: "createquicklaunch"; Description: "Create a quick launch icon"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
Source: "..\build\bin\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion; DestName: "README.txt"
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion; DestName: "LICENSE.txt"
Source: "..\docs\documentation.html"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{cmd}"; Parameters: "/k title Gecko && gecko help"; IconFileName: "{app}\{#MyAppExeName}"; Comment: "Open Gecko in command prompt"; WorkingDir: "{commondesktop}"
Name: "{group}\{#MyAppName} Help"; Filename: "{cmd}"; Parameters: "/k gecko help"; Comment: "Display Gecko help information"; WorkingDir: "{commondesktop}"
Name: "{group}\Documentation"; Filename: "{app}\docs\documentation.html"; Comment: "View Gecko documentation"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Comment: "Uninstall {#MyAppName}"
Name: "{commondesktop}\{#MyAppName} Command Prompt"; Filename: "{cmd}"; Parameters: "/k title Gecko && gecko help"; IconFileName: "{app}\{#MyAppExeName}"; Comment: "Gecko command line"; WorkingDir: "{commondesktop}"; Tasks: createdesktopicon

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  ParamExpanded: string;
begin
  ParamExpanded := ExpandConstant(Param);
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + UpperCase(ParamExpanded) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
  if Result = True then
    Result := Pos(';' + UpperCase(ParamExpanded) + '\;', ';' + UpperCase(OrigPath) + ';') = 0;
end;

procedure RemovePath();
var
  Path: string;
  AppDir: string;
  Index: Integer;
begin
  AppDir := ExpandConstant('{app}');
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', Path) then
  begin
    Index := Pos(';' + AppDir, Path);
    if Index > 0 then
    begin
      Delete(Path, Index, Length(';' + AppDir));
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Path', Path);
    end
    else begin
      Index := Pos(AppDir + ';', Path);
      if Index > 0 then
      begin
        Delete(Path, Index, Length(AppDir + ';'));
        RegWriteStringValue(HKEY_LOCAL_MACHINE,
          'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
          'Path', Path);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemovePath();
  end;
end;

[Messages]
BeveledLabel=Gecko {#MyAppVersion}
WelcomeLabel1=Welcome to the Gecko Setup
WelcomeLabel2=This will install [name/ver] on your computer.%n%n[name] is an encrypted USB vault utility that provides secure file storage with military-grade AES-256-GCM encryption and PBKDF2 key derivation.%n%nFeatures:%n• 256-bit AES-GCM encryption%n• Secure USB vault creation%n• Keyfile support%n• Vault merging capabilities%n• Emergency wipe function%n%nIt is recommended that you close all other applications before continuing.
FinishedLabel=Setup has completed the installation of [name/ver] on your computer.%n%nTo get started:%n1. Open a new command prompt window (CMD or PowerShell)%n2. Type: gecko help%n3. View documentation for usage examples%n%nThank you for using Gecko!
