; SafeBox Kurulum Scripti - Garantili çalışan, Inno Setup 6.4.3 uyumlu

[Setup]
AppName=SafeBox
AppVersion=1.0
DefaultDirName={userappdata}\SafeBox
DefaultGroupName=SafeBox
OutputDir=Output
OutputBaseFilename=SafeBoxSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=none
PrivilegesRequiredOverridesAllowed=dialog
DisableWelcomePage=no

[Files]
Source: "D:\SafeBox\dist\SafeBox\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userdesktop}\SafeBox"; Filename: "{app}\SafeBox.exe"; Tasks: desktopicon
Name: "{group}\SafeBox"; Filename: "{app}\SafeBox.exe"

[Tasks]
Name: desktopicon; Description: "Masaüstü kısayolu oluştur"; GroupDescription: "Ek görevler"; Flags: unchecked

[Run]
Filename: "{app}\SafeBox.exe"; Description: "SafeBox'u Başlat"; Flags: nowait postinstall skipifsilent
