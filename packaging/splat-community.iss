; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#ifndef StageDir
  #error StageDir must be the verified community staging directory.
#endif
#ifndef OutputDir
  #error OutputDir must be an explicit build output directory.
#endif
#ifndef AppVersion
  #error AppVersion must be supplied by build-community-installer.ps1.
#endif
#define LicensePreamble "AGPL-3.0; separate commercial licensing available from Platten Industries. See COMMERCIAL.md."

[Setup]
AppId={{FE65C0A1-120A-4DFD-B251-CF9533C0BEE0}
AppName=SPLAT Community Test Candidate
AppVersion={#AppVersion}
AppPublisher=Platten Industries
AppPublisherURL=https://github.com/Spplatten/SPLAT
AppContact=Sean Patrick Platten, Platten Industries, 27 Pledger Pkwy, LaFayette, GA
AppSupportPhone=706-239-7969
AppCopyright=Copyright (C) 2026 Platten Industries. AGPL-3.0 / separate commercial licensing.
AppComments=Experimental test candidate. {#LicensePreamble}
VersionInfoCompany=Platten Industries
; Keep both grants inside the bootstrap loader's limited version-resource field.
VersionInfoDescription=SPLAT: AGPL-3.0 / Platten Industries commercial license
VersionInfoVersion={#AppVersion}
VersionInfoProductTextVersion={#AppVersion} experimental
DefaultDirName={autopf}\Platten Industries\SPLAT Community
DefaultGroupName=SPLAT Community Test
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
LicenseFile={#StageDir}\INSTALLER-LICENSE.txt
InfoBeforeFile={#StageDir}\docs\COMMUNITY-TESTING.md
OutputDir={#OutputDir}
OutputBaseFilename=SPLAT-Community-{#AppVersion}-Setup
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
; Brand artwork. The icon is the same .ico the console and the MSIX tiles use, and the wizard bitmaps
; are generated beside it by brand/build-brand-assets.py at every size Inno scales between, so a
; 150% or 200% display gets a bitmap rendered at that size rather than a stretched one.
SetupIconFile=..\src\MissionController.UI\Assets\splat.ico
WizardImageFile=installer-brand\wizard-large-*.bmp
WizardSmallImageFile=installer-brand\wizard-small-*.bmp
; Inno 6 skips the welcome page unless told otherwise, which would drop the panel that names the licensor.
DisableWelcomePage=no
UninstallDisplayIcon={app}\App\MissionController.UI.exe
CloseApplications=no
RestartApplications=no

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Excludes: "Linux\rootfs.tar.xz"; Flags: ignoreversion recursesubdirs createallsubdirs
#if FileExists(StageDir + "\Linux\rootfs.tar.xz")
Source: "{#StageDir}\Linux\rootfs.tar.xz"; DestDir: "{app}\Linux"; Flags: ignoreversion nocompression
#endif

[Messages]
; The welcome and completion panels carry the licensor's identity, so the person who accepted the
; grant on the license page has already seen who is granting it and how to reach them.
WelcomeLabel1=Welcome to SPLAT
WelcomeLabel2=This installs [name/ver] on your computer.%n%nSPLAT is published by Platten Industries under the GNU Affero General Public License v3.0, with separate commercial licensing available.%n%nLicensor: Sean Patrick Platten, Platten Industries%n27 Pledger Pkwy, LaFayette, GA%n706-239-7969, plattenindustries@gmail.com%n%nThe next pages show the full license and the community testing limits. Read both before continuing.
FinishedHeadingLabel=SPLAT is installed
FinishedLabel=Setup has finished installing the SPLAT Community Test Candidate.%n%nThis is an experimental test candidate licensed under AGPL-3.0 by Platten Industries. It makes no warranty of security, and installation does not establish the caller-identity boundary described in the testing notes.%n%nQuestions, defects and licensing: Sean Patrick Platten, Platten Industries, 27 Pledger Pkwy, LaFayette, GA, 706-239-7969, plattenindustries@gmail.com.
FinishedLabelNoIcons=Setup has finished installing the SPLAT Community Test Candidate.%n%nThis is an experimental test candidate licensed under AGPL-3.0 by Platten Industries. It makes no warranty of security, and installation does not establish the caller-identity boundary described in the testing notes.%n%nQuestions, defects and licensing: Sean Patrick Platten, Platten Industries, 27 Pledger Pkwy, LaFayette, GA, 706-239-7969, plattenindustries@gmail.com.

[Icons]
Name: "{group}\SPLAT Community Test"; Filename: "{app}\App\MissionController.UI.exe"; WorkingDir: "{app}\App"
Name: "{group}\Community testing instructions"; Filename: "{app}\docs\COMMUNITY-TESTING.md"
Name: "{group}\Uninstall SPLAT Community Test"; Filename: "{uninstallexe}"

[Code]
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  { Require the real license page even if a custom automation drives the wizard. }
  Result := (CurPageID <> wpLicense) or WizardForm.LicenseAcceptedRadio.Checked;
end;

function InitializeSetup(): Boolean;
begin
  { Silent acceptance is not evidence of a person reviewing the supplied grant. }
  Result := not WizardSilent;
  if not Result then
    MsgBox('Run this community candidate interactively to review its license and deployment limits.', mbError, MB_OK);
end;

{ WSL import must run in the selected owner's session. An elevated installer cannot infer that
  principal or manufacture the missing bridge service; bootstrap hooks are supplied for the lab. }
