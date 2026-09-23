# SPLAT — Client Quickstart

SPLAT is a desktop console for running governed diagnostic and security missions on this PC. This
package is complete: nothing needs to be installed first, not .NET, not a runtime, not an SDK.

## What is in the package

| Item | What it is |
|---|---|
| `run.bat` | Start here. Checks the PC, prepares your data folder, starts SPLAT. |
| `App\` | The console and everything it runs on. Do not move files out of it. |
| `config\splat.env.example` | Optional settings, with every line explained. Copied to your profile on first run. |
| `docs\SPLAT-Field-Guide.html` | The plain-English guide to what SPLAT does. Opens in any browser. |
| `VERSION.txt` | Which build this is and what it was tested with. |
| `SHA256SUMS.txt` | A checksum for every file, so you can confirm nothing changed in transit. |

## System requirements

- Windows 10 version 2004 (build 19041) or newer, or Windows 11. 64-bit only.
- About 300 MB of free disk space for the package, plus room for your data.
- A normal user account. Administrator rights are not required to install or run.
- An internet connection only if you use live AI analysis. Without a key, SPLAT runs its
  missions locally and shows simulated analysis.

## How to launch

1. Unzip the whole package into a folder you own, for example `C:\Users\<you>\SPLAT`.
   Keep `run.bat` and the `App` folder together.
2. Double-click `run.bat`.
3. The first time, Windows may show "Windows protected your PC" because the package is not signed
   by a store publisher. Click **More info**, then **Run anyway**. This happens once.
4. The SPLAT window opens. In the top bar, three lights report the self-check:
   **JOB SANDBOX READY**, **ACL JAIL READY** and **LEDGER CHAIN VERIFIED**. All three green means
   the console is ready to run missions.

You can also start `App\MissionController.UI.exe` directly. Prefer `run.bat`: it runs the checks
and shows the reason on screen if something is wrong.

## First-run setup (optional)

- **Live AI analysis.** Open **Settings** inside SPLAT and paste an Anthropic or Google Gemini API
  key. The key is stored encrypted for your Windows account and never written to a plain file. Do
  not put keys in `splat.env`.
- **Custom data location or signing keys.** Edit `%LOCALAPPDATA%\SPLAT\splat.env` (created from
  the example on first run). Each line is explained in the file. Restart through `run.bat`.

## Where your data is

Everything SPLAT writes lives under your Windows profile. Nothing is written into the package
folder, into `Program Files`, or into the registry.

| What | Where |
|---|---|
| Mission database and audit ledger | `%LOCALAPPDATA%\MissionController\Data\missioncontroller.db` |
| Encrypted API keys | `%LOCALAPPDATA%\MissionController\Vault\` |
| Temporary mission jails (cleaned after each run) | `%LOCALAPPDATA%\MissionController\Jails\` |
| Exported compliance bundles and run records | `%LOCALAPPDATA%\MissionController\ComplianceExports\` and `...\MissionRunRecords\` |
| Your settings file | `%LOCALAPPDATA%\SPLAT\splat.env` |
| Launcher log (every check `run.bat` made) | `%LOCALAPPDATA%\SPLAT\launcher.log` |
| Crash log (written only when SPLAT fails) | `%LOCALAPPDATA%\SPLAT\crash.log` |

To open the folder: press **Win+R**, type `%LOCALAPPDATA%\MissionController`, press Enter.

To back up: copy the `Data` folder. To move to another PC: copy the package and the `Data`
folder. API keys do not move (they are encrypted to your Windows account); paste them again.

## Troubleshooting

**`run.bat` shows "SPLAT cannot start" and a reason.**
The reason line says what to fix: unzip the whole package, use a 64-bit PC, free the data folder
from a permission or antivirus block, or correct a path in `splat.env`. The same text is in
`launcher.log`.

**"Windows protected your PC" (blue SmartScreen box).**
Click **More info**, then **Run anyway**. If those buttons are missing, right-click the zip file
before unzipping, choose **Properties**, tick **Unblock**, click OK, then unzip again.

**A window opens and closes, or nothing appears.**
`run.bat` waits a few seconds and prints the end of `crash.log` if SPLAT exited. If it did not
exit but shows no window, check Task Manager for `MissionController.UI.exe`, end it, and read
`%LOCALAPPDATA%\SPLAT\crash.log`. The last entry names the failure.

**An error dialog titled "SPLAT — Unrecoverable Error".**
The dialog text and the crash log carry the same detail. The most common cause is a `splat.env`
line pointing at a key file that does not exist or is the wrong size. Remove or fix the line.

**Error mentioning `0x80008083`.**
SPLAT was started from the wrong folder. Use `run.bat`, or start the exe from inside `App\`.

**Self-check shows ACL JAIL FAILED.**
SPLAT could not create and lock down a folder under `%LOCALAPPDATA%\MissionController\Jails`.
Check that folder is not read-only, not on a network drive, and not blocked by antivirus
"controlled folder access".

**Self-check shows LEDGER CHAIN FAILED.**
The audit database failed integrity verification. If you moved or edited
`missioncontroller.db`, restore it from backup. If this is a fresh install, delete the `Data`
folder and start again; a new, empty ledger is created.

**Missions run but analysis says "simulated".**
No API key is configured, or the key was rejected. Open **Settings**, paste the key, and use the
validate button. An organisation-scoped Anthropic key is refused; use a workspace key.

**The window is black or blank.**
The graphics layer could not start. Update the display driver, then try again. Remote Desktop
sessions without GPU acceleration can also show this.

**Antivirus quarantines a file from `App\`.**
Restore it and add the package folder to the exclusion list, or re-unzip the package. Check
`SHA256SUMS.txt` if you want to confirm the file is the one that shipped.

## Uninstall

Delete the package folder. To remove your data as well, delete
`%LOCALAPPDATA%\MissionController` and `%LOCALAPPDATA%\SPLAT`. Nothing else is left behind.
