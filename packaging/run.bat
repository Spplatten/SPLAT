@echo off
setlocal EnableExtensions
title SPLAT launcher

rem ============================================================================
rem  SPLAT turnkey launcher. Checks the workstation, prepares the data folder,
rem  loads the optional config file, then starts the console from its own folder.
rem  Every failure names itself and stays on screen. Nothing here needs admin.
rem  Console tools are called by full System32 path: a PATH that puts another
rem  find or timeout first (Git Bash, MSYS) would otherwise change what this does.
rem ============================================================================

set "ROOT=%~dp0"
set "APP=%ROOT%App"
set "EXE=%APP%\MissionController.UI.exe"
set "DATA=%LOCALAPPDATA%\MissionController"
set "SPLATDIR=%LOCALAPPDATA%\SPLAT"
set "CONFIG=%SPLATDIR%\splat.env"
set "TEMPLATE=%ROOT%config\splat.env.example"
set "CRASHLOG=%SPLATDIR%\crash.log"
set "LAUNCHLOG=%SPLATDIR%\launcher.log"
set "SYS32=%SystemRoot%\System32"
set "PS=%SYS32%\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%SPLATDIR%" mkdir "%SPLATDIR%" 2>nul
call :log "---- launcher start ----"

rem ---- 1. 64-bit Windows ------------------------------------------------------
set "ARCH=%PROCESSOR_ARCHITEW6432%"
if "%ARCH%"=="" set "ARCH=%PROCESSOR_ARCHITECTURE%"
if /I not "%ARCH%"=="AMD64" (
    set "MSG=This package is built for 64-bit Windows on x64. This PC reports %ARCH%." & goto :fail
)
call :log "arch ok: %ARCH%"

rem ---- 2. Windows build 19041 (Windows 10 version 2004) or newer ---------------
rem  ver prints "Microsoft Windows [Version 10.0.26200.1234]"; the third dotted
rem  number is the build. Older builds lack the Windows App SDK's OS surface.
set "BUILD="
for /f "tokens=2 delims=[]" %%v in ('ver') do set "VERSTR=%%v"
for /f "tokens=4 delims=. " %%b in ("%VERSTR%") do set "BUILD=%%b"
if "%BUILD%"=="" (
    call :log "warning: could not parse Windows build from '%VERSTR%'"
) else (
    if %BUILD% LSS 19041 (
        set "MSG=SPLAT needs Windows 10 version 2004 (build 19041) or newer. This PC is build %BUILD%." & goto :fail
    )
)
call :log "windows ok: %VERSTR%"

rem ---- 3. The package is complete ---------------------------------------------
if not exist "%EXE%" (
    set "MSG=App\MissionController.UI.exe was not found next to this launcher. Unzip the whole package, keeping the App folder, then run again." & goto :fail
)
if not exist "%APP%\Microsoft.WindowsAppRuntime.Bootstrap.dll" (
    set "MSG=The App folder is incomplete (runtime files missing). Unzip the whole package again." & goto :fail
)
call :log "package ok: %EXE%"

rem ---- 4. Data folder exists and is writable ----------------------------------
rem  The console keeps its database, credential vault and jails here. A folder
rem  that cannot be written shows up later as 'ACL JAIL FAILED' or a ledger
rem  error; it is cheaper to say so now.
if not exist "%DATA%" mkdir "%DATA%" 2>nul
if not exist "%DATA%" (
    set "MSG=Could not create the data folder %DATA%. Check that your user account can write under %LOCALAPPDATA%." & goto :fail
)
echo probe> "%DATA%\.write-probe" 2>nul
if not exist "%DATA%\.write-probe" (
    set "MSG=The data folder %DATA% is not writable. Check folder permissions or antivirus folder protection." & goto :fail
)
del /q "%DATA%\.write-probe" 2>nul
call :log "data folder ok: %DATA%"

rem ---- 5. Config file: create from the template on first run, then load it ----
rem  splat.env is plain KEY=VALUE lines. It is optional: an absent or empty file
rem  means every default. API keys do NOT go here; they go in the Settings pane.
if not exist "%CONFIG%" (
    if exist "%TEMPLATE%" (
        copy /y "%TEMPLATE%" "%CONFIG%" >nul
        call :log "config created from template: %CONFIG%"
    )
)
if exist "%CONFIG%" (
    for /f "usebackq eol=# tokens=1,* delims==" %%k in ("%CONFIG%") do (
        if not "%%k"=="" if not "%%l"=="" (
            set "%%k=%%l"
            call :log "config: %%k set"
        )
    )
)

rem  A configured key file that does not exist stops the console at start with a
rem  dialog. Say it here, where the path is one line away from being fixed.
if defined SPLAT_LEDGER_KEY_FILE if not exist "%SPLAT_LEDGER_KEY_FILE%" (
    set "MSG=splat.env names SPLAT_LEDGER_KEY_FILE=%SPLAT_LEDGER_KEY_FILE% but that file does not exist. Fix or remove the line in %CONFIG%." & goto :fail
)
if defined SPLAT_RUN_RECORD_KEY_FILE if not exist "%SPLAT_RUN_RECORD_KEY_FILE%" (
    set "MSG=splat.env names SPLAT_RUN_RECORD_KEY_FILE=%SPLAT_RUN_RECORD_KEY_FILE% but that file does not exist. Fix or remove the line in %CONFIG%." & goto :fail
)

rem ---- 6. Already running? -----------------------------------------------------
"%SYS32%\tasklist.exe" /FI "IMAGENAME eq MissionController.UI.exe" 2>nul | "%SYS32%\find.exe" /I "MissionController.UI.exe" >nul
if not errorlevel 1 (
    echo SPLAT is already running. Bring its window to the front, or close it and run again.
    call :log "already running; not starting a second copy"
    goto :end
)

rem ---- 7. Start from the App folder --------------------------------------------
rem  The working directory must be the exe's own folder: started from anywhere
rem  else the Windows App SDK cannot find its resources and fails with 0x80008083,
rem  which looks like a missing runtime and is not. DOTNET_ROOT is cleared so a
rem  runtime installed elsewhere on the PC cannot be substituted for the bundled one.
set "DOTNET_ROOT="
echo Starting SPLAT...
call :log "starting %EXE%"
start "" /D "%APP%" "%EXE%"

rem  A startup failure shows its own error dialog and exits. Wait a moment and,
rem  if the process is already gone, show the crash log so the reason is on screen.
rem  Not timeout.exe: it refuses to run when stdin is redirected, which is how a
rem  scheduled task or a deployment script calls this launcher.
"%PS%" -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 6" >nul 2>nul
"%SYS32%\tasklist.exe" /FI "IMAGENAME eq MissionController.UI.exe" 2>nul | "%SYS32%\find.exe" /I "MissionController.UI.exe" >nul
if errorlevel 1 (
    echo.
    echo SPLAT exited within a few seconds of starting.
    if exist "%CRASHLOG%" (
        echo Last lines of %CRASHLOG%:
        echo ----------------------------------------------------------------------
        "%PS%" -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -LiteralPath '%CRASHLOG%' -Tail 30" 2>nul || type "%CRASHLOG%"
        echo ----------------------------------------------------------------------
    ) else (
        echo No crash log was written at %CRASHLOG%.
    )
    call :log "process gone within 6 s"
    echo See README_CLIENT.md, section Troubleshooting.
    pause
    endlocal
    exit /b 2
)
call :log "running"
goto :end

rem ---- helpers -----------------------------------------------------------------
:log
>> "%LAUNCHLOG%" echo %date% %time% %~1
exit /b 0

:fail
echo.
echo SPLAT cannot start:
echo   %MSG%
echo.
echo Details are in %LAUNCHLOG%. See README_CLIENT.md, section Troubleshooting.
call :log "FAIL: %MSG%"
pause
endlocal
exit /b 1

:end
endlocal
exit /b 0
