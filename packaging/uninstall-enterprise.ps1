<#
.SYNOPSIS
    Clean De-Provisioning Script for Mission Controller.
.DESCRIPTION
    Silently uninstalls the AppX package and wipes temporary DPAPI vaults,
    SQLite WAL databases, and active NT ACL filesystem jails.
#>
[CmdletBinding()]
param (
    [string]$PackageName = "Enterprise.MissionController",
    [switch]$PurgeUserData = $true,
    [string]$LogPath = "$env:TEMP\MissionController_Uninstall.log"
)

$ErrorActionPreference = "Continue"

function Log-Message {
    param([string]$Message)
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry = "[$Timestamp] $Message"
    Write-Output $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry -Force
}

try {
    Log-Message "================================================================="
    Log-Message "Starting Enterprise De-Provisioning for Mission Controller"
    Log-Message "================================================================="

    # 1. Remove AppX Package
    $App = Get-AppxPackage -Name "*MissionController*" | Select-Object -First 1
    if ($App) {
        Log-Message "Removing AppX Package: $($App.PackageFullName)..."
        Remove-AppxPackage -Package $App.PackageFullName
        Log-Message "AppX Package removed."
    }

    # 2. Clean ProgramFiles if standalone deployment was used
    $TargetDir = "$env:ProgramFiles\Enterprise Mission Controller"
    if (Test-Path $TargetDir) {
        Log-Message "Removing standalone installation directory: $TargetDir..."
        Remove-Item -Path $TargetDir -Recurse -Force
    }

    # 3. Clean the data root (DPAPI secrets, SQLite DBs, Jails, workspaces, crash log).
    #    Both are purged: since 2026-09-25 everything lives under %LOCALAPPDATA%\SPLAT, but a machine
    #    that never started the new build still has the old root, and an uninstaller that cleans only
    #    where the current build writes leaves an operator's DPAPI secrets on a decommissioned host.
    if ($PurgeUserData) {
        foreach ($DataDir in @("$env:LOCALAPPDATA\SPLAT", "$env:LOCALAPPDATA\MissionController")) {
            if (Test-Path $DataDir) {
                Log-Message "Purging local data directory and DPAPI secrets: $DataDir..."
                Remove-Item -Path $DataDir -Recurse -Force
                Log-Message "Data directory purged: $DataDir"
            }
        }
    }

    Log-Message "De-provisioning completed successfully with Exit Code 0."
    exit 0
}
catch {
    Log-Message "ERROR: De-provisioning encountered an error: $_"
    exit 1
}
