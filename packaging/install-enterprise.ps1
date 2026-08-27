<#
.SYNOPSIS
    Silent Enterprise Deployment Script for Mission Controller (Intune / SCCM).
.DESCRIPTION
    Installs the enterprise signing certificate into TrustedPeople and deploys
    the application MSIX / package with full logging.
#>
[CmdletBinding()]
param (
    [string]$PackagePath = "$PSScriptRoot\Enterprise.MissionController.msix",
    [string]$CertificatePath = "$PSScriptRoot\Enterprise.MissionController.cer",
    [string]$LogPath = "$env:TEMP\MissionController_Install.log"
)

$ErrorActionPreference = "Stop"

function Log-Message {
    param([string]$Message)
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry = "[$Timestamp] $Message"
    Write-Output $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry -Force
}

try {
    Log-Message "================================================================="
    Log-Message "Starting Enterprise Silent Deployment for Mission Controller"
    Log-Message "================================================================="

    # 1. Trust Enterprise Signing Certificate
    if (Test-Path $CertificatePath) {
        Log-Message "Importing Code-Signing Certificate into LocalMachine\TrustedPeople..."
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPeople" | Out-Null
        Log-Message "Certificate successfully imported."
    } else {
        Log-Message "Notice: Certificate file not found at $CertificatePath; proceeding with existing root trust."
    }

    # 2. Deploy MSIX Package
    if (Test-Path $PackagePath) {
        Log-Message "Deploying MSIX Package from $PackagePath..."
        Add-AppxPackage -Path $PackagePath -ForceApplicationShutdown
        Log-Message "MSIX Package installed successfully."
    } elseif (Test-Path "$PSScriptRoot\Enterprise.MissionController.zip") {
        # Fallback unpackaged enterprise extraction
        $TargetDir = "$env:ProgramFiles\Enterprise Mission Controller"
        Log-Message "Extracting standalone distribution to $TargetDir..."
        if (-not (Test-Path $TargetDir)) {
            New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        }
        Expand-Archive -Path "$PSScriptRoot\Enterprise.MissionController.zip" -DestinationPath $TargetDir -Force
        Log-Message "Standalone enterprise application deployed successfully to $TargetDir."
    } else {
        throw "Neither MSIX nor ZIP package payload found in $PSScriptRoot."
    }

    Log-Message "Installation completed successfully with Exit Code 0."
    exit 0
}
catch {
    Log-Message "ERROR: Installation failed with exception: $_"
    exit 1603 # Standard Windows Installer Fatal Error
}
