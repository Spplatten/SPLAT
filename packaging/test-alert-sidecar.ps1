# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration='Release',
    # Sandboxed runners may redirect LOCALAPPDATA. Accept an explicit installed SDK rather
    # than falling back to PATH, which points at SDK 9 on the development host.
    [string]$DotNetPath=(Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe')
)
$ErrorActionPreference='Stop'
$repoRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sidecarSdk=$DotNetPath
if (-not (Test-Path -LiteralPath $sidecarSdk -PathType Leaf)) { throw 'The repository requires .NET 10. Supply -DotNetPath when LOCALAPPDATA does not identify the installed SDK.' }
$sidecarVersion=& $sidecarSdk --version
if ($LASTEXITCODE -ne 0 -or $sidecarVersion -notmatch '^10\.') { throw 'A .NET 10 SDK is required.' }
$sidecarProject=Join-Path $repoRoot 'src\splat-alert-sidecar\splat-alert-sidecar.csproj'
# Separate compilation and execution; no warning/audit suppression and no dependency on WinUI,
# the native daemon, its pins or packaging output. A failure prevents a successful gate exit.
& $sidecarSdk build $sidecarProject -c $Configuration -m:1 -p:UseSharedCompilation=false
if ($LASTEXITCODE -ne 0) { throw 'Sidecar build gate failed.' }
$sidecarAssembly=Join-Path $repoRoot "src\splat-alert-sidecar\bin\$Configuration\net10.0\splat-alert-sidecar.dll"
& $sidecarSdk $sidecarAssembly --self-test
if ($LASTEXITCODE -ne 0) { throw 'Sidecar contract checks failed.' }
Write-Output 'PASS sidecar build and contract checks. Live provider/TLS/native validation is separate.'
