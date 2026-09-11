<#
.SYNOPSIS
    Produces the one file a stranger downloads: a self-contained splat-mcp.exe, and its SHA-256.

.DESCRIPTION
    Self-contained on purpose. The machine that runs an MCP client is not required to have the .NET
    10 runtime, and the native SQLite the ledger uses is packed inside the executable rather than
    laid beside it (IncludeNativeLibrariesForSelfExtract in splat-mcp.csproj).

    Every step is checked. F22 is in this repository because a packaging script can announce success
    while producing nothing: a non-zero publish, a missing output, or an executable that cannot even
    print its own usage each stop this script with a non-zero exit rather than a reassuring log line.

    There is no `dotnet tool` package: PackAsTool refuses a platform TFM (NETSDK1146) and splat-mcp
    must target net10.0-windows for the Win32 containment primitives. See splat-mcp.csproj.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not $OutputDir) { $OutputDir = Join-Path $root 'dist' }

$dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source }
if (-not $dotnet) { Write-Error 'No dotnet found: this machine cannot build the artifact.'; exit 1 }

$publishDir = Join-Path $root "src\splat-mcp\bin\$Configuration\net10.0-windows\$Runtime\publish"

# Cleared first, because the check below - "nothing beside the executable" - is only meaningful
# against a directory this run produced. A symbol file left by an earlier publish would otherwise
# either fail the run or, worse, be copied out as part of the artifact.
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

Write-Host "[1/4] publishing splat-mcp ($Configuration, $Runtime, self-contained single file)" -ForegroundColor Cyan
& $dotnet publish "$root\src\splat-mcp" `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:DebugType=none `
    --nologo
if ($LASTEXITCODE -ne 0) { Write-Error "publish failed with exit code $LASTEXITCODE"; exit 1 }

$published = Join-Path $publishDir 'splat-mcp.exe'
if (-not (Test-Path $published)) { Write-Error "publish reported success but produced no $published"; exit 1 }

Write-Host "[2/4] checking it is one file and nothing else is required beside it" -ForegroundColor Cyan
$strays = Get-ChildItem (Split-Path $published) -File | Where-Object { $_.Name -ne 'splat-mcp.exe' }
if ($strays) {
    Write-Error ("the publish left files beside the executable, so it is not self-contained: " +
                 ($strays.Name -join ', '))
    exit 1
}

Write-Host "[3/4] running it, because an artifact that cannot start is not an artifact" -ForegroundColor Cyan
& $published --help | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "the published executable failed to print its usage (exit $LASTEXITCODE)"; exit 1 }

Write-Host "[4/4] staging the artifact and its hash" -ForegroundColor Cyan
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$artifact = Join-Path $OutputDir 'splat-mcp.exe'
Copy-Item $published $artifact -Force
$hash = (Get-FileHash $artifact -Algorithm SHA256).Hash
$commit = (& git -C $root rev-parse --short HEAD 2>$null)
"$hash  splat-mcp.exe  built from $commit" | Set-Content "$artifact.sha256" -Encoding utf8

Write-Host ""
Write-Host "artifact : $artifact  ($([math]::Round((Get-Item $artifact).Length / 1MB, 1)) MB)"
Write-Host "sha256   : $hash"
Write-Host "commit   : $commit"
Write-Host ""
Write-Host "Run 'splat-mcp doctor' on the target machine before trusting it: it exits 0 only when a"
Write-Host "lease there would reach the kernel."
