# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$WindowsPayload = "$PSScriptRoot\..\dist\App",
    [Parameter(Mandatory)][string]$McpBinary,
    [Parameter(Mandatory)][string]$DaemonBinary,
    [Parameter(Mandatory)][string]$CompilerPath,
    [Parameter(Mandatory)][string]$OutputDir,
    [ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version = '0.2.0',
    [string]$RootfsPath,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$RootfsSha256,
    [string]$SourceArchive,
    [string]$McpBuildManifest,
    [string]$TestResultsPath
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. "$PSScriptRoot\community-integrity.ps1"
$payload = (Resolve-Path -LiteralPath $WindowsPayload).Path.TrimEnd('\')
$output = [IO.Path]::GetFullPath($OutputDir).TrimEnd('\')
if (Test-Path -LiteralPath $output) { throw 'Use a new output directory; existing payloads and installers are never overwritten.' }
if ($output.StartsWith($payload + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'OutputDir must be outside the preserved application payload.' }
if (@($Version.Split('.') | Where-Object { [int]$_ -gt 65535 }).Count) { throw 'Each installer version component must be at most 65535.' }
foreach ($path in @($McpBinary, $DaemonBinary, $CompilerPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required build input missing: $path" }
}
foreach ($marker in @('MissionController.UI.exe', 'MissionController.UI.dll', 'MissionController.UI.pri',
    'MissionController.UI.runtimeconfig.json', 'coreclr.dll', 'hostfxr.dll', 'Microsoft.Graphics.Canvas.dll', 'e_sqlite3.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $payload $marker) -PathType Leaf)) { throw "Incomplete Windows payload: $marker" }
}
if ($RootfsPath -and -not $RootfsSha256) { throw 'A rootfs requires its expected publisher SHA-256.' }
if ($RootfsSha256 -and -not $RootfsPath) { throw 'A rootfs checksum requires its archive.' }
if ($RootfsPath -and (Get-FileHash -LiteralPath $RootfsPath -Algorithm SHA256).Hash -ne $RootfsSha256) {
    throw 'The rootfs checksum differs from its expected publisher checksum.'
}
if ($SourceArchive -and -not (Test-Path -LiteralPath $SourceArchive -PathType Leaf)) { throw 'SourceArchive does not exist.' }
$mcpBuild = $null
if ($McpBuildManifest) {
    if ($SourceArchive) { throw 'An attested MCP build requires the verified local source snapshot, not an unchecked external archive.' }
    $mcpBuild = Get-Content -LiteralPath $McpBuildManifest -Raw | ConvertFrom-Json
    if ($mcpBuild.schema -ne 1 -or $mcpBuild.runtime -ne 'win-x64' -or
        (Get-FileHash -LiteralPath $McpBinary -Algorithm SHA256).Hash -ne $mcpBuild.sha256 -or
        (Get-FileHash -LiteralPath $DaemonBinary -Algorithm SHA256).Hash -ne $mcpBuild.daemonSha256) {
        throw 'MCP build metadata does not match the supplied Windows and Linux binaries.'
    }
    Assert-SplatSourceInventory -Expected $mcpBuild.sourceInputs -Actual @(Get-SplatSourceInventory -Root $root -BuildInputsOnly)
}
$entries = @(Get-ChildItem -LiteralPath $payload -Recurse -Force)
if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
    throw 'The payload contains a reparse point; stage real files so package contents cannot escape the input directory.'
}
$files = @($entries | Where-Object { -not $_.PSIsContainer })
if ($files | Where-Object { $_.Name -match '(?i)^(\.env($|\.)|agent\.token$|secrets\.json$)|\.(pfx|pem|key|sqlite3|db)$' }) {
    throw 'Private state or signing material is present in the application payload; use a clean application-only directory.'
}

$stage = Join-Path $output 'Payload'
foreach ($directory in @('App', 'Tools', 'Linux', 'packaging', 'docs', 'evidence')) {
    New-Item -ItemType Directory -Path (Join-Path $stage $directory) -Force | Out-Null
}
# Preserve every compiled dependency byte-for-byte, including DLLs absent from source control.
# The inventory, not a guessed NuGet dependency list, defines this installation's Windows payload.
$inventory = @(foreach ($file in $files) {
    $relative = $file.FullName.Substring($payload.Length + 1)
    $destination = Join-Path (Join-Path $stage 'App') $relative
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
    $before = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $file.FullName -Destination $destination
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $before) { throw "Payload changed during staging: $relative" }
    [ordered]@{ path = 'App/' + $relative.Replace('\', '/'); bytes = $file.Length; sha256 = $before }
})
Copy-Item -LiteralPath $McpBinary -Destination (Join-Path $stage 'Tools\splat-mcp.exe')
Copy-Item -LiteralPath $DaemonBinary -Destination (Join-Path $stage 'Linux\splat-agent')
if ($mcpBuild) { Copy-Item -LiteralPath $McpBuildManifest -Destination (Join-Path $stage 'MCP-BUILD-MANIFEST.json') }
foreach ($name in @('bootstrap-community-wsl.ps1', 'provision-community-guest.sh', 'probe-caller-identity.ps1', 'verify-community-package.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage 'packaging')
}
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'caller-identity-listener.c')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'caller-identity-listener.c') -Destination (Join-Path $stage 'packaging')
}
Copy-Item -LiteralPath (Join-Path $root 'docs\COMMUNITY-TESTING.md') -Destination (Join-Path $stage 'docs')
Copy-Item -LiteralPath (Join-Path $root 'docs\audits\2026-10-06-community-distribution.md') -Destination (Join-Path $stage 'docs')
foreach ($name in @('THREAT-MODEL.md', 'HANDOFF-caller-identity.md')) {
    Copy-Item -LiteralPath (Join-Path $root "docs\$name") -Destination (Join-Path $stage 'docs')
}
foreach ($name in @('daemon-probe.json', 'last-hop-probe.json')) {
    Copy-Item -LiteralPath (Join-Path $root "native\splat-agent\evidence\$name") -Destination (Join-Path $stage 'evidence')
}
& "$PSScriptRoot\write-distribution-license.ps1" -Destination $stage
& "$PSScriptRoot\collect-community-dependencies.ps1" -WindowsPayload $payload -Destination $stage
$dependencies = Get-Content -LiteralPath (Join-Path $stage 'DEPENDENCIES.json') -Raw | ConvertFrom-Json
if ($RootfsPath) { Copy-Item -LiteralPath $RootfsPath -Destination (Join-Path $stage 'Linux\rootfs.tar.xz') }
if ($SourceArchive) {
    Copy-Item -LiteralPath $SourceArchive -Destination (Join-Path $stage ('SPLAT-Source' + [IO.Path]::GetExtension($SourceArchive)))
} else {
    $sourceInventory = @(Get-SplatSourceInventory -Root $root)
    Write-SplatSourceArchive -Root $root -Path (Join-Path $stage 'SPLAT-Source.zip') -Inventory $sourceInventory
    [IO.File]::WriteAllText((Join-Path $stage 'SOURCE-INVENTORY.json'), (ConvertTo-Json -InputObject $sourceInventory -Depth 4) + "`n", [Text.UTF8Encoding]::new($false))
    if ($mcpBuild) { Assert-SplatSourceInventory -Expected $mcpBuild.sourceInputs -Actual @(Get-SplatSourceInventory -Root $root -BuildInputsOnly) }
}
$testSummary = $null
if ($TestResultsPath) {
    [xml]$trx = Get-Content -LiteralPath $TestResultsPath -Raw
    $testSummary = [ordered]@{ outcome = [string]$trx.TestRun.ResultSummary.outcome; total = [int]$trx.TestRun.ResultSummary.Counters.total;
        passed = [int]$trx.TestRun.ResultSummary.Counters.passed; failed = [int]$trx.TestRun.ResultSummary.Counters.failed }
    # Test logs can contain host names and captured telemetry; only counters go into the package.
}
$runtime = Get-Content -LiteralPath (Join-Path $payload 'MissionController.UI.runtimeconfig.json') -Raw | ConvertFrom-Json
$commit = (& git -C $root rev-parse HEAD | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not record the source-reference revision.' }
$manifest = [ordered]@{
    schema = 1; product = 'SPLAT Community Test Candidate'; version = $Version
    builtUtc = [DateTimeOffset]::UtcNow.ToString('o'); publisher = 'Platten Industries'
    license = 'AGPL-3.0-only'; commercialLicense = 'Separate agreement with Platten Industries; see COMMERCIAL.md.'
    thirdPartyLicenseScope = 'Third-party components retain their own licenses.'
    sourceReferenceCommit = $commit; compiledPayloadRebuilt = $false
    customDllSourceCompleteness = if ($dependencies.unresolvedDlls -eq 0) { 'PROJECT_SOURCES_LOCATED; PRESERVED_BINARIES_NOT_REBUILT' } else { 'UNRESOLVED_DLLS; SEE DEPENDENCIES.json' }
    sourceArchiveIncluded = $true; runtime = $runtime.runtimeOptions.includedFrameworks
    bpfSourceReferenceSha256 = (Get-FileHash -LiteralPath (Join-Path $root 'native\splat-agent\src\bpf\lease_lsm.bpf.c') -Algorithm SHA256).Hash.ToLowerInvariant()
    daemonSha256 = (Get-FileHash -LiteralPath (Join-Path $stage 'Linux\splat-agent') -Algorithm SHA256).Hash.ToLowerInvariant()
    rootfsSha256 = if ($RootfsPath) { $RootfsSha256.ToLowerInvariant() } else { $null }
    rootfsIncluded = [bool]$RootfsPath; tests = $testSummary
    distributionReady = $false; installerSignature = 'UNSIGNED'; cleanMachineInstallation = 'NOT_TESTED'
    secondaryPrincipalBridge = if ($mcpBuild) { $mcpBuild.managedBridge } else { 'NOT_ATTESTED' }; roadmap24Closed = $false
    mcpSha256 = (Get-FileHash -LiteralPath (Join-Path $stage 'Tools\splat-mcp.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    mcpBuildManifestIncluded = [bool]$mcpBuild
    windowsFiles = $inventory
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-MANIFEST.json'), ($manifest | ConvertTo-Json -Depth 8) + "`n", $utf8)
$sums = @(Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
})
[IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'), (($sums | Sort-Object) -join "`n") + "`n", $utf8)
& "$PSScriptRoot\verify-community-package.ps1" -PackagePath $stage | Out-Null
& $CompilerPath /Qp "/DStageDir=$stage" "/DOutputDir=$output" "/DAppVersion=$Version" "$PSScriptRoot\splat-community.iss"
if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed (exit $LASTEXITCODE)." }
$installer = Join-Path $output "SPLAT-Community-$Version-Setup.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Compiler reported success without producing the installer.' }
$description = [Diagnostics.FileVersionInfo]::GetVersionInfo($installer).FileDescription
if ($description -notmatch 'AGPL-3.0' -or $description -notmatch 'Platten Industries') { throw 'The installer lost its license metadata.' }
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$installer.sha256", "$hash  $([IO.Path]::GetFileName($installer))`n", $utf8)
[pscustomobject]@{ installer = $installer; sha256 = $hash; windowsFiles = $inventory.Count; distributionReady = $false }
