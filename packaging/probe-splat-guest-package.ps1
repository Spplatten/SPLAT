# SPDX-License-Identifier: AGPL-3.0-only
# Measures packaging inputs and staging only; never installs, imports, or boots a guest.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GuestBuildDirectory,
    [string]$EvidencePath = "$PSScriptRoot\evidence\lite-guest-packaging.json"
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\splat-guest-package.ps1"
$root = Split-Path -Parent $PSScriptRoot
$cases = @(& "$PSScriptRoot\test-splat-guest-package.ps1" | Where-Object { $_ -like 'PASS *' })
if (-not $cases.Count) { throw 'No packaging checks ran; no evidence will be written.' }
$build = Get-SplatGuestBuild -Directory $GuestBuildDirectory
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$stage = [IO.Path]::GetFullPath((Join-Path $tempRoot ('splat-guest-probe-' + [Guid]::NewGuid().ToString('N'))))
if (-not $stage.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging directory.' }
try {
    Copy-SplatGuestBuild -Build $build -Destination $stage
    $copied = Get-SplatGuestBuild -Directory (Join-Path $stage 'Guest') -RootfsPath (Join-Path $stage 'rootfs.tar.xz')
    if ($copied.sha256 -ne $build.sha256 -or $copied.packageCount -ne $build.packageCount) { throw 'Staging differs from the validated build.' }
    $sourceHashes = [ordered]@{}
    foreach ($relative in @('packaging/splat-guest-package.ps1', 'packaging/test-splat-guest-package.ps1',
        'packaging/probe-splat-guest-package.ps1', 'packaging/build-community-installer.ps1', 'packaging/verify-community-package.ps1')) {
        $text = [IO.File]::ReadAllText((Join-Path $root $relative)).Replace("`r`n", "`n")
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $sourceHashes[$relative] = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    $evidence = [ordered]@{
        schema = 1; recordedUtc = [DateTimeOffset]::UtcNow.ToString('o'); verdict = 'PASS'
        scope = 'Guest build validation and byte-verified staging; synthetic package verification controls'
        powershell = $PSVersionTable.PSVersion.ToString(); sourceHashEncoding = 'UTF-8 with LF line endings'
        sourceSha256 = $sourceHashes; checks = $cases; checksPassed = $cases.Count
        guest = [ordered]@{ name=$build.name; base=$build.base; snapshot=$build.snapshot; sha256=$build.sha256
            packageCount=$build.packageCount; stagedFiles=$copied.files.Count; sourceStatus=$copied.sourceStatus }
        installerCompiled = $false; guestImported = $false; cleanMachineTested = $false
        sourceCompletenessEstablished = $false; distributionReady = $false
    }
    $evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($evidenceFullPath)) -Force | Out-Null
    [IO.File]::WriteAllText($evidenceFullPath, ($evidence | ConvertTo-Json -Depth 6) + "`n", [Text.UTF8Encoding]::new($false))
    $evidence | ConvertTo-Json -Depth 6
} finally {
    if (Test-Path -LiteralPath $stage) {
        $resolved = (Resolve-Path -LiteralPath $stage).Path
        if ($resolved -ne $stage -or -not $resolved.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing unsafe staging cleanup.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
