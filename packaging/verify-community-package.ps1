# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
<#
.SYNOPSIS
    Verifies a SPLAT community package, staged or installed, against its own SHA256SUMS.txt and
    PACKAGE-MANIFEST.json.

.DESCRIPTION
    The build runs this over the staging directory before compiling the installer, and the package
    ships it so a tester can run it over the installed directory:

        powershell -ExecutionPolicy Bypass -File "<install dir>\packaging\verify-community-package.ps1" -PackagePath "<install dir>"

    It fails on any listed file that is missing or whose bytes differ, on any file present but not
    listed, and on a manifest whose Windows inventory, daemon or MCP hash disagrees with the files.
    The only unlisted files tolerated are Inno Setup's own uninstaller, which exists only after
    installation. A pass proves the files match the package's own records; it does not authenticate
    the publisher. The installer is unsigned, so compare the Setup checksum through a separate channel.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackagePath)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PackagePath).TrimEnd('\')
$sumsPath = Join-Path $root 'SHA256SUMS.txt'
$manifestPath = Join-Path $root 'PACKAGE-MANIFEST.json'
foreach ($required in @($sumsPath, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Not a SPLAT community package: $required is missing." }
}

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

# A reparse point could make a listed path read bytes from outside the package.
$entries = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
$links = @($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
if ($links.Count) { throw "The package contains a reparse point: $($links[0].FullName)" }

$listed = @{}
foreach ($line in [IO.File]::ReadAllLines($sumsPath)) {
    if (-not $line) { continue }
    if ($line -notmatch '^([0-9a-f]{64})  (\S.*)$') { throw "Malformed SHA256SUMS.txt line: $line" }
    $relative = $Matches[2]
    if ($relative -match '(^|/)\.\.(/|$)' -or $relative.StartsWith('/') -or $relative -match ':') { throw "Unsafe path in SHA256SUMS.txt: $relative" }
    if ($listed.ContainsKey($relative)) { throw "Duplicate path in SHA256SUMS.txt: $relative" }
    $listed[$relative] = $Matches[1]
}
if ($listed.Count -eq 0) { throw 'SHA256SUMS.txt lists no files.' }

$failures = New-Object System.Collections.Generic.List[string]
foreach ($relative in $listed.Keys) {
    $full = Join-Path $root ($relative.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $failures.Add("missing: $relative"); continue }
    if ((Get-Sha256 $full) -ne $listed[$relative]) { $failures.Add("changed: $relative") }
}
foreach ($file in @($entries | Where-Object { -not $_.PSIsContainer })) {
    $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
    if ($relative -eq 'SHA256SUMS.txt' -or $listed.ContainsKey($relative)) { continue }
    if ($relative -match '^unins\d{3}\.(exe|dat|msg)$') { continue }
    $failures.Add("unlisted: $relative")
}

# The manifest is itself covered by SHA256SUMS.txt, so its claims are checked against the files
# rather than trusted: a manifest naming different binaries than the package carries must fail.
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($item in @($manifest.windowsFiles)) {
    $full = Join-Path $root ($item.path.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $failures.Add("manifest names a missing Windows file: $($item.path)"); continue }
    if ((Get-Item -LiteralPath $full).Length -ne $item.bytes -or (Get-Sha256 $full) -ne $item.sha256) {
        $failures.Add("Windows file differs from the manifest: $($item.path)")
    }
}
foreach ($pair in @(@('daemonSha256', 'Linux\splat-agent'), @('mcpSha256', 'Tools\splat-mcp.exe'))) {
    $expected = $manifest.($pair[0])
    $full = Join-Path $root $pair[1]
    if (-not $expected) { $failures.Add("manifest has no $($pair[0])"); continue }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf) -or (Get-Sha256 $full) -ne $expected) {
        $failures.Add("$($pair[1]) differs from the manifest's $($pair[0])")
    }
}
if ($manifest.rootfsIncluded) {
    $rootfs = Join-Path $root 'Linux\rootfs.tar.xz'
    if (-not (Test-Path -LiteralPath $rootfs -PathType Leaf) -or (Get-Sha256 $rootfs) -ne $manifest.rootfsSha256) {
        $failures.Add('Linux\rootfs.tar.xz differs from the manifest''s rootfsSha256')
    }
}

if ($failures.Count) {
    $failures | ForEach-Object { Write-Host "FAIL  $_" }
    throw "Package verification failed: $($failures.Count) problem(s)."
}
[pscustomobject]@{ verdict = 'PASS'; files = $listed.Count; windowsFiles = @($manifest.windowsFiles).Count
    version = $manifest.version; sourceReferenceCommit = $manifest.sourceReferenceCommit }
