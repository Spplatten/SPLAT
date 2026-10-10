# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing: COMMERCIAL.md.
#requires -Version 5.1

function Get-SplatSourceInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [switch]$BuildInputsOnly)
    $Root = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $paths = @('src', 'native', 'packaging', 'Directory.Build.props', 'Directory.Build.targets', 'global.json', 'NuGet.Config')
    if (-not $BuildInputsOnly) { $paths += @('tests', 'brand', 'LICENSE', 'COMMERCIAL.md', 'MissionController.sln', 'README.md', '.gitignore') }
    # Include new implementation files before their first commit, while retaining Git's ignore
    # rules for build trees and private material. A tracked-only snapshot can omit shipped code.
    $files = @(& git -C $Root -c core.quotepath=false ls-files --cached --others --exclude-standard -- @paths)
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate the source snapshot.' }
    if (-not $BuildInputsOnly) {
        $files += @(& git -C $Root -c core.quotepath=false ls-files -- docs)
        if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate public source documentation.' }
        foreach ($document in @('docs/COMMUNITY-TESTING.md', 'docs/audits/2026-10-06-community-distribution.md')) {
            if (Test-Path -LiteralPath (Join-Path $Root $document)) { $files += $document }
        }
    }
    foreach ($relative in @($files | Sort-Object -Unique)) {
        if (-not $relative -or $relative -match '[\x00-\x1f"]' -or [IO.Path]::IsPathRooted($relative)) { throw 'Unsafe source filename.' }
        if ($relative -match '(?i)(^|/)(\.env($|\.)|agent\.token$|secrets\.json$)|\.(pfx|pem|key|p12|sqlite3|db)(-|$)') {
            throw "Private state or key material cannot enter the source archive: $relative"
        }
        $full = [IO.Path]::GetFullPath((Join-Path $Root $relative))
        if (-not $full.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Source path escapes the repository.' }
        $entry = Get-Item -LiteralPath $full -Force
        while ($entry.FullName -ne $Root) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Source paths cannot traverse reparse points: $relative" }
            $entry = if ($entry -is [IO.FileInfo]) { $entry.Directory } else { $entry.Parent }
        }
        $file = Get-Item -LiteralPath $full -Force
        if ($file.PSIsContainer) { throw "Expected a source file: $relative" }
        [pscustomobject][ordered]@{ path = $relative.Replace('\', '/'); bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
}

function Assert-SplatSourceInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Expected, [Parameter(Mandatory)][object[]]$Actual)
    $before = @{}; $after = @{}
    foreach ($item in $Expected) {
        if ($before.ContainsKey($item.path)) { throw 'Duplicate path in expected source inventory.' }
        $before[$item.path] = $item.sha256
    }
    foreach ($item in $Actual) {
        if ($after.ContainsKey($item.path)) { throw 'Duplicate path in actual source inventory.' }
        $after[$item.path] = $item.sha256
    }
    if ($before.Count -ne $after.Count) { throw 'Source files changed after the build began; publish again from a stable snapshot.' }
    foreach ($path in $before.Keys) {
        if (-not $after.ContainsKey($path) -or $after[$path] -ne $before[$path]) {
            throw "Source changed after the build began: $path. Publish again from a stable snapshot."
        }
    }
}

function Write-SplatSourceArchive {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Inventory)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($item in $Inventory) {
            $entry = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $Root $item.path),
                $item.path, [IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $archive.Dispose() }
    # Verify the archive's bytes, not just the input filenames. A concurrent edit must not turn a
    # build attestation into an unrelated source archive during the copy.
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($item in $Inventory) {
            $entry = $archive.GetEntry($item.path)
            $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
            finally { $stream.Dispose(); $sha.Dispose() }
            if ($hash -ne $item.sha256 -or $entry.Length -ne $item.bytes) { throw "Source changed during archival: $($item.path)" }
        }
    } finally { $archive.Dispose() }
}
