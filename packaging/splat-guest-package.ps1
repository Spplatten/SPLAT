# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing: COMMERCIAL.md.
#requires -Version 5.1

function Get-SplatGuestBuild {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory, [string]$RootfsPath)
    $directoryPath = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path.TrimEnd('\')
    # Validate the tree before following any of its files. Only the named public build outputs
    # below are included; unrelated files beside a build must never enter an installer.
    $entries = @(Get-Item -LiteralPath $directoryPath -Force) + @(Get-ChildItem -LiteralPath $directoryPath -Recurse -Force -ErrorAction Stop)
    if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Guest build contains a reparse point.' }
    if (-not $RootfsPath) { $RootfsPath = Join-Path $directoryPath 'splat-guest.tar.xz' }
    $rootfs = Get-Item -LiteralPath $RootfsPath -ErrorAction Stop
    if ($rootfs.PSIsContainer -or ($rootfs.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest rootfs must be a regular file.' }
    $required = @('BUILD.json', 'PACKAGES.tsv', 'SOURCES.tsv', 'THIRD-PARTY-LICENSES.txt', 'splat-guest.tar.xz.sha256')
    foreach ($relative in $required) {
        $file = Get-Item -LiteralPath (Join-Path $directoryPath $relative) -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -eq 0) { throw "Missing guest record: $relative" }
    }
    $build = Get-Content -LiteralPath (Join-Path $directoryPath 'BUILD.json') -Raw | ConvertFrom-Json
    if ($build.name -ne 'SPLAT Guest' -or $build.snapshot -notmatch '^\d{8}T\d{6}Z$' -or
        $build.sha256 -notmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrWhiteSpace($build.base)) { throw 'Invalid guest BUILD.json.' }
    $hash = (Get-FileHash -LiteralPath $rootfs.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksum = (Get-Content -LiteralPath (Join-Path $directoryPath 'splat-guest.tar.xz.sha256') -Raw).Trim()
    if ($hash -ne $build.sha256 -or $rootfs.Length -ne $build.xzBytes -or
        $checksum -cne "$hash  splat-guest.tar.xz") { throw 'Guest archive differs from its build record or checksum.' }

    $sources = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $directoryPath 'SOURCES.tsv'))) {
        $row = $line.Split([char]9)
        if ($row.Count -ne 3 -or $row[0] -notmatch '^[a-z0-9][a-z0-9+.-]*$' -or
            $row[1] -notmatch '^[A-Za-z0-9.+:~_-]+$') { throw 'Invalid guest source inventory.' }
        $key = $row[0] + "`t" + $row[1]
        $url = 'https://snapshot.debian.org/package/' + $row[0] + '/' + $row[1].Replace(':', '%3A') + '/'
        if ($sources.ContainsKey($key) -or $row[2] -cne $url) { throw 'Duplicate or mismatched guest source record.' }
        $sources[$key] = $true
    }
    $packages = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $directoryPath 'PACKAGES.tsv'))) {
        $row = $line.Split([char]9)
        if ($row.Count -ne 5 -or $row[0] -notmatch '^[a-z0-9][a-z0-9+.-]*$' -or
            $row[1] -notmatch '^[A-Za-z0-9.+:~_-]+$' -or $row[4] -notmatch '^\d+$') { throw 'Invalid guest package inventory.' }
        if ($packages.ContainsKey($row[0]) -or -not $sources.ContainsKey($row[2] + "`t" + $row[3])) {
            throw 'Duplicate guest package or missing exact source version.'
        }
        $packages[$row[0]] = $true
        $relative = 'licenses/' + $row[0] + '.copyright'
        $license = Get-Item -LiteralPath (Join-Path $directoryPath $relative) -ErrorAction Stop
        if ($license.PSIsContainer -or $license.Length -eq 0) { throw "Missing guest copyright record: $relative" }
        $required += $relative
    }
    if ($packages.Count -eq 0 -or $packages.Count -ne $build.packageCount) { throw 'Guest package count differs from BUILD.json.' }

    $sourceFiles = @()
    $sourceDirectory = Join-Path $directoryPath 'sources'
    if (Test-Path -LiteralPath $sourceDirectory) {
        $sourceFiles = @(Get-ChildItem -LiteralPath $sourceDirectory -Force -ErrorAction Stop)
        if ($sourceFiles.Count -eq 0) { throw 'The guest sources directory is empty.' }
        foreach ($file in $sourceFiles) {
            if ($file.PSIsContainer -or $file.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9+._~-]*\.(dsc|tar|tar\.(gz|bz2|xz|zst)|diff\.gz|asc)$') {
                throw 'Unexpected file in guest sources; only Debian source archives and descriptors may be packaged.'
            }
            $required += 'sources/' + $file.Name
        }
    }
    $files = @([pscustomobject]@{ source = $rootfs.FullName; path = 'rootfs.tar.xz'; bytes = $rootfs.Length; sha256 = $hash })
    foreach ($relative in $required) {
        $file = Get-Item -LiteralPath (Join-Path $directoryPath $relative)
        $files += [pscustomobject]@{ source = $file.FullName; path = 'Guest/' + $relative; bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    [pscustomobject]@{ directory = $directoryPath; rootfsPath = $rootfs.FullName; sha256 = $hash; files = $files
        name = $build.name; base = $build.base; snapshot = $build.snapshot; packageCount = $packages.Count
        # A directory of downloads is not proof of corresponding-source completeness or a written offer.
        sourceStatus = $(if ($sourceFiles.Count) { 'FILES_INCLUDED_COMPLETENESS_UNVERIFIED' } else { 'NOT_INCLUDED' }) }
}

function Copy-SplatGuestBuild {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Build, [Parameter(Mandatory)][string]$Destination)
    $target = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($target.Equals($Build.directory, [StringComparison]::OrdinalIgnoreCase) -or
        $target.StartsWith($Build.directory + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Guest staging must be outside the source build.' }
    foreach ($item in $Build.files) {
        $path = Join-Path $target $item.path
        if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite staged guest file: $($item.path)" }
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $item.source -Destination $path -ErrorAction Stop
        if ((Get-Item -LiteralPath $path).Length -ne $item.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $item.sha256) { throw "Guest input changed during staging: $($item.path)" }
    }
}
