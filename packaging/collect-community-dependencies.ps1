# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsPayload,
    [Parameter(Mandatory)][string]$Destination
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$payload = (Resolve-Path -LiteralPath $WindowsPayload).Path.TrimEnd('\')
$assets = Get-Content -LiteralPath (Join-Path $root 'src\MissionController.UI\obj\project.assets.json') -Raw | ConvertFrom-Json
$deps = Get-Content -LiteralPath (Join-Path $payload 'MissionController.UI.deps.json') -Raw | ConvertFrom-Json
$cacheRoots = @($assets.packageFolders.PSObject.Properties.Name)
$packageNames = @($assets.libraries.PSObject.Properties | Where-Object { $_.Value.type -eq 'package' } | ForEach-Object Name)
$packageNames += @($deps.libraries.PSObject.Properties.Name | Where-Object { $_ -like 'runtimepack.*' } | ForEach-Object { $_ -replace '^runtimepack\.', '' })
$candidates = @{}
$archives = @()
$packages = @()
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
foreach ($name in @($packageNames | Sort-Object -Unique)) {
    $directory = $null
    foreach ($cache in $cacheRoots) {
        $candidate = Join-Path $cache ($name.ToLowerInvariant().Replace('/', '\'))
        if (Test-Path -LiteralPath $candidate -PathType Container) { $directory = $candidate; break }
    }
    if (-not $directory) { continue }
    $packageFiles = @(Get-ChildItem -LiteralPath $directory -Recurse -File)
    foreach ($dll in @($packageFiles | Where-Object Extension -eq '.dll')) {
        if (-not $candidates.ContainsKey($dll.Name)) { $candidates[$dll.Name] = @() }
        $candidates[$dll.Name] += [pscustomobject]@{ file = $dll; package = $name; relative = $dll.FullName.Substring($directory.Length + 1).Replace('\', '/') }
    }
    foreach ($archive in @($packageFiles | Where-Object { $_.Extension -in @('.msix', '.appx') })) {
        $archives += [pscustomobject]@{ file = $archive; package = $name; relative = $archive.FullName.Substring($directory.Length + 1).Replace('\', '/') }
    }
    $noticeFiles = @($packageFiles | Where-Object { $_.Name -match '^(?i)(licen[cs]e|notice|thirdpartynotices)([._-].*)?$' -or $_.Extension -eq '.nuspec' })
    foreach ($notice in $noticeFiles) {
        $target = Join-Path (Join-Path $Destination 'ThirdParty') ($name.Replace('/', '\') + '\' + $notice.FullName.Substring($directory.Length + 1))
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Copy-Item -LiteralPath $notice.FullName -Destination $target -Force
    }
    $packages += [ordered]@{ package = $name; licenseMetadataFiles = $noticeFiles.Count }
}

$rows = @(foreach ($file in Get-ChildItem -LiteralPath $payload -Recurse -File -Filter '*.dll') {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $project = "src/$($file.BaseName)/$($file.BaseName).csproj"
    $row = [ordered]@{ path = 'App/' + $file.FullName.Substring($payload.Length + 1).Replace('\', '/'); sha256 = $hash
        status = 'UNRESOLVED'; source = $null; package = $null; packageAsset = $null; bytes = $file.Length }
    if ($file.BaseName -like 'MissionController.*' -and (Test-Path -LiteralPath (Join-Path $root $project))) {
        # A source project is evidence of location, not proof that an existing binary was rebuilt.
        $row.status = 'PROJECT_SOURCE_PRESENT_NOT_REBUILT'; $row.source = $project
    } elseif ($candidates.ContainsKey($file.Name)) {
        foreach ($candidate in $candidates[$file.Name]) {
            if ($candidate.file.Length -eq $file.Length -and (Get-FileHash -LiteralPath $candidate.file.FullName -Algorithm SHA256).Hash -eq $hash) {
                $row.status = 'PACKAGE_BYTES_MATCH'; $row.package = $candidate.package; $row.packageAsset = $candidate.relative; break
            }
        }
    }
    [pscustomobject]$row
})
# Windows App SDK carries part of its runtime in MSIX payloads, outside the .deps.json asset list.
# Compare those archive entries by content instead of interpreting a DLL's editable company field.
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($candidate in $archives) {
    $zip = [IO.Compression.ZipFile]::OpenRead($candidate.file.FullName)
    try {
        foreach ($entry in $zip.Entries) {
            $matches = @($rows | Where-Object { $_.status -eq 'UNRESOLVED' -and [IO.Path]::GetFileName($_.path) -eq $entry.Name -and $_.bytes -eq $entry.Length })
            if (-not $matches.Count) { continue }
            $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
            finally { $stream.Dispose(); $sha.Dispose() }
            foreach ($row in $matches) {
                if ($row.sha256 -eq $hash) {
                    $row.status = 'PACKAGE_BYTES_MATCH'; $row.package = $candidate.package
                    $row.packageAsset = $candidate.relative + '!' + $entry.FullName
                }
            }
        }
    } finally { $zip.Dispose() }
}
$report = [ordered]@{ schema = 1; totalDlls = $rows.Count; unresolvedDlls = @($rows | Where-Object status -eq 'UNRESOLVED').Count
    firstPartyDlls = @($rows | Where-Object status -eq 'PROJECT_SOURCE_PRESENT_NOT_REBUILT').Count
    byteMatchedPackageDlls = @($rows | Where-Object status -eq 'PACKAGE_BYTES_MATCH').Count
    scope = 'Windows payload DLL provenance; not a legal clearance or full reproducibility proof.'; packages = $packages; dlls = $rows }
[IO.File]::WriteAllText((Join-Path $Destination 'DEPENDENCIES.json'), ($report | ConvertTo-Json -Depth 7) + "`n", [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ totalDlls = $report.totalDlls; unresolvedDlls = $report.unresolvedDlls; firstPartyDlls = $report.firstPartyDlls; byteMatchedPackageDlls = $report.byteMatchedPackageDlls }
