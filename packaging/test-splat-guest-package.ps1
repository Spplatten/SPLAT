# SPDX-License-Identifier: AGPL-3.0-only
# Synthetic packaging fixtures only: this script never imports a guest or runs a daemon.
#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('All','Valid','ArchiveTamper','MissingLicense','SourceVersion','PackageCount','ChangedDuringCopy','SourceFiles','FalseSourceClaim')][string]$Case = 'All')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\splat-guest-package.ps1"
$utf8 = [Text.UTF8Encoding]::new($false)
function Write-Text([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $utf8) }
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Require $rejected 'The invalid guest input was accepted.'
}
function New-Fixture([string]$Root) {
    New-Item -ItemType Directory -Path (Join-Path $Root 'licenses') -Force | Out-Null
    Write-Text (Join-Path $Root 'splat-guest.tar.xz') 'Synthetic fixture, not a bootable rootfs.'
    $hash = Hash (Join-Path $Root 'splat-guest.tar.xz')
    $build = [ordered]@{ name='SPLAT Guest'; base='Synthetic Debian package fixture'; snapshot='20261014T000000Z'
        packageCount=1; xzBytes=(Get-Item -LiteralPath (Join-Path $Root 'splat-guest.tar.xz')).Length; sha256=$hash }
    Write-Text (Join-Path $Root 'BUILD.json') ($build | ConvertTo-Json)
    Write-Text (Join-Path $Root 'splat-guest.tar.xz.sha256') "$hash  splat-guest.tar.xz`n"
    Write-Text (Join-Path $Root 'PACKAGES.tsv') "fixture`t1.0`tfixture`t1.0`t10`n"
    Write-Text (Join-Path $Root 'SOURCES.tsv') "fixture`t1.0`thttps://snapshot.debian.org/package/fixture/1.0/`n"
    Write-Text (Join-Path $Root 'THIRD-PARTY-LICENSES.txt') 'Synthetic copyright record.'
    Write-Text (Join-Path $Root 'licenses\fixture.copyright') 'Synthetic copyright record.'
    Write-Text (Join-Path $Root 'private.key') 'Unrelated fixture file: must not be staged.'
}
function New-Package([string]$Root, $Build, [switch]$FalseClaim) {
    Copy-SplatGuestBuild -Build $Build -Destination (Join-Path $Root 'Linux')
    New-Item -ItemType Directory -Path (Join-Path $Root 'Tools') -Force | Out-Null
    Write-Text (Join-Path $Root 'Tools\splat-mcp.exe') 'Synthetic MCP binary fixture.'
    Write-Text (Join-Path $Root 'Linux\splat-agent') 'Synthetic daemon binary fixture.'
    $manifest = [ordered]@{ schema=1; version='fixture'; sourceReferenceCommit='fixture'; windowsFiles=@()
        rootfsIncluded=$true; rootfsSha256=$Build.sha256
        daemonSha256=(Hash (Join-Path $Root 'Linux\splat-agent')); mcpSha256=(Hash (Join-Path $Root 'Tools\splat-mcp.exe'))
        guestBuild=[ordered]@{ name=$Build.name; base=$Build.base; snapshot=$Build.snapshot; packageCount=$Build.packageCount
            sourceStatus=$(if($FalseClaim) { 'INCLUDED' } else { $Build.sourceStatus }) } }
    Write-Text (Join-Path $Root 'PACKAGE-MANIFEST.json') ($manifest | ConvertTo-Json -Depth 5)
    $lines = @(Get-ChildItem -LiteralPath $Root -Recurse -File | ForEach-Object {
        (Hash $_.FullName) + '  ' + $_.FullName.Substring($Root.Length + 1).Replace('\','/')
    })
    Write-Text (Join-Path $Root 'SHA256SUMS.txt') (($lines -join "`n") + "`n")
}

$cases = if ($Case -eq 'All') { @('Valid','ArchiveTamper','MissingLicense','SourceVersion','PackageCount','ChangedDuringCopy','SourceFiles','FalseSourceClaim') } else { @($Case) }
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
foreach ($testCase in $cases) {
    $work = [IO.Path]::GetFullPath((Join-Path $tempRoot ('splat-guest-test-' + [Guid]::NewGuid().ToString('N'))))
    if (-not $work.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test directory.' }
    $fixture = Join-Path $work 'input'
    $stage = Join-Path $work 'package'
    try {
        New-Fixture $fixture
        switch ($testCase) {
            'ArchiveTamper' {
                [IO.File]::AppendAllText((Join-Path $fixture 'splat-guest.tar.xz'), 'changed')
                Reject { Get-SplatGuestBuild -Directory $fixture }
            }
            'MissingLicense' {
                Remove-Item -LiteralPath (Join-Path $fixture 'licenses\fixture.copyright')
                Reject { Get-SplatGuestBuild -Directory $fixture }
            }
            'SourceVersion' {
                Write-Text (Join-Path $fixture 'SOURCES.tsv') "fixture`t2.0`thttps://snapshot.debian.org/package/fixture/2.0/`n"
                Reject { Get-SplatGuestBuild -Directory $fixture }
            }
            'PackageCount' {
                $build = Get-Content -LiteralPath (Join-Path $fixture 'BUILD.json') -Raw | ConvertFrom-Json
                $build.packageCount = 2
                Write-Text (Join-Path $fixture 'BUILD.json') ($build | ConvertTo-Json)
                Reject { Get-SplatGuestBuild -Directory $fixture }
            }
            'ChangedDuringCopy' {
                $build = Get-SplatGuestBuild -Directory $fixture
                Write-Text (Join-Path $fixture 'licenses\fixture.copyright') 'Changed after validation.'
                Reject { Copy-SplatGuestBuild -Build $build -Destination (Join-Path $stage 'Linux') }
            }
            'SourceFiles' {
                New-Item -ItemType Directory -Path (Join-Path $fixture 'sources') | Out-Null
                Write-Text (Join-Path $fixture 'sources\fixture_1.0.dsc') 'Synthetic unverified source descriptor.'
                $build = Get-SplatGuestBuild -Directory $fixture
                Require ($build.sourceStatus -eq 'FILES_INCLUDED_COMPLETENESS_UNVERIFIED') 'Source downloads were presented as complete.'
                New-Package $stage $build
                Require (Test-Path -LiteralPath (Join-Path $stage 'Linux\Guest\sources\fixture_1.0.dsc')) 'Source file was not staged.'
                & "$PSScriptRoot\verify-community-package.ps1" -PackagePath $stage | Out-Null
            }
            'FalseSourceClaim' {
                New-Package $stage (Get-SplatGuestBuild -Directory $fixture) -FalseClaim
                Reject { & "$PSScriptRoot\verify-community-package.ps1" -PackagePath $stage }
            }
            'Valid' {
                $build = Get-SplatGuestBuild -Directory $fixture
                Require ($build.sourceStatus -eq 'NOT_INCLUDED') 'Source inventory was confused with source archives.'
                New-Package $stage $build
                $copied = Get-SplatGuestBuild -Directory (Join-Path $stage 'Linux\Guest') -RootfsPath (Join-Path $stage 'Linux\rootfs.tar.xz')
                Require ($copied.sha256 -eq $build.sha256) 'Staged rootfs changed.'
                Require (-not (Get-ChildItem -LiteralPath $stage -Recurse -Filter 'private.key')) 'Unrelated file was packaged.'
                & "$PSScriptRoot\verify-community-package.ps1" -PackagePath $stage | Out-Null
            }
        }
        Write-Output "PASS $testCase"
    } finally {
        if (Test-Path -LiteralPath $work) {
            $resolved = (Resolve-Path -LiteralPath $work).Path
            if ($resolved -ne $work -or -not $resolved.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing unsafe test cleanup.' }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
