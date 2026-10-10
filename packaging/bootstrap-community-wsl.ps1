# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^SPLAT-[A-Za-z0-9][A-Za-z0-9._-]{0,55}$')][string]$Distro,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$ExpectedOwnerSid,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$OperatorSid,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifest = Get-Content -LiteralPath (Join-Path $package 'PACKAGE-MANIFEST.json') -Raw | ConvertFrom-Json
if (-not $manifest.rootfsIncluded) { throw 'This candidate has no clean rootfs; no WSL state was changed.' }
foreach ($item in @(@('Linux\rootfs.tar.xz', $manifest.rootfsSha256), @('Linux\splat-agent', $manifest.daemonSha256))) {
    if (-not $item[1] -or (Get-FileHash -LiteralPath (Join-Path $package $item[0]) -Algorithm SHA256).Hash -ne $item[1]) {
        throw "The package input hash is wrong: $($item[0]). No WSL state was changed."
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $ExpectedOwnerSid -or $ExpectedOwnerSid -eq $OperatorSid) {
    throw 'Run this hook inside the intended secondary owner account; it must differ from the operator.'
}
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$groups = & "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify the owner token.' }
$members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    ($groups -join "`n") -match 'S-1-5-32-544' -or $members.SID.Value -contains $identity.User.Value) {
    throw 'The distro owner must be a separate standard Windows account, not an elevated or filtered administrator.'
}
$null = Get-LocalUser -SID $identity.User -ErrorAction Stop
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
$listed = @(& $wsl --list --quiet)
if ($LASTEXITCODE -ne 0) { throw 'WSL is unavailable; enable WSL2 and complete its reboot first.' }
$names = @($listed | ForEach-Object { $_.Replace([string][char]0, '').Trim() })
if ($names -contains $Distro) { throw 'Refusing to replace an existing distro.' }
$location = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "SPLAT\WSL\$Distro"))
if (Test-Path -LiteralPath $location) { throw 'Refusing to reuse an existing WSL storage directory.' }
if (-not $Apply) {
    [pscustomobject]@{ action = 'PLAN_ONLY'; distro = $Distro; ownerSid = $ExpectedOwnerSid; location = $location; roadmap24Closed = $false }
    return
}
# Registration is per Windows principal. Never change a default distro, unregister one, or
# change .wslconfig for every guest just to make this experiment appear to have passed.
New-Item -ItemType Directory -Path $location -ErrorAction Stop | Out-Null
& $wsl --import $Distro $location (Join-Path $package 'Linux\rootfs.tar.xz') --version 2
if ($LASTEXITCODE -ne 0) { throw 'WSL import failed; preserve the new directory for diagnosis.' }
$guestScript = (& $wsl -d $Distro -e wslpath -a (Join-Path $PSScriptRoot 'provision-community-guest.sh') | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $guestScript) { throw 'Cannot resolve the guest provisioning hook.' }
& $wsl -d $Distro -u root -e bash $guestScript --configure-systemd
if ($LASTEXITCODE -ne 0) { throw 'The new distro could not enable systemd; inspect it before continuing.' }
# Only the distro just imported is restarted; other distros and their workloads keep running.
& $wsl --terminate $Distro
if ($LASTEXITCODE -ne 0) { throw 'The new distro could not restart to activate systemd.' }
$guestDaemon = (& $wsl -d $Distro -e wslpath -a (Join-Path $package 'Linux\splat-agent') | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $guestDaemon) { throw 'Cannot resolve the bundled daemon.' }
& $wsl -d $Distro -u root -e bash $guestScript $guestDaemon $manifest.daemonSha256
if ($LASTEXITCODE -ne 0) { throw 'Guest provisioning refused; the distro remains available for diagnosis. Row 2.4 is still open.' }
[pscustomobject]@{ distro = $Distro; ownerSid = $ExpectedOwnerSid; daemonProvisioned = $true; bridgeServiceAvailable = $false; roadmap24Closed = $false }
