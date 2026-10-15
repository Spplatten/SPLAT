<#
.SYNOPSIS
    Builds the SPLAT Guest rootfs (Debian 13 minimal) in a privileged Debian container.

.DESCRIPTION
    Runs build-splat-guest.sh as root inside debian:trixie under Docker Desktop. The script reaches
    the container with its CRs removed, because a Windows checkout may be CRLF and sh would read a CR
    as part of every line. The output lands under dist\, which git ignores:
    - splat-guest.tar.xz and its SHA-256;
    - PACKAGES.tsv and SOURCES.tsv;
    - THIRD-PARTY-LICENSES.txt and licenses\;
    - BUILD.json.
    -WithSources also fetches every source package at the same snapshot, which a commercial
    redistribution of the GPL parts needs on offer. It is a large download.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{8}T\d{6}Z$')][string]$Snapshot = '20261014T000000Z',
    [string]$OutputDir,
    [switch]$WithSources
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDir) { $OutputDir = Join-Path $root "dist\splat-guest\$Snapshot" }
$docker = (Get-Command docker -ErrorAction SilentlyContinue).Source
if (-not $docker) { throw 'docker was not found. Start Docker Desktop first.' }
$null = & $docker version --format '{{.Server.Version}}' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'The Docker engine is not running. Start Docker Desktop first.' }

$stage = Join-Path ([IO.Path]::GetTempPath()) ('splat-guest-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $OutputDir, $stage | Out-Null
try {
    $script = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'build-splat-guest.sh')).Replace("`r", '')
    [IO.File]::WriteAllBytes((Join-Path $stage 'build-splat-guest.sh'), [Text.UTF8Encoding]::new($false).GetBytes($script))
    $inner = 'set -eu; apt-get update -qq; apt-get install -y -qq --no-install-recommends mmdebstrap xz-utils ca-certificates >/dev/null; ' +
        "sh /build/build-splat-guest.sh $Snapshot /out" + $(if ($WithSources) { ' with-sources' } else { '' })
    # docker writes its progress to stderr, and Windows PowerShell turns a native program's stderr
    # into terminating errors under 'Stop'. Only the exit codes decide.
    $ErrorActionPreference = 'Continue'
    & $docker pull debian:trixie
    if ($LASTEXITCODE -ne 0) { throw "Could not pull debian:trixie (docker exit $LASTEXITCODE)." }
    & $docker run --rm --privileged -v "${OutputDir}:/out" -v "${stage}:/build:ro" debian:trixie sh -c $inner
    if ($LASTEXITCODE -ne 0) { throw "The guest build failed (docker exit $LASTEXITCODE)." }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
Get-Content -LiteralPath (Join-Path $OutputDir 'BUILD.json')
