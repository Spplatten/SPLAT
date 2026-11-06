# SPDX-License-Identifier: AGPL-3.0-only
# Runs native_witness_run.py as root in a WSL guest: the committed witness against real pidfds and
# cgroup v2 on the guest kernel. Root is needed only to create, kill and remove the disposable
# mission cgroups; the fixture inside them runs as uid 65534. Writes one evidence directory under
# the ignored private/, so a run never leaves untracked files in docs/ to collide with a later pull;
# evidence worth keeping is committed under docs/audits/evidence/ deliberately.
[CmdletBinding()]
param([string]$Distro='Ubuntu', [switch]$DryRun)
$ErrorActionPreference='Stop'
$repoRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmss')
$stage=Join-Path ([IO.Path]::GetTempPath()) "splat-native-witness-$stamp"
$evidenceDir=Join-Path $repoRoot "private\native-witness-$stamp"
New-Item -ItemType Directory -Path $stage | Out-Null
function WslPath([string]$path) {
    $converted=(& wsl.exe -d $Distro -e wslpath -a -u $path.Replace('\','/'))
    if ($LASTEXITCODE -ne 0 -or -not $converted) { throw "WSL distribution '$Distro' cannot map $path." }
    return ([string]$converted).Trim()
}
try {
    # The committed bytes, not the CRLF working copy: the witness refuses to run unless the pin
    # matches its own file, and the evidence should name what was reviewed. Both files are ASCII,
    # so rejoining git's lines with LF reproduces them; the blob check below proves it did.
    foreach ($name in 'witness.py','workload_fixture.py') {
        $path="native/experiments/alert-cancellation/$name"
        $lines=& git -C $repoRoot show "HEAD:$path"
        if ($LASTEXITCODE -ne 0) { throw "Cannot read $path at HEAD." }
        $file=Join-Path $stage $name
        [IO.File]::WriteAllText($file,(($lines -join "`n") + "`n"),[Text.UTF8Encoding]::new($false))
        $blob=& git -C $repoRoot rev-parse "HEAD:$path"
        $written=& git -C $repoRoot hash-object --no-filters -- $file
        if ($LASTEXITCODE -ne 0 -or $blob -ne $written) { throw "Staged $name is not the committed blob." }
    }
    $harness=WslPath (Join-Path $repoRoot 'native\experiments\alert-cancellation\native_witness_run.py')
    $witness=WslPath (Join-Path $stage 'witness.py')
    $fixture=WslPath (Join-Path $stage 'workload_fixture.py')
    if ($DryRun) {
        Write-Output "Staged the committed witness and fixture; '$Distro' maps every path. As root it would run:"
        Write-Output "  /usr/bin/python3 -I $harness $witness $fixture <evidence.json>"
        return
    }
    New-Item -ItemType Directory -Path $evidenceDir | Out-Null
    $evidence=Join-Path $evidenceDir 'evidence.json'
    & wsl.exe -d $Distro -u root -e /usr/bin/python3 -I $harness $witness $fixture (WslPath $evidence)
    $code=$LASTEXITCODE
    if (Test-Path -LiteralPath $evidence) { Get-Content -LiteralPath $evidence }
    if ($code -ne 0) { throw "Native witness run did not pass (exit $code); evidence: $evidenceDir" }
    Write-Output "PASS native witness run; evidence: $evidenceDir"
} finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
