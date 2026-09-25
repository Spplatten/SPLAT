<#
.SYNOPSIS
    Re-proves the Linux substrate only when the program that ships has moved ahead of the evidence.

.DESCRIPTION
    `reprove-substrate.ps1` costs a cargo build, a stopped service and two probe runs. Running that
    weekly against an unchanged daemon is a weekly interruption to prove a thing already proven, and
    the surest way to have a scheduled task switched off. Running it never is how four kernel-side
    changes came to sit unproven between 2026-09-20 and 2026-09-24, with the README's "proven under
    root" withdrawn the whole time.

    So the trigger is not the calendar, it is the hash. `DocumentationDriftTests` already binds the
    README's claim to `daemon-probe.json`, which carries the SHA-256 of the BPF source it exercised.
    This script compares that recorded hash with the source in the tree. Equal means the standing
    PASS still describes the program that ships, and nothing runs. Different means the proof has
    expired, and the full re-proof runs.

    THE PROOF RUNS AGAINST A CLEAN CHECKOUT, and that is the reason this script exists rather than a
    schtasks line pointing straight at reprove-substrate.ps1. C:\C_AGENT_BUILDER is a shared working
    tree - more than one agent edits it, and it usually carries uncommitted work. A probe run there
    would hash a daemon source that includes somebody's half-finished edit and record a PASS for a
    program that is on no branch and in nobody's build. This tree is fetched and reset to
    origin/main before anything is measured, so what gets proven is what ships.

    It does NOT commit the evidence. A scheduled task that pushes to main unattended is a scheduled
    task that can publish a claim nobody read. The evidence lands in the tree and the log says so;
    landing it on main is a person's act.

.PARAMETER Tree
    The proof checkout. Must be a git worktree that nothing else edits.

.PARAMETER LogPath
    Appended to on every run, whether or not anything was proven.

.PARAMETER Force
    Re-prove even when the hashes agree. For testing this script, and for the case where the
    evidence is suspect rather than stale.

.PARAMETER CheckOnly
    Report whether the proof has expired and stop there, touching no service and building nothing.
    Exit 0 when the standing evidence still describes what ships, 2 when it does not. This is the
    form to run when you just want the answer, and the form this script is tested by.
#>
[CmdletBinding()]
param(
    [string]$Tree = 'C:\C_AGENT_BUILDER-reprove',
    [string]$LogPath = "$env:LOCALAPPDATA\SPLAT\reprove.log",
    [switch]$Force,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

function Write-Line([string]$text) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$stamp  $text"
    Write-Host $line
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    } catch {
        # A log that cannot be written is not a reason to skip the proof.
    }
}

function Fail([string]$text) {
    Write-Line "FAILED  $text"
    exit 1
}

if (-not (Test-Path (Join-Path $Tree '.git'))) {
    Fail "$Tree is not a git checkout. Create it with: git -C C:\C_AGENT_BUILDER worktree add $Tree origin/main --detach"
}

$script = Join-Path $Tree 'packaging\reprove-substrate.ps1'
$source = Join-Path $Tree 'native\splat-agent\src\bpf\lease_lsm.bpf.c'
$evidence = Join-Path $Tree 'native\splat-agent\evidence\daemon-probe.json'

# ------------------------------------------------------------------------------------------------
# Never while a proof is already in flight. The next thing this script does is reset the tree hard,
# and reprove-substrate.ps1 runs out of that same tree with the installed service stopped and a root
# daemon up: pulling the ground out from under it would leave the operator's daemon down and its
# `finally` never reached. An operator running it by hand and a schedule firing on the hour is not
# a hypothetical - it is the first hour this task exists.
# ------------------------------------------------------------------------------------------------
$inFlight = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'reprove-substrate\.ps1' })
if ($inFlight.Count -gt 0) {
    Write-Line "skipped  a re-proof is already running (pid $($inFlight.ProcessId -join ', ')); this run does nothing."
    exit 0
}

# ------------------------------------------------------------------------------------------------
# The checkout is made to be what ships, every time. A dirty proof tree is a defect in the proof,
# not a local variation to preserve, so anything in it is discarded rather than worked around.
# ------------------------------------------------------------------------------------------------
& git -C $Tree fetch --quiet origin
if ($LASTEXITCODE -ne 0) { Fail 'git fetch origin failed; the proof would run against an unknown revision.' }

& git -C $Tree checkout --quiet --detach origin/main
if ($LASTEXITCODE -ne 0) { Fail 'could not check out origin/main in the proof tree.' }

& git -C $Tree reset --quiet --hard origin/main
& git -C $Tree clean -qfd -e 'target' -e '*.INCOMPLETE.json'

$revision = (& git -C $Tree rev-parse --short HEAD).Trim()

foreach ($path in @($script, $source)) {
    if (-not (Test-Path $path)) { Fail "$path is missing at $revision." }
}

$treeHash = (Get-FileHash -Path $source -Algorithm SHA256).Hash.ToLowerInvariant()

$recordedHash = $null
$recordedAt = 'never'
if (Test-Path $evidence) {
    try {
        $json = Get-Content $evidence -Raw | ConvertFrom-Json
        $recordedHash = ($json.bpf_source_sha256).ToLowerInvariant()
        $recordedAt = $json.recorded_utc
    } catch {
        Write-Line "evidence at $evidence could not be read as JSON; treating the proof as expired."
    }
}

if ($recordedHash -eq $treeHash -and -not $Force) {
    Write-Line "current  $revision  bpf $($treeHash.Substring(0,12))  proven $recordedAt - nothing to do."
    exit 0
}

$verdict = "expired  {0}  tree bpf {1}  evidence bpf {2} ({3})" -f
    $revision,
    $treeHash.Substring(0, 12),
    $(if ($recordedHash) { $recordedHash.Substring(0, 12) } else { 'none' }),
    $recordedAt

if ($CheckOnly) {
    Write-Line "$verdict - CheckOnly, so nothing was built, stopped or proven."
    exit 2
}

Write-Line "$verdict - re-proving."

& powershell -ExecutionPolicy Bypass -File $script
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Line "PASS     $revision - evidence rewritten in $Tree. It is NOT committed: review it, then commit and push it to main."
} else {
    Write-Line "FAILED   $revision - reprove-substrate.ps1 exited $code. Standing evidence was not overwritten; look for *.INCOMPLETE.json beside it."
}

exit $code
