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
    This script compares that recorded hash with the source on origin/main. Equal means the standing
    PASS still describes the program that ships, and nothing runs. Different means the proof has
    expired, and the full re-proof runs.

    THE PROOF RUNS AGAINST A CLEAN CHECKOUT, and that is the reason this script exists rather than a
    schtasks line pointing straight at reprove-substrate.ps1. The repository is a shared working tree
    - more than one agent edits it, and it usually carries uncommitted work. A probe run there would
    hash a daemon source that includes somebody's half-finished edit and record a PASS for a program
    that is on no branch and in nobody's build.

    IT NO LONGER NEEDS A SECOND FOLDER TO DO THAT. Until 2026-09-27 this pointed at a permanent
    `C:\C_AGENT_BUILDER-reprove` worktree, and refused to run when that path was missing - so deleting
    a directory silently disarmed the schedule. Two changes:

      - Deciding needs no checkout at all. Both the BPF source and the recorded evidence are read out
        of origin/main with `git show`, so -CheckOnly touches nothing and cannot destroy an answer
        while asking a question. That happened on 2026-09-25: a -CheckOnly run reset away a passing
        last-hop the operator had recorded minutes earlier.
      - Proving runs here, in this repository. One repository on disk, and no second checkout that can
        go missing and disarm the schedule without saying so.

    It does NOT commit the evidence. A scheduled task that pushes to main unattended is a scheduled
    task that can publish a claim nobody read. The evidence lands in the repository's own evidence
    directory, uncommitted, and the log says so; landing it on main is a person's act.

.PARAMETER Repo
    The repository to fetch, decide from, and prove in. Defaults to the one this script sits in.

.PARAMETER LogPath
    Appended to on every run, whether or not anything was proven.

.PARAMETER Force
    Re-prove even when the hashes agree. For testing this script, and for the case where the
    evidence is suspect rather than stale.

#>
[CmdletBinding()]
param(
    [string]$Repo,
    [string]$LogPath = "$env:LOCALAPPDATA\SPLAT\reprove.log",
    [switch]$Force,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

# Resolved here rather than as a parameter default: $PSScriptRoot is not populated while the param
# block is being evaluated, so the default silently became an empty path and Split-Path threw before
# the script had said anything about what it was doing.
if ([string]::IsNullOrWhiteSpace($Repo)) {
    $Repo = Split-Path -Parent $PSScriptRoot
}

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

if (-not (Test-Path (Join-Path $Repo '.git'))) {
    Fail "$Repo is not a git repository."
}

$evidenceRelative = 'native/splat-agent/evidence/daemon-probe.json'
$sourceRelative = 'native/splat-agent/src/bpf/lease_lsm.bpf.c'

# ------------------------------------------------------------------------------------------------
# Never while a proof is already in flight. A re-proof stops the installed service and brings up a
# root daemon: starting a second one on top of the first would leave the operator's daemon down and
# the first run's `finally` never reached. An operator running it by hand and a schedule firing on
# the hour is not a hypothetical - it is the first hour this task exists.
# ------------------------------------------------------------------------------------------------
$inFlight = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'reprove-substrate\.ps1' })
if ($inFlight.Count -gt 0) {
    Write-Line "skipped  a re-proof is already running (pid $($inFlight.ProcessId -join ', ')); this run does nothing."
    exit 0
}

& git -C $Repo fetch --quiet origin
if ($LASTEXITCODE -ne 0) { Fail 'git fetch origin failed; the proof would run against an unknown revision.' }

$revision = (& git -C $Repo rev-parse --short origin/main).Trim()

# ------------------------------------------------------------------------------------------------
# Decide from origin/main, reading nothing off anybody's working tree.
#
# `git show` takes both the source and the evidence straight out of the commit, so the comparison is
# between what SHIPS and what was PROVEN - never between what somebody has half-written and what was
# proven. It also means -CheckOnly opens no checkout, resets nothing and cannot destroy an answer
# while asking a question, which is what happened on 2026-09-25.
# ------------------------------------------------------------------------------------------------
# Hashed from the blob itself, written out by git rather than reconstructed here: cmd's redirection
# copies the bytes through untouched, where Set-Content would re-encode them and PowerShell 5.1 has no
# utf8NoBOM to stop it. A changed byte is a changed hash, and this hash decides whether a claim stands.
$tempSource = Join-Path ([System.IO.Path]::GetTempPath()) ("splat-bpf-" + [guid]::NewGuid().ToString('N') + '.c')
try {
    & cmd /c "git -C ""$Repo"" cat-file blob origin/main:$sourceRelative > ""$tempSource"""
    if (-not (Test-Path $tempSource)) { Fail "could not read $sourceRelative out of origin/main." }
    $treeHash = (Get-FileHash -Path $tempSource -Algorithm SHA256).Hash.ToLowerInvariant()
} finally {
    Remove-Item $tempSource -Force -ErrorAction SilentlyContinue
}

$recordedHash = $null
$recordedAt = 'never'
$evidenceJson = & git -C $Repo show "origin/main:$evidenceRelative" 2>$null
if ($LASTEXITCODE -eq 0 -and $evidenceJson) {
    try {
        $json = ($evidenceJson -join "`n") | ConvertFrom-Json
        $recordedHash = ($json.bpf_source_sha256).ToLowerInvariant()
        $recordedAt = $json.recorded_utc
    } catch {
        Write-Line "the evidence on origin/main could not be read as JSON; treating the proof as expired."
    }
} else {
    Write-Line "no daemon-probe.json on origin/main; treating the proof as expired."
}

if ($recordedHash -eq $treeHash -and -not $Force) {
    Write-Line "current  $revision  bpf $($treeHash.Substring(0,12))  proven $recordedAt - nothing to do."
    exit 0
}

$verdict = "expired  {0}  ships bpf {1}  evidence bpf {2} ({3})" -f
    $revision,
    $treeHash.Substring(0, 12),
    $(if ($recordedHash) { $recordedHash.Substring(0, 12) } else { 'none' }),
    $recordedAt

if ($CheckOnly) {
    Write-Line "$verdict - CheckOnly, so nothing was built, stopped, proven or checked out."
    exit 2
}

# ------------------------------------------------------------------------------------------------
# The proof runs HERE, in this repository.
#
# It used to run in a second permanent checkout so a probe could never hash a source carrying
# somebody's half-finished edit. That is not worth a second folder: the comparison above already reads
# origin/main rather than the working tree, so an expired verdict is about what SHIPS whatever happens
# to be sitting uncommitted here.
#
# What that costs, stated rather than hidden: if the working tree holds edits to the daemon or the BPF
# source, reprove-substrate.ps1 builds and proves THOSE, and the evidence it records will carry their
# hash - which will not match origin/main and will read as expired on the next run. So a re-proof is
# worth running from a clean tree, and the run below says so when it is not.
# ------------------------------------------------------------------------------------------------
$dirty = @(& git -C $Repo status --porcelain --untracked-files=no -- 'native/splat-agent' 'src')
if ($dirty.Count -gt 0) {
    Write-Line "WARNING  the working tree holds $($dirty.Count) uncommitted change(s) under native/splat-agent or src;"
    Write-Line "         what gets proven is the tree as it stands, not origin/main. Commit or stash first if"
    Write-Line "         the evidence is meant to describe what ships."
}

Write-Line "$verdict - re-proving in $Repo."

& powershell -ExecutionPolicy Bypass -File (Join-Path $Repo 'packagingeprove-substrate.ps1')
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Line "PASS     $revision - evidence is in $Repo. It is NOT committed: review it, then commit and push it to main."
} else {
    Write-Line "FAILED   $revision - reprove-substrate.ps1 exited $code. Standing evidence was not overwritten; look for *.INCOMPLETE.json beside it."
}

exit $code
