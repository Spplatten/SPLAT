<#
.SYNOPSIS
    Produces the exact body to publish as the Field Guide artifact, and records the hash afterwards.

.DESCRIPTION
    The Field Guide has three copies. Two live here and are checked against the code by the suite.
    The third is a published page outside this repository - the one a non-engineer actually reads -
    and DocumentationDriftTests.ThePublishedFieldGuide_IsTheSourceAsItStandsToday holds it by
    recording the source's hash in docs\SPLAT-Field-Guide.published.

    That check has one weakness, and this script exists to close it: nothing local can prove the
    republish happened, so the cheapest way to make the build go green is to edit the hash and skip
    the publish - which leaves the page wrong and now looking verified. People take that shortcut
    when the honest path is tedious, and the honest path was "cut these line numbers by hand,
    and whatever you do don't use a regex for <head, because it also matches <header class="hero">
    and an earlier republish lost the title placard that way for months."

    So the slice is done here, once, correctly. The two halves stay separate on purpose:

        .\build-field-guide-artifact.ps1                 # writes the body to publish, prints the hash
        .\build-field-guide-artifact.ps1 -RecordPublished # writes that hash into the .published file

    Run the second only after the page is actually live. Recording without publishing is the one
    failure this design cannot detect, and splitting the switches is what makes it a deliberate act
    rather than an accident of convenience.

    Markers are matched as whole lines, never as substrings. `<header class="hero">` is not the line
    `<body>`, so the accident that destroyed the placard cannot recur here.
#>
[CmdletBinding()]
param(
    [switch]$RecordPublished,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Join-Path $root 'docs\SPLAT-Field-Guide.html'
$record = Join-Path $root 'docs\SPLAT-Field-Guide.published'
if (-not $OutputPath) { $OutputPath = Join-Path $root 'dist\field-guide-artifact.html' }

if (-not (Test-Path $source)) { Write-Error "No source at $source"; exit 1 }

# Read as lines, so the slice is positional and the wrapper cannot be matched by accident.
$lines = [System.IO.File]::ReadAllLines($source)

function Find-SoleLine([string[]]$all, [string]$exact) {
    $hits = @(0..($all.Length - 1) | Where-Object { $all[$_].Trim() -ceq $exact })
    if ($hits.Count -ne 1) {
        Write-Error "Expected exactly one line '$exact' in SPLAT-Field-Guide.html, found $($hits.Count). The wrapper changed shape; fix this script rather than guessing."
        exit 1
    }
    return $hits[0]
}

$headOpen   = Find-SoleLine $lines '<head>'
$headClose  = Find-SoleLine $lines '</head>'
$bodyOpen   = Find-SoleLine $lines '<body>'
$bodyClose  = Find-SoleLine $lines '</body>'

if (-not ($headOpen -lt $headClose -and $headClose -lt $bodyOpen -and $bodyOpen -lt $bodyClose)) {
    Write-Error 'The wrapper markers are out of order. Refusing to slice a document this script no longer understands.'
    exit 1
}

# Everything inside <head> except the metas the artifact host supplies for us, then everything
# inside <body>. Trailing blank lines are dropped so the output is stable across edits above them.
$head = @($lines[($headOpen + 1)..($headClose - 1)] | Where-Object { $_ -notmatch '^\s*<meta\b' })
$body = @($lines[($bodyOpen + 1)..($bodyClose - 1)])
while ($head.Count -gt 0 -and [string]::IsNullOrWhiteSpace($head[-1])) { $head = $head[0..($head.Count - 2)] }
while ($body.Count -gt 0 -and [string]::IsNullOrWhiteSpace($body[-1])) { $body = $body[0..($body.Count - 2)] }

# The three things whose loss is invisible on a published page until someone looks at it.
$slice = ($head + '' + $body) -join "`n"
foreach ($required in @('<title>', '<header class="hero">', '<div class="wrap">')) {
    if ($slice -notlike "*$required*") {
        Write-Error "The sliced body is missing $required. Publishing it would damage the live page."
        exit 1
    }
}
if ($slice -match '(?m)^\s*(<!doctype|</?html|</?head>|</?body>)') {
    Write-Error 'The sliced body still carries wrapper tags. The artifact host supplies its own.'
    exit 1
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $slice + "`n", (New-Object System.Text.UTF8Encoding($false)))

# Hashed the way the test hashes it: normalised text, not raw bytes. This repository is checked out
# with autocrlf on, so a byte hash would differ between the shared tree and a worktree and the check
# would be reporting which machine ran it.
# SHA256.HashData is .NET 5+; this script runs under Windows PowerShell 5.1 on .NET Framework.
$normalised = [System.IO.File]::ReadAllText($source) -replace "`r`n", "`n"
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $sha = [System.BitConverter]::ToString(
        $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalised))
    ).Replace('-', '').ToLowerInvariant()
} finally {
    $sha256.Dispose()
}

if ($RecordPublished) {
    if (-not (Test-Path $record)) { Write-Error "No record file at $record"; exit 1 }
    $text = [System.IO.File]::ReadAllText($record)
    if ($text -notmatch '(?m)^sha256\s+[0-9a-f]{64}\s*$') {
        Write-Error 'The record file has no sha256 line in the form the test reads. Fix it by hand.'
        exit 1
    }
    # [ \t]* rather than \s*: \s crosses the line break, so the replacement would eat the file's
    # trailing newline and every run would leave a slightly different file than the last.
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $text = [regex]::Replace($text, '(?m)^sha256([ \t]+)[0-9a-f]{64}[ \t]*$', "sha256`${1}$sha")
    $text = [regex]::Replace($text, '(?m)^published([ \t]+)\d{4}-\d{2}-\d{2}[ \t]*$', "published`${1}$today")
    [System.IO.File]::WriteAllText($record, $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Recorded sha256 $sha (published $today)."
    Write-Host 'This asserts the live page matches the source. If it does not, you have just hidden that.'
    exit 0
}

Write-Host "Body to publish : $OutputPath  ($($slice.Length) chars, $(($head + $body).Count) lines)"
Write-Host "Source sha256   : $sha"
Write-Host ''
Write-Host 'Next: publish that file to'
Write-Host '  https://claude.ai/code/artifact/18992308-da75-4782-87b8-20b6ba7b4311'
Write-Host 'and only once it is live, run this script again with -RecordPublished.'
