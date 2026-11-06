# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param([switch]$Commit, [string]$Branch='codex/falcon-pilot-closure')
$ErrorActionPreference='Stop'
$repoRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifestPath='packaging/falcon-closure-files.json'
Push-Location $repoRoot
try {
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $head=& git rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $manifest.baseCommit) { throw 'HEAD changed; review and regenerate the handoff before committing.' }
    $staged=@(& git diff --cached --name-only)
    if ($LASTEXITCODE -ne 0 -or $staged.Count -ne 0) { throw 'The index must be empty; existing staged work is never included or reset.' }
    $paths=@()
    foreach ($entry in $manifest.files) {
        $relative=[string]$entry.path
        if ($relative -notmatch '^(src/splat-alert-sidecar/|native/experiments/alert-cancellation/|docs/|packaging/)' -or
            $relative -match '(^|/)\.\.(/|$)|[\x00-\x1f:*?\\]') { throw 'Invalid handoff path.' }
        $full=[IO.Path]::GetFullPath((Join-Path $repoRoot $relative))
        if (-not $full.StartsWith($repoRoot + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Path outside checkout.' }
        $actual=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $entry.sha256) { throw "Reviewed bytes changed: $relative. Review before regenerating the manifest." }
        $paths+=$relative
    }
    if (($paths | Sort-Object -Unique).Count -ne $paths.Count) { throw 'Duplicate handoff paths.' }
    $paths+=$manifestPath
    Write-Output "Validated $($paths.Count) explicit paths at $head. Live B/C proof remains unproven."
    if (-not $Commit) { Write-Output 'Preview only. Use -Commit in an authorized shell to create the branch and local commit.'; return }
    & git check-ref-format --branch $Branch | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not $Branch.StartsWith('codex/')) { throw 'Supply a new codex/ branch name.' }
    & git switch -c $Branch
    if ($LASTEXITCODE -ne 0) { throw 'Branch creation failed; no files staged.' }
    # Explicit paths only. Historical TRX records are ignored globally and need -f individually.
    $ordinary=@($paths | Where-Object { -not $_.EndsWith('.trx') })
    & git add -- @ordinary
    if ($LASTEXITCODE -ne 0) { throw 'Staging failed; inspect the index. No commit or reset attempted.' }
    foreach ($path in ($paths | Where-Object { $_.EndsWith('.trx') })) {
        & git add -f -- $path
        if ($LASTEXITCODE -ne 0) { throw 'Historical evidence staging failed; inspect the index.' }
    }
    # --only limits the commit even if a peer stages other work after the empty-index check.
    $message=Join-Path ([IO.Path]::GetTempPath()) ('splat-closure-' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        [IO.File]::WriteAllText($message,"Add admission registrar and cancellation pilot verification harness`n`nPreserve Option A evidence and add B/C proof tooling with pinned receipts, held native identities, LF framing and local regression evidence. Native and vendor pilot execution remain unproven.`n")
        & git commit --only -F $message -- @paths
        if ($LASTEXITCODE -ne 0) { throw 'Commit failed; retain the branch/index for inspection.' }
    } finally { if (Test-Path -LiteralPath $message) { Remove-Item -LiteralPath $message } }
    Write-Output 'Local commit created. Nothing was pushed.'
} finally { Pop-Location }
