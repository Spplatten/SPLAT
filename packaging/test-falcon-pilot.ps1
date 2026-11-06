# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
    [string]$DotNetPath=(Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'),
    [string]$PythonPath='python',
    [string]$ResultsDirectory
)
$ErrorActionPreference='Stop'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in a param() default under -File.
if (-not $ResultsDirectory) { $ResultsDirectory=Join-Path $PSScriptRoot ('..\private\falcon-local-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')) }
$repoRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (Test-Path -LiteralPath $ResultsDirectory) { throw 'Use a new results directory; existing evidence is never overwritten.' }
$sdkVersion=& $DotNetPath --version
if ($LASTEXITCODE -ne 0 -or $sdkVersion -notmatch '^10\.') { throw 'A .NET 10 SDK is required.' }
$python=(Get-Command $PythonPath -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
New-Item -ItemType Directory -Path $ResultsDirectory | Out-Null
$results=(Resolve-Path -LiteralPath $ResultsDirectory).Path
function Run-Gate([string]$Name,[string]$Executable,[string[]]$Arguments) {
    # Python unittest writes successful summaries to stderr. Preserve that output without
    # treating PowerShell 5.1's NativeCommandError wrapper as the process exit status.
    $ErrorActionPreference='Continue'
    & $Executable @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $results ($Name + '.txt')) | Out-Host
    $code=$LASTEXITCODE
    if ($code -ne 0) { throw "$Name failed with exit code $code; no PASS manifest written." }
}
function Count-Result([string]$Name,[string]$Pattern) {
    $match=[regex]::Match([IO.File]::ReadAllText((Join-Path $results ($Name + '.txt'))),$Pattern)
    if (-not $match.Success) { throw "Missing test summary in $Name." }
    return [int]$match.Groups[1].Value
}
function Digest([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
Push-Location $repoRoot
try {
    Run-Gate 'build' $DotNetPath @('build','src/splat-alert-sidecar/splat-alert-sidecar.csproj','-c','Release','-m:1','-p:UseSharedCompilation=false')
    $assembly=Join-Path $repoRoot 'src/splat-alert-sidecar/bin/Release/net10.0/splat-alert-sidecar.dll'
    Run-Gate 'sidecar' $DotNetPath @($assembly,'--self-test')
    Run-Gate 'witness-contract' $python @('-I','native/experiments/alert-cancellation/test_witness.py')
    Run-Gate 'witness-wire' $DotNetPath @($assembly,'--self-test-witness-wire',$python,(Join-Path $repoRoot 'native/experiments/alert-cancellation/test_witness.py'))
    Run-Gate 'offline-audit' $python @('-I','native/splat-agent/validation/test_audit_gaps.py')
    Run-Gate 'python-syntax' $python @('-I','-m','py_compile','native/experiments/alert-cancellation/witness.py','native/experiments/alert-cancellation/workload_fixture.py','native/experiments/alert-cancellation/native_witness_run.py')
    $sources=[ordered]@{}
    $sourcePaths=@(Get-ChildItem -LiteralPath 'src/splat-alert-sidecar' -File | Where-Object { $_.Extension -in '.cs','.csproj' })
    $sourcePaths+=@(Get-ChildItem -LiteralPath 'native/experiments/alert-cancellation' -Filter '*.py' -File)
    $sourcePaths+=@(Get-Item 'src/Directory.Build.props','packaging/test-falcon-pilot.ps1','native/splat-agent/validation/test_audit_gaps.py')
    foreach ($file in ($sourcePaths | Sort-Object FullName)) { $sources[$file.FullName.Substring($repoRoot.Length+1).Replace('\','/')]=Digest $file.FullName }
    $logs=[ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $results -Filter '*.txt' -File | Sort-Object Name)) { $logs[$file.Name]=Digest $file.FullName }
    $head=& git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify evidence base commit.' }
    $manifest=[ordered]@{
        schema=1; recordedUtc=[DateTime]::UtcNow.ToString('o'); baseCommit=$head
        status='PASS_LOCAL_GATES_ONLY'; sdk=$sdkVersion; assemblySha256=(Digest $assembly)
        sidecarChecks=(Count-Result 'sidecar' 'PASS (\d+) checks:')
        registrarChecks=(Count-Result 'sidecar' 'PASS (\d+) registrar checks;')
        proofPilotChecks=(Count-Result 'sidecar' 'PASS (\d+) cancellation-proof/pilot checks;')
        witnessContractTests=(Count-Result 'witness-contract' 'Ran (\d+) tests?')
        realProcessWireChecks=(Count-Result 'witness-wire' 'PASS (\d+) witness wire checks;')
        offlineAuditTests=(Count-Result 'offline-audit' 'Ran (\d+) tests?')
        nativePidfdCgroupExecution='NOT_RUN'; liveFalconPilot='NOT_RUN'; focusedVSTest='NOT_RUN'
        scope='Real RSA, SQLite and C#/Python process pipes; injected kernel observations; no native or vendor proof.'
        sourceSha256ExactWorktree=$sources; logSha256=$logs
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $results 'verification.json') -Encoding UTF8
    Write-Output "PASS local gates; evidence: $results"
} finally { Pop-Location }
