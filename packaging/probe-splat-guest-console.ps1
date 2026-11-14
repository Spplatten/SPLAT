# SPDX-License-Identifier: AGPL-3.0-only
# Rebuilds and measures the console/managed guest stand-ins. Does not import or boot a real guest.
#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$DotNet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe",
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug',
    [string]$ResultsDirectory,
    [string]$EvidencePath = "$PSScriptRoot\evidence\lite-guest-console.json"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$DotNet = (Resolve-Path -LiteralPath $DotNet -ErrorAction Stop).Path
if (-not $ResultsDirectory) {
    $ResultsDirectory = Join-Path $root ('artifacts\verification\lite-guest-' + [Guid]::NewGuid().ToString('N'))
}
$ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
if (Test-Path -LiteralPath $ResultsDirectory) { throw 'Use a new results directory; earlier measurements are retained.' }
New-Item -ItemType Directory -Path $ResultsDirectory | Out-Null
$project = Join-Path $root 'tests\MissionController.Tests\MissionController.Tests.csproj'
$groups = @('BundledWslGuestTests', 'ManagedSubstrateCheckTests', 'SplatGuestPackagingTests')
$filter = ($groups | ForEach-Object { 'FullyQualifiedName~' + $_ }) -join '|'

function Get-SourceHash([string]$RelativePath) {
    $source = [IO.File]::ReadAllText((Join-Path $root $RelativePath)).Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Invoke-DotNet([string[]]$Arguments) {
    # Windows PowerShell wraps native stderr in ErrorRecords; the native exit status remains decisive.
    $before = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $DotNet @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $script:probeExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $before }
}

$sourceHashes = [ordered]@{}
foreach ($path in @(
    'src/MissionController.Host/BundledWslGuest.cs', 'src/MissionController.Host/SubstrateLifecycle.cs',
    'src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs',
    'src/MissionController.Infrastructure.Linux/WslLeasedExecutor.Receipts.cs',
    'src/MissionController.Infrastructure.Linux/WslSubstrateHealthChecker.cs',
    'src/MissionController.Infrastructure.Linux/WslAgentToken.cs',
    'src/splat-mcp/ManagedBridgeHost.cs',
    'src/MissionController.UI/App.xaml.cs', 'src/MissionController.UI/KernelLeaseViewModel.cs',
    'tests/MissionController.Tests/BundledWslGuestTests.cs',
    'tests/MissionController.Tests/ManagedSubstrateCheckTests.cs',
    'tests/MissionController.Tests/SplatGuestPackagingTests.cs',
    'packaging/splat-guest-package.ps1', 'packaging/test-splat-guest-package.ps1',
    'packaging/verify-community-package.ps1', 'packaging/probe-splat-guest-console.ps1')) {
    $sourceHashes[$path] = Get-SourceHash $path
}

Invoke-DotNet @('build', $project, '-c', $Configuration, '-m:1', '-p:UseSharedCompilation=false', '--no-restore')
if ($probeExitCode -ne 0) { throw "Test build failed ($probeExitCode); no new evidence was written." }

$assemblies = [ordered]@{}
$assemblyDirectory = Join-Path $root "tests\MissionController.Tests\bin\$Configuration\net10.0-windows"
foreach ($name in @('MissionController.Tests.dll', 'MissionController.Host.dll',
    'MissionController.Infrastructure.Linux.dll', 'splat-mcp.dll')) {
    $assemblies[$name] = (Get-FileHash -LiteralPath (Join-Path $assemblyDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}

Invoke-DotNet @('test', $project, '-c', $Configuration, '--no-build', '--filter', $filter,
    '--logger', 'trx;LogFileName=lite-guest.trx', '--results-directory', $ResultsDirectory,
    '--', ('RunConfiguration.DotNetHostPath=' + $DotNet.Replace('\', '/')))
$testExitCode = $probeExitCode
$trxPath = Join-Path $ResultsDirectory 'lite-guest.trx'
if (-not (Test-Path -LiteralPath $trxPath)) { throw 'The test runner produced no TRX; no new evidence was written.' }
$trx = [xml][IO.File]::ReadAllText($trxPath)
$results = @($trx.TestRun.Results.UnitTestResult)
if (-not $results.Count -or [int]$trx.TestRun.ResultSummary.Counters.total -ne $results.Count) {
    throw 'The TRX is empty or its result count disagrees; no evidence was written.'
}
$byGroup = [ordered]@{}
foreach ($group in $groups) {
    $groupResults = @($results | Where-Object { $_.testName.StartsWith("MissionController.Tests.$group.") })
    if (-not $groupResults.Count) { throw "The test runner omitted $group; no evidence was written." }
    $byGroup[$group] = [ordered]@{
        passed = @($groupResults | Where-Object outcome -eq 'Passed').Count
        failed = @($groupResults | Where-Object outcome -eq 'Failed').Count
        notExecuted = @($groupResults | Where-Object outcome -notin @('Passed', 'Failed')).Count
    }
}
# Refuse evidence about a moving input or a DLL replaced by another build during this run.
foreach ($path in $sourceHashes.Keys) {
    if ((Get-SourceHash $path) -ne $sourceHashes[$path]) { throw "Source changed during the measurement: $path" }
}
foreach ($name in $assemblies.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $assemblyDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $assemblies[$name]) {
        throw "Assembly changed during the measurement: $name"
    }
}
$passed = @($results | Where-Object outcome -eq 'Passed').Count
$complete = $testExitCode -eq 0 -and $passed -eq $results.Count
$evidence = [ordered]@{
    schema = 2; recordedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    verdict = $(if ($complete) { 'PASS' } else { 'INCOMPLETE' })
    scope = 'Normal VSTest run of console ownership, managed health, and Windows PowerShell packaging tests; WSL and daemon stand-ins only'
    sourceHashEncoding = 'UTF-8 with LF line endings'; sourceSha256 = $sourceHashes
    testAssemblySha256 = $assemblies; buildExitCode = 0; testExitCode = $testExitCode
    resultSha256 = (Get-FileHash -LiteralPath $trxPath -Algorithm SHA256).Hash.ToLowerInvariant()
    checksPassed = $passed; checksFailed = @($results | Where-Object outcome -eq 'Failed').Count
    checksNotExecuted = @($results | Where-Object outcome -notin @('Passed', 'Failed')).Count
    groups = $byGroup
    results = @($results | Sort-Object testName | ForEach-Object {
        $entry = [ordered]@{ test = [string]$_.testName; outcome = [string]$_.outcome }
        if ($_.outcome -ne 'Passed') { $entry.error = [string]$_.Output.ErrorInfo.Message }
        $entry
    })
    realGuestImported = $false; kernelEnforcementProven = $false; cleanMachineTested = $false
    uiBuilt = $false; upgradeTested = $false; uninstallTested = $false; distributionReady = $false
}
$evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($evidenceFullPath)) -Force | Out-Null
[IO.File]::WriteAllText($evidenceFullPath, ($evidence | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "Evidence: $evidenceFullPath ($($evidence.verdict)); raw results: $trxPath"
if (-not $complete) { throw 'Targeted guest proof is INCOMPLETE; inspect the recorded failures. No deployment proof is implied.' }
