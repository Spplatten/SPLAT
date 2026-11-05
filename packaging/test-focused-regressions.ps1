# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
    [string]$DotNetPath=(Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'),
    [string]$ResultsDirectory,
    [switch]$PreflightOnly
)
$ErrorActionPreference='Stop'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in a param() default under -File.
if (-not $ResultsDirectory) { $ResultsDirectory=Join-Path $PSScriptRoot '..\private\focused-regressions' }
$repoRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path -LiteralPath $DotNetPath -PathType Leaf)) { throw 'Supply the installed .NET 10 executable using -DotNetPath.' }
$sdkVersion=& $DotNetPath --version
if ($LASTEXITCODE -ne 0 -or $sdkVersion -notmatch '^10\.') { throw 'The focused gate requires .NET 10.' }
New-Item -ItemType Directory -Force -Path $ResultsDirectory | Out-Null
$results=(Resolve-Path -LiteralPath $ResultsDirectory).Path

# VSTest's parent/child protocol needs loopback TCP. A 10013 rejection is a prerequisite
# failure, not a failed test and not a slow machine. Do not hide it with a longer timeout,
# disabled security policy, a skipped test, or a custom assertion-only substitute for xUnit.
$listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,0)
$client=[System.Net.Sockets.TcpClient]::new()
try {
    $listener.Start()
    $connection=$client.ConnectAsync([System.Net.IPAddress]::Loopback,$listener.LocalEndpoint.Port)
    if (-not $connection.Wait(3000)) { throw 'Loopback TCP connection did not complete in 3 seconds.' }
    $peer=$listener.AcceptTcpClient()
    $peer.Dispose()
} catch {
    $failure=$_.Exception.GetBaseException()
    $diagnosis="BLOCKED before tests: loopback TCP preflight failed: $($failure.GetType().Name): $($failure.Message)"
    if ($failure -is [System.Net.Sockets.SocketException]) { $diagnosis+=" SocketErrorCode=$($failure.SocketErrorCode); NativeErrorCode=$($failure.NativeErrorCode)." }
    $diagnosis | Set-Content -LiteralPath (Join-Path $results 'preflight.txt') -Encoding UTF8
    throw "$diagnosis Run this gate in an authorized runner that permits the VSTest loopback connection. No test result was produced."
} finally { $client.Dispose(); $listener.Stop() }
'PASS loopback TCP prerequisite only; not a test result.' | Set-Content -LiteralPath (Join-Path $results 'preflight.txt') -Encoding UTF8
if ($PreflightOnly) { Write-Output 'PASS loopback prerequisite. No tests requested.'; return }

$project=Join-Path $repoRoot 'tests\MissionController.Tests\MissionController.Tests.csproj'
# Windows PowerShell 5.1 wraps every stderr line of a redirected native command in an error record,
# which 'Stop' makes terminating before the exit code is read. The exit code is the verdict here.
$ErrorActionPreference='Continue'
& $DotNetPath build $project -c Debug -m:1 -p:UseSharedCompilation=false 2>&1 | Tee-Object -FilePath (Join-Path $results 'build.txt')
if ($LASTEXITCODE -ne 0) { throw 'Test project build failed.' }
$filter='FullyQualifiedName~DocumentationDriftTests|FullyQualifiedName~SiemTransportInvariantTests|FullyQualifiedName~WslLeasedExecutorWireTests|FullyQualifiedName~SensorNetworkContainmentTests'
& $DotNetPath test $project -c Debug --no-build --filter $filter --diag (Join-Path $results 'vstest.log') --logger 'trx;LogFileName=focused.trx' --results-directory $results 2>&1 | Tee-Object -FilePath (Join-Path $results 'tests.txt')
if ($LASTEXITCODE -ne 0) { throw 'Focused regression gate failed or aborted. Inspect tests.txt, focused.trx and vstest host diagnostics.' }
Write-Output 'PASS focused VSTest regressions.'
