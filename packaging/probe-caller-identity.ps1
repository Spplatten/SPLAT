#requires -Version 5.1
<#
.SYNOPSIS
Records WSL registration and optional loopback observations under the current Windows identity.
.EXAMPLE
.\packaging\probe-caller-identity.ps1 -Mode Owner -Distro SplatProbe -OutputPath C:\evidence\owner-before.json
.EXAMPLE
.\packaging\probe-caller-identity.ps1 -Mode Operator -Distro Ubuntu -OwnerEvidence C:\evidence\owner-before.json -OutputPath C:\evidence\operator.json
.NOTES
Provision a disposable distro under a separate non-admin account before Owner mode. Keep it alive
and repeat Owner mode afterwards; an unavailable owner distro is not an isolation result.
LoopbackPort and LoopbackMarker require caller-identity-listener.c running inside that distro on
both 50051 and the otherwise-unused control port. Compile with cc -O2 -Wall -Wextra -Werror;
run the binary as: serve PORT SPLAT_IDENTITY_PROBE_<32-lowercase-hex-digits>.
Verify it inside the guest with: check PORT MARKER. The fixture expires after eight minutes.
A TCP connection alone does not identify the listener; require the same marker in owner controls.
No mode proves daemon authorization or closes roadmap 2.4. Output files must be new.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Baseline', 'Owner', 'Operator')][string]$Mode,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$Distro = 'Ubuntu',
    [string]$OwnerEvidence,
    [ValidateRange(0, 65535)][int]$LoopbackPort = 0,
    [ValidatePattern('^SPLAT_IDENTITY_PROBE_[a-f0-9]{32}$')][string]$LoopbackMarker,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Invoke-WslObservation([string[]]$Arguments, [switch]$UnicodeOutput) {
    # Arguments come only from the fixed commands below and the validated distro name.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32\wsl.exe'
    $start.Arguments = $Arguments -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = if ($UnicodeOutput) { [Text.Encoding]::Unicode } else { [Text.Encoding]::UTF8 }
    $start.StandardErrorEncoding = $start.StandardOutputEncoding
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit(30000)
        if ($timedOut) {
            # Stop only this probe client; never shut down an operator's WSL VM.
            $process.Kill()
            if (-not $process.WaitForExit(3000)) { throw 'WSL probe client did not exit after cancellation.' }
        }
        # A surviving child can hold redirected pipes open after the client exits.
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 3000)) {
            throw 'WSL probe output did not close; no isolation verdict can be recorded.'
        }
        [pscustomobject]@{
            arguments = $Arguments
            exitCode = $process.ExitCode
            timedOut = $timedOut
            stdout = $stdout.GetAwaiter().GetResult().Replace([string][char]0, '').Trim()
            stderr = $stderr.GetAwaiter().GetResult().Replace([string][char]0, '').Trim()
        }
    } finally {
        $process.Dispose()
    }
}

function Test-RootControl($Observation) {
    return -not $Observation.timedOut -and $Observation.exitCode -eq 0 -and $Observation.stdout -eq '0'
}

function Invoke-LoopbackObservation([int]$Port, [string]$Marker) {
    $result = [ordered]@{ port = $Port; connected = $false; markerMatches = $false; reply = ''; error = $null }
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $connect.Wait(3000)) { throw 'Connect timed out.' }
        [void]$connect.GetAwaiter().GetResult()
        $result.connected = $true
        $stream = $client.GetStream()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $buffer = New-Object byte[] ($Marker.Length + 1)
        $count = 0
        while ($count -lt $buffer.Length) {
            # A different service can own this port; bound both response size and total read time.
            $remaining = 3000 - [int]$clock.ElapsedMilliseconds
            if ($remaining -le 0) { throw 'Read timed out.' }
            $stream.ReadTimeout = $remaining
            $read = $stream.Read($buffer, $count, $buffer.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
            $result.reply = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        }
        $result.markerMatches = $result.reply -ceq ($Marker + "`n")
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        $client.Dispose()
    }
    [pscustomobject]$result
}

if (($LoopbackPort -ne 0) -ne [bool]$LoopbackMarker) { throw 'LoopbackPort and LoopbackMarker must be supplied together.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$adminSid = 'S-1-5-32-544'
$groupRows = & (Join-Path $env:SystemRoot 'System32\whoami.exe') /groups /fo csv /nh
if ($LASTEXITCODE -ne 0) { throw 'Could not read the current token groups.' }
# WindowsIdentity.Groups omits deny-only groups; those still identify a filtered admin token.
$tokenGroups = @($groupRows | ConvertFrom-Csv -Header Name, Type, Sid, Attributes)
$directAdmin = $null
$localAccount = $false
try {
    $localAccount = $null -ne (Get-LocalUser -SID $identity.User -ErrorAction Stop)
    $directAdmin = @((Get-LocalGroupMember -SID $adminSid -ErrorAction Stop).SID.Value) -contains $identity.User.Value
} catch {
    # A restricted token can omit the Administrators SID. Unknown account membership is not proof
    # of a standard account; capture it separately from the current token's elevation.
}
$actor = [pscustomobject]@{
    name = $identity.Name
    sid = $identity.User.Value
    elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    administratorsSidInToken = @($tokenGroups.Sid) -contains $adminSid
    tokenGroups = $tokenGroups
    directAdministratorsMember = $directAdmin
    localAccount = $localAccount
}
$nonAdminObserved = $localAccount -and $directAdmin -eq $false -and -not $actor.elevated -and -not $actor.administratorsSidInToken
$outputFile = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $outputFile) { throw "Refusing to overwrite evidence: $outputFile" }
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($outputFile)))) {
    throw 'Create the evidence directory before running the probe.'
}

$owner = $null
if ($Mode -eq 'Operator') {
    if (-not $OwnerEvidence) { throw 'Operator mode requires the record captured under the distro owner account.' }
    $owner = Get-Content -Raw -LiteralPath $OwnerEvidence | ConvertFrom-Json
    $age = [DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($owner.recordedUtc)
    if ($owner.schema -ne 1 -or $owner.mode -ne 'Owner' -or $owner.verdict -ne 'OWNER_CONTROL_PASS' -or
        $owner.computer -ne $env:COMPUTERNAME -or $owner.actor.sid -eq $actor.sid -or
        $age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt 30 -or
        $owner.distro -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw 'Owner evidence must be a successful, distinct-principal control from this machine within 30 minutes.'
    }
    if ($owner.loopbackTest) {
        if ($owner.loopbackTest.marker -notmatch '^SPLAT_IDENTITY_PROBE_[a-f0-9]{32}$' -or
            $owner.loopbackTest.controlPort -lt 1 -or $owner.loopbackTest.controlPort -gt 65535) {
            throw 'Owner loopback fixture metadata is invalid.'
        }
        $LoopbackPort = [int]$owner.loopbackTest.controlPort
        $LoopbackMarker = $owner.loopbackTest.marker
    }
}

$listed = Invoke-WslObservation -Arguments @('--list', '--quiet') -UnicodeOutput
$root = Invoke-WslObservation -Arguments @('-d', $Distro, '-u', 'root', '-e', '/usr/bin/id', '-u')
$record = [ordered]@{
    schema = 1
    probeSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
    mode = $Mode
    recordedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    windowsVersion = [Environment]::OSVersion.VersionString
    wslVersion = Invoke-WslObservation -Arguments @('--version') -UnicodeOutput
    actor = $actor
    nonAdminAccountObserved = [bool]$nonAdminObserved
    distro = $Distro
    list = $listed
    ownDistroRootControl = $root
    verdict = 'INCOMPLETE'
    daemonReachability = 'NOT_MEASURED'
    callerAuthorization = 'NOT_MEASURED'
    roadmap24Closed = $false
}
if ($LoopbackPort) {
    # These listeners carry a public test marker, never the daemon token or a lease request.
    # A negative operator observation counts only with owner positive controls on the same port.
    $record.loopbackTest = [ordered]@{
        transportOnly = $true
        controlPort = $LoopbackPort
        marker = $LoopbackMarker
        observations = @(@(50051, $LoopbackPort) | Select-Object -Unique | ForEach-Object {
            Invoke-LoopbackObservation -Port $_ -Marker $LoopbackMarker
        })
    }
}
$controlPassed = $listed.exitCode -eq 0 -and -not $listed.timedOut -and (Test-RootControl $root)
$names = @($listed.stdout -split '\r?\n' | ForEach-Object { $_.Trim() })
if ($Mode -eq 'Baseline') {
    if ($controlPassed -and $names -contains $Distro) { $record.verdict = 'OWN_DISTRO_ROOT_REACHABLE' }
} elseif ($Mode -eq 'Owner') {
    if ($controlPassed -and $names -contains $Distro -and $nonAdminObserved) { $record.verdict = 'OWNER_CONTROL_PASS' }
} else {
    $target = Invoke-WslObservation -Arguments @('-d', $owner.distro, '-u', 'root', '-e', '/usr/bin/id', '-u')
    $record.ownerEvidenceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $OwnerEvidence).Hash.ToLowerInvariant()
    $record.ownerActor = $owner.actor
    $record.ownerRecordedUtc = $owner.recordedUtc
    $record.targetDistro = $owner.distro
    $record.targetListed = $names -contains $owner.distro
    $record.targetRootAttempt = $target
    # A timeout or a broken WSL installation is not isolation. Even this observed refusal covers
    # registration lookup only; it says nothing about TCP reachability or service authorization.
    $notRegistered = "$($target.stdout) $($target.stderr)" -match 'WSL_E_DISTRO_NOT_FOUND'
    if ($controlPassed -and -not $record.targetListed -and -not $target.timedOut -and
        $target.exitCode -ne 0 -and $notRegistered) {
        $record.verdict = 'OTHER_PRINCIPAL_DISTRO_NOT_REACHABLE'
    } elseif ($record.targetListed -or (Test-RootControl $target)) {
        # A same-name local registration also invalidates the experiment; do not call it a breach.
        $record.verdict = 'REACHABLE_OR_NAME_COLLISION_REQUIRES_INVESTIGATION'
    }
}
$json = $record | ConvertTo-Json -Depth 8
$stream = [IO.File]::Open($outputFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $stream.Write($bytes, 0, $bytes.Length)
} finally {
    $stream.Dispose()
}
$json
if ($record.verdict -eq 'INCOMPLETE') { exit 2 }
