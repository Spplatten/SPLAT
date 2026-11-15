# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries LLC. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
<#
.SYNOPSIS
    The Lite guest's release measurements as one resumable run on a clean machine: installer,
    console import, enforcement, the kernel proof inside the imported guest, restart, sleep,
    reboot, upgrade, unmount, uninstall and deliberate guest removal.

.DESCRIPTION
    docs/LITE-GUEST.md, "Remaining release measurements", lists what stand-ins cannot establish.
    This script measures those on the machine it runs on and writes one evidence file.

    It measures; it does not drive. The installer refuses a silent run, and the Lite import is
    reachable only from the console's Kernel Lease page, both on purpose: each is a change a
    person reviews. So at five points the script stops, names the buttons, and waits for Enter.
    Everything it then records is read from WSL, the guest and the installed package, never from
    what the operator says happened.

    Run it in the desktop session of the machine under test, not over SSH: the console needs an
    interactive logon. Re-run the same command to resume; a stage that passed is not repeated,
    a stage that failed is. The reboot stage ends the run with exit 3 and resumes after sign-in.

    It changes this machine in four ways, each announced first: it stops and restarts the
    guest's splat-agent unit for the kernel proof, it runs `wsl --shutdown` in the restart stage
    (every distribution stops), it writes one sentinel file in the guest, and in the last stage
    it unregisters the Lite guest after the operator types its name.

    Exit 0 only when every stage passed. The evidence file says INCOMPLETE otherwise, and always
    carries the list of what this run does not measure.

.PARAMETER Installer
    SPLAT-Community-<version>-Setup.exe, with its .sha256 file beside it.

.PARAMETER UpgradeInstaller
    A later package for the upgrade stage. Without it the same installer is run over the top,
    and the evidence records that as a reinstall, which is a weaker measurement.

.PARAMETER CrateDirectory
    A copy of native\splat-agent holding probe-daemon.sh and src\bpf\lease_lsm.bpf.c.

.PARAMETER RunDirectory
    Where stage records and the evidence go. Kept outside the SPLAT data root so the removal
    stage can tell SPLAT's leftovers from this script's.

.PARAMETER Stage
    Run one stage again, whatever its recorded verdict.

.PARAMETER Plan
    List the stages and their recorded verdicts. Changes nothing.

.PARAMETER SkipSleep
    Record the sleep stage as SKIPPED. The run then cannot be PASS.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\prove-lite-guest-release.ps1 -Installer .\SPLAT-Community-0.2.0-Setup.exe
#>
[CmdletBinding()]
param(
    [string]$Installer,
    [string]$UpgradeInstaller,
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'Platten Industries\SPLAT Community'),
    [string]$CrateDirectory,
    [string]$RunDirectory = (Join-Path $env:LOCALAPPDATA 'SPLAT-proof\lite-guest-release'),
    [ValidatePattern('^127\.0\.0\.1:\d{1,5}$')][string]$Listen = '127.0.0.1:50051',
    [ValidateSet('preflight', 'install', 'import', 'enforce', 'kernel-proof', 'restart', 'sleep', 'reboot',
        'upgrade', 'unmount', 'uninstall', 'remove-guest')][string]$Stage,
    [switch]$Plan,
    [switch]$SkipSleep
)

$ErrorActionPreference = 'Stop'
# Not a parameter default: Windows PowerShell 5.1 leaves $PSScriptRoot empty while binding them.
if (-not $CrateDirectory) { $CrateDirectory = Join-Path $PSScriptRoot '..\native\splat-agent' }
# Without this wsl.exe answers in UTF-16 and every name read from it carries NULs.
$env:WSL_UTF8 = '1'
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stageNames = @('preflight', 'install', 'import', 'enforce', 'kernel-proof', 'restart', 'sleep', 'reboot',
    'upgrade', 'unmount', 'uninstall', 'remove-guest')
# Named in the evidence so a PASS cannot be read as covering them.
$notMeasured = @(
    'A configured managed service with a non-administrator operator.',
    'Recovery from a failed or interrupted import.',
    'A changed ownership marker being refused, as observed through the console.',
    'A lease executed from the console or splat-mcp; the kernel proof drives the installed daemon directly.',
    'Publisher authentication: the Authenticode status is recorded, not required.',
    'Completeness of the guest source bundle and relinking materials.'
)

# The same derivation as BundledWslGuest: the data root the console resolves, then a name from it.
$dataRoot = if ($env:SPLAT_DATA_DIR) { $env:SPLAT_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'SPLAT' }
$dataRoot = [IO.Path]::GetFullPath($dataRoot).TrimEnd('\')
$sha = [Security.Cryptography.SHA256]::Create()
$suffix = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataRoot.ToUpperInvariant()))) -replace '-', '').Substring(0, 12).ToLowerInvariant()
$distro = "SPLAT-Lite-$suffix"
$stateDirectory = Join-Path $dataRoot 'lite-guest'
$receiptPath = Join-Path $stateDirectory 'import.json'
$storageDirectory = Join-Path $stateDirectory 'rootfs'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FE65C0A1-120A-4DFD-B251-CF9533C0BEE0}_is1'

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-StagePath([string]$Name) {
    Join-Path $RunDirectory ('stage-{0:00}-{1}.json' -f ([array]::IndexOf($stageNames, $Name) + 1), $Name)
}

function Read-Json([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    return $null
}

function Write-Json([string]$Path, $Value) {
    # The account, profile and machine names never leave this machine in an evidence file.
    $text = $Value | ConvertTo-Json -Depth 8
    $text = $text.Replace($env:USERPROFILE.Replace('\', '\\'), '%USERPROFILE%').Replace($env:COMPUTERNAME, '%COMPUTERNAME%')
    $text = [regex]::Replace($text, '\b' + [regex]::Escape($env:USERNAME) + '\b', '%USERNAME%', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    [IO.File]::WriteAllText($Path, $text + "`n", $utf8)
}

function Get-Distributions {
    $names = @(& $wsl --list --quiet)
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($names | ForEach-Object { $_.Replace([string][char]0, '').Trim() } | Where-Object { $_ })
}

function Get-DefaultDistribution {
    $lines = @(& $wsl --list --verbose)
    if ($LASTEXITCODE -ne 0) { return '' }
    foreach ($line in $lines) {
        if ($line.Replace([string][char]0, '') -match '^\*\s+(\S+)') { return $Matches[1] }
    }
    return ''
}

function Invoke-Guest([string]$Script, [switch]$AsUser) {
    # From a file, not `sh -c`: Windows PowerShell 5.1 does not escape quotes in a native argument.
    $file = Join-Path ([IO.Path]::GetTempPath()) ('splat-lite-proof-' + [guid]::NewGuid().ToString('N') + '.sh')
    [IO.File]::WriteAllText($file, ("exec 2>&1`n" + $Script).Replace("`r`n", "`n"), $utf8)
    try {
        $guestFile = (& $wsl -d $distro -e wslpath -a $file | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $guestFile) { return [pscustomobject]@{ ExitCode = 255; Output = "the guest could not map $file" } }
        $user = @('-u', 'root')
        if ($AsUser) { $user = @() }
        $output = (& $wsl -d $distro @user -e sh $guestFile | Out-String).Trim()
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
}

function Get-GuestPath([string]$WindowsPath) {
    $guest = (& $wsl -d $distro -e wslpath -a $WindowsPath | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $guest -or $guest.Contains("'")) { throw "The guest cannot map $WindowsPath." }
    return $guest
}

function Test-PortAnswers {
    $address, $port = $Listen -split ':', 2
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($address, [int]$port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(1000)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Dispose() }
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-Operator([string[]]$Lines) {
    Write-Host ''
    $Lines | ForEach-Object { Write-Host "   $_" -ForegroundColor Yellow }
    $null = Read-Host '   Press Enter when that is done'
}

$script:checks = $null
$script:facts = $null
function Check([string]$Name, [bool]$Pass, [string]$Detail = '') {
    $script:checks.Add([ordered]@{ name = $Name; pass = $Pass; detail = $Detail })
    $mark = if ($Pass) { 'ok  ' } else { 'FAIL' }
    Write-Host ("   {0} {1}{2}" -f $mark, $Name, $(if ($Detail) { " - $Detail" } else { '' }))
}
function Note([string]$Name, $Value) {
    # Windows PowerShell 5.1 cannot serialise an array that arrived wrapped from a pipeline.
    if ($Value -is [array]) { $Value = [string[]]@($Value) }
    $script:facts[$Name] = $Value
}

function Get-Receipt { Read-Json $receiptPath }

# The guest-side half of every later stage: the registration, the marker and the retained file
# must all still be the ones the import stage recorded.
function Check-GuestIntact([switch]$ExpectDaemon) {
    $baseline = Read-Json (Join-Path $RunDirectory 'baseline.json')
    $receipt = Get-Receipt
    Check 'guest still registered' ((Get-Distributions) -contains $distro)
    Check 'receipt identity unchanged' ($receipt -and $receipt.Identity -eq $baseline.identity)
    $marker = (Invoke-Guest 'cat /etc/splat/guest.id').Output
    Check 'ownership marker matches the receipt' ($receipt -and $marker -eq $receipt.Identity)
    $kept = (Invoke-Guest 'cat /var/lib/splat-proof-sentinel').Output
    Check 'data written before this stage is retained' ($kept -eq $baseline.sentinel)
    Check 'default distribution unchanged' ((Get-DefaultDistribution) -eq $baseline.defaultDistribution)
    if ($ExpectDaemon) {
        $active = Wait-Until { (Invoke-Guest 'systemctl is-active splat-agent').Output -eq 'active' } 90
        Check 'splat-agent unit active' $active
        Check "daemon answers at $Listen" (Wait-Until { Test-PortAnswers } 30)
    }
}

function Test-BpfOnBootLine {
    $cmdline = (Invoke-Guest 'cat /proc/cmdline').Output
    $lsm = @($cmdline -split '\s+' | Where-Object { $_.StartsWith('lsm=') } | ForEach-Object { $_.Substring(4) -split ',' })
    return ($lsm -contains 'bpf')
}

function Get-Manifest { Read-Json (Join-Path $InstallDirectory 'PACKAGE-MANIFEST.json') }

function Test-InstalledPackage {
    # The verifier the package ships, run over the directory the installer wrote, in a child so its
    # throw is an exit code here and not the end of this run.
    $verifier = Join-Path $InstallDirectory 'packaging\verify-community-package.ps1'
    if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) { return $false }
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $verifier -PackagePath $InstallDirectory | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Invoke-Setup([string]$Path) {
    Write-Host "   starting $([IO.Path]::GetFileName($Path)); complete its wizard. It asks for elevation."
    $process = Start-Process -FilePath $Path -Wait -PassThru
    return $process.ExitCode
}

$stageBody = @{}

$stageBody['preflight'] = {
    $os = Get-CimInstance Win32_OperatingSystem
    Note 'windows' "$($os.Caption) $($os.Version)"
    Note 'wslVersion' @(& $wsl --version | ForEach-Object { $_.Replace([string][char]0, '').Trim() } | Where-Object { $_ } | Select-Object -First 2)
    $distributions = @(Get-Distributions)
    Note 'distributionsBefore' $distributions
    $groups = (& (Join-Path $env:SystemRoot 'System32\whoami.exe') /groups /fo csv /nh) -join "`n"
    Check 'interactive desktop logon' ($groups -match 'S-1-5-4"') 'the console cannot be driven from a network logon such as SSH'
    & $wsl --status | Out-Null
    Check 'WSL is installed' ($LASTEXITCODE -eq 0)
    Check 'no Lite guest registered' ($distributions -notcontains $distro) $distro
    Check 'no Lite guest state in the data root' (-not (Test-Path -LiteralPath $stateDirectory)) $stateDirectory
    Check 'SPLAT is not installed' (-not (Test-Path -LiteralPath $InstallDirectory) -and -not (Test-Path -LiteralPath $uninstallKey))
    # Every distribution shares one network namespace, so another guest's daemon on this port
    # would answer for the Lite guest and the proof would be of the wrong program.
    Check "nothing answers at $Listen" (-not (Test-PortAnswers)) 'if this fails, another distribution runs splat-agent: disable that unit there first'
    Check 'installer present' ([bool]$Installer -and (Test-Path -LiteralPath $Installer -PathType Leaf))
    if ($Installer -and (Test-Path -LiteralPath $Installer -PathType Leaf)) {
        $sumFile = "$Installer.sha256"
        $expected = if (Test-Path -LiteralPath $sumFile) { ((Get-Content -LiteralPath $sumFile -TotalCount 1) -split '\s+')[0] } else { '' }
        $actual = Get-Sha256 $Installer
        Note 'installerSha256' $actual
        Note 'installerAuthenticode' ([string](Get-AuthenticodeSignature -LiteralPath $Installer).Status)
        Check 'installer matches its .sha256 file' ($expected -eq $actual)
    }
    foreach ($probeInput in @('probe-daemon.sh', 'src\bpf\lease_lsm.bpf.c')) {
        Check "probe input present: $probeInput" (Test-Path -LiteralPath (Join-Path $CrateDirectory $probeInput) -PathType Leaf)
    }
    $wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
    # A machine that already carries the lsm= line never exercises the console writing it.
    Note 'bootLineAlreadyConfigured' ((Test-Path -LiteralPath $wslconfig) -and [bool](Select-String -LiteralPath $wslconfig -Pattern 'lsm=.*bpf' -Quiet))
    Write-Json (Join-Path $RunDirectory 'baseline.json') ([ordered]@{
        defaultDistribution = Get-DefaultDistribution; distributions = $distributions; distro = $distro
        identity = $null; sentinel = $null })
}

$stageBody['install'] = {
    Check 'installer exited 0' ((Invoke-Setup $Installer) -eq 0)
    Check 'installed package verifies against its own records' (Test-InstalledPackage)
    $manifest = Get-Manifest
    if ($manifest) {
        foreach ($name in @('version', 'sourceReferenceCommit', 'rootfsSha256', 'daemonSha256', 'bpfSourceReferenceSha256', 'installerSignature')) { Note $name $manifest.$name }
        Check 'package carries the Lite guest build records' ([bool]$manifest.guestBuild -and [bool]$manifest.rootfsIncluded)
        $build = Read-Json (Join-Path $InstallDirectory 'Linux\Guest\BUILD.json')
        $archive = Join-Path $InstallDirectory 'Linux\rootfs.tar.xz'
        $hash = if (Test-Path -LiteralPath $archive) { Get-Sha256 $archive } else { '' }
        Check 'installed archive is the one BUILD.json and the manifest name' ($build -and $hash -eq $build.sha256 -and $hash -eq $manifest.rootfsSha256) $hash
    }
    else { Check 'package manifest readable' $false }
    Check 'installation alone registered no guest' ((Get-Distributions) -notcontains $distro)
    Check 'default distribution unchanged' ((Get-DefaultDistribution) -eq (Read-Json (Join-Path $RunDirectory 'baseline.json')).defaultDistribution)
}

$stageBody['import'] = {
    Wait-Operator @(
        'Start "SPLAT Community Test" from the Start menu and open the Kernel Lease page.',
        'Press Plan mount, read the import plan, then press "Import Lite guest: apply the plan below".',
        'Wait for "Guest imported". Leave the console open.')
    Check 'Lite guest registered under the derived name' ((Get-Distributions) -contains $distro) $distro
    $receipt = Get-Receipt
    Check 'receipt is ready and names this guest' ($receipt -and $receipt.Phase -eq 'ready' -and $receipt.Distribution -eq $distro -and $receipt.Identity -match '^[0-9a-fA-F]{32}$')
    Check 'ownership marker matches the receipt' ($receipt -and (Invoke-Guest 'cat /etc/splat/guest.id').Output -eq $receipt.Identity)
    $conf = (Invoke-Guest 'cat /etc/wsl.conf').Output
    Check 'guest boots systemd with restricted Windows-drive mounts' ($conf -match 'systemd=true' -and $conf -match 'umask=077')
    Check 'PID 1 is systemd' ((Invoke-Guest 'ps -p 1 -o comm=').Output -eq 'systemd')
    $release = (Invoke-Guest '. /etc/os-release; echo "$ID $VERSION_ID"').Output
    Check 'guest is Debian 13' ($release -eq 'debian 13') $release
    Check 'storage is under the data root' (Test-Path -LiteralPath (Join-Path $storageDirectory 'ext4.vhdx'))
    Check 'import installed no daemon' ((Invoke-Guest 'test -e /opt/splat/splat-agent; echo $?').Output -eq '1')
    $baseline = Read-Json (Join-Path $RunDirectory 'baseline.json')
    Check 'default distribution unchanged' ((Get-DefaultDistribution) -eq $baseline.defaultDistribution)
    # One file the guest did not ship with, so upgrade and restart can show data is retained.
    $sentinel = [guid]::NewGuid().ToString('N')
    $written = Invoke-Guest "umask 077; printf '%s\n' '$sentinel' > /var/lib/splat-proof-sentinel"
    Check 'sentinel written in the guest' ($written.ExitCode -eq 0)
    if ($receipt) { $baseline.identity = $receipt.Identity }
    $baseline.sentinel = $sentinel
    Write-Json (Join-Path $RunDirectory 'baseline.json') $baseline
}

$stageBody['enforce'] = {
    Wait-Operator @(
        'In the console: Plan mount, read the plan, then apply it.',
        'If it hands you "wsl --shutdown", run that, reopen the console, and plan and apply again.',
        'Stop when Check reports the substrate enforcing. Leave the console open.')
    Check-GuestIntact -ExpectDaemon
    Check 'bpf is on the guest boot line' (Test-BpfOnBootLine)
    $manifest = Get-Manifest
    $installed = ((Invoke-Guest 'sha256sum /opt/splat/splat-agent').Output -split '\s+')[0]
    Check 'guest daemon is the packaged binary' ($manifest -and $installed -eq $manifest.daemonSha256) $installed
    Check 'unit enabled for the next boot' ((Invoke-Guest 'systemctl is-enabled splat-agent').Output -eq 'enabled')
    # Metadata only. The token's content is the daemon's and the console's, never this script's.
    Check 'token is root-owned 0600' ((Invoke-Guest "stat -c '%a %U' /etc/splat/agent.token").Output -eq '600 root')
    Check 'mount manifest recorded' (Test-Path -LiteralPath (Join-Path $stateDirectory 'mount-manifest.json'))
    Note 'journalSaysEnforcementLive' ((Invoke-Guest "journalctl -u splat-agent -b --no-pager -o cat | grep -c 'kernel enforcement is live'").Output)
}

$stageBody['kernel-proof'] = {
    # LF copies: the probe hashes the BPF source it finds, and a CRLF checkout would name a
    # program nobody shipped. Staged in the run directory so the record sits beside its inputs.
    $probeStage = Join-Path $RunDirectory 'probe-stage'
    $evidence = Join-Path $RunDirectory 'probe-evidence'
    Remove-Item -LiteralPath $probeStage, $evidence -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path (Join-Path $probeStage 'src\bpf'), $evidence -Force | Out-Null
    foreach ($probeInput in @('probe-daemon.sh', 'src\bpf\lease_lsm.bpf.c')) {
        $text = [IO.File]::ReadAllText((Join-Path $CrateDirectory $probeInput)).Replace("`r`n", "`n")
        [IO.File]::WriteAllText((Join-Path $probeStage $probeInput), $text, $utf8)
    }
    $sourceHash = Get-Sha256 (Join-Path $probeStage 'src\bpf\lease_lsm.bpf.c')
    Note 'bpfSourceSha256' $sourceHash
    $canonical = Read-Json (Join-Path $CrateDirectory 'evidence\daemon-probe.json')
    if ($canonical) { Note 'bpfSourceMatchesCanonicalEvidence' ($canonical.bpf_source_sha256 -eq $sourceHash) }
    $started = [DateTime]::UtcNow
    Write-Host '   stopping the installed unit; the probe must own the only daemon'
    $stop = Invoke-Guest 'systemctl stop splat-agent; echo "RC=$?"'
    try {
        Check 'installed unit stopped' ($stop.Output -match 'RC=0')
        Check "$Listen is free for the probe" (Wait-Until { -not (Test-PortAnswers) } 15)
        # The installed binary, not a build: this stage proves the daemon the package delivered.
        $probe = Invoke-Guest (@'
mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf
cd '__STAGE__'
SPLAT_PROBE_DAEMON=/opt/splat/splat-agent SPLAT_EVIDENCE_DIR='__EVIDENCE__' bash probe-daemon.sh '__LISTEN__'
'@).Replace('__STAGE__', (Get-GuestPath $probeStage)).Replace('__EVIDENCE__', (Get-GuestPath $evidence)).Replace('__LISTEN__', $Listen)
        [IO.File]::WriteAllText((Join-Path $RunDirectory 'probe-output.txt'), $probe.Output + "`n", $utf8)
        $probe.Output -split "`n" | Select-Object -Last 25 | ForEach-Object { Write-Host "   $_" }
    }
    finally {
        $start = Invoke-Guest 'systemctl start splat-agent; echo "RC=$?"'
        Check 'installed unit started again' ($start.Output -match 'RC=0')
    }
    $record = Read-Json (Join-Path $evidence 'daemon-probe.json')
    Check 'probe wrote its PASS record' ([bool]$record) 'an INCOMPLETE record, if any, is in probe-evidence'
    if ($record) {
        $recorded = [datetime]::Parse($record.recorded_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
        Check 'record written by this run' ($recorded -ge $started.AddMinutes(-1))
        Check 'verdict PASS' ($record.verdict -eq 'PASS') ([string]$record.verdict)
        Check 'record names the staged kernel program' ([string]$record.bpf_source_sha256 -eq $sourceHash)
        Note 'probeResults' @($record.results).Count
    }
    Check 'no INCOMPLETE record from this run' (-not (Test-Path -LiteralPath (Join-Path $evidence 'daemon-probe.INCOMPLETE.json')))
    Check "daemon answers at $Listen after the proof" (Wait-Until { Test-PortAnswers } 30)
}

$stageBody['restart'] = {
    & $wsl --terminate $distro | Out-Null
    Check 'guest terminated' ($LASTEXITCODE -eq 0)
    Check-GuestIntact -ExpectDaemon
    Wait-Operator @('Next is "wsl --shutdown": EVERY WSL distribution on this machine stops.', 'Close the console and anything else using WSL first.')
    & $wsl --shutdown | Out-Null
    Check 'WSL shut down' ($LASTEXITCODE -eq 0)
    Check-GuestIntact -ExpectDaemon
    Check 'bpf is on the guest boot line after the restart' (Test-BpfOnBootLine)
}

$stageBody['sleep'] = {
    $started = Get-Date
    Wait-Operator @('Put this machine to sleep (Start, Power, Sleep), wake it, and sign in again.')
    # The operator's word is not the measurement; the resume the system logged is.
    $resumed = 0
    foreach ($filter in @(@{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $started },
            @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 107, 507; StartTime = $started })) {
        try { $resumed += @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop).Count } catch { }
    }
    Check 'Windows logged a resume during this stage' ($resumed -gt 0)
    Check-GuestIntact -ExpectDaemon
}

$stageBody['reboot'] = {
    $pendingPath = Join-Path $RunDirectory 'reboot-pending.json'
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $pending = Read-Json $pendingPath
    if (-not $pending) {
        Write-Json $pendingPath ([ordered]@{ bootBefore = $boot })
        return 'PENDING'
    }
    Check 'Windows restarted since the stage began' ($boot -ne $pending.bootBefore) $boot
    # Deliberately before the console is opened: the first WSL call after boot must be enough.
    Check-GuestIntact -ExpectDaemon
    Check 'bpf is on the guest boot line after the reboot' (Test-BpfOnBootLine)
    Remove-Item -LiteralPath $pendingPath -Force
}

$stageBody['upgrade'] = {
    $package = if ($UpgradeInstaller) { $UpgradeInstaller } else { $Installer }
    Check 'upgrade installer present' ([bool]$package -and (Test-Path -LiteralPath $package -PathType Leaf))
    if (-not $package -or -not (Test-Path -LiteralPath $package -PathType Leaf)) { return }
    $before = Get-Manifest
    $receiptBefore = Get-Sha256 $receiptPath
    Wait-Operator @('Close the SPLAT console. The installer does not close it for you.')
    Check 'console closed' (-not (Get-Process -Name 'MissionController.UI' -ErrorAction SilentlyContinue))
    Check 'installer exited 0' ((Invoke-Setup $package) -eq 0)
    Check 'installed package verifies against its own records' (Test-InstalledPackage)
    $after = Get-Manifest
    $kind = if ($after -and $before -and $after.sourceReferenceCommit -ne $before.sourceReferenceCommit) { 'NEWER_PACKAGE' } else { 'REINSTALL_SAME_PACKAGE' }
    Note 'kind' $kind
    Note 'versionBefore' $before.version
    Note 'versionAfter' $after.version
    Check 'receipt file untouched by the installer' ((Get-Sha256 $receiptPath) -eq $receiptBefore)
    Check-GuestIntact -ExpectDaemon
    $daemon = { ((Invoke-Guest 'sha256sum /opt/splat/splat-agent').Output -split '\s+')[0] }
    $remount = ((& $daemon) -ne $after.daemonSha256)
    Note 'daemonNeededRemount' $remount
    if ($remount) {
        Wait-Operator @('The package carries a different daemon than the guest runs.', 'Open the console, Plan mount, apply it, and wait for Check to report enforcing.')
    }
    Check 'guest daemon is the upgraded package''s binary' ((& $daemon) -eq $after.daemonSha256)
    Check "daemon answers at $Listen" (Wait-Until { Test-PortAnswers } 30)
}

$stageBody['unmount'] = {
    Wait-Operator @('In the console: Plan unmount, read the plan, apply it. Then close the console.')
    Check 'unit removed' ((Invoke-Guest 'test -e /etc/systemd/system/splat-agent.service; echo $?').Output -eq '1')
    Check 'daemon binary removed' ((Invoke-Guest 'test -e /opt/splat/splat-agent; echo $?').Output -eq '1')
    Check "nothing answers at $Listen" (Wait-Until { -not (Test-PortAnswers) } 15)
    Check-GuestIntact
    Note 'mountManifestRemains' (Test-Path -LiteralPath (Join-Path $stateDirectory 'mount-manifest.json'))
    $wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
    Note 'bootLineRemains' ((Test-Path -LiteralPath $wslconfig) -and [bool](Select-String -LiteralPath $wslconfig -Pattern 'lsm=.*bpf' -Quiet))
}

$stageBody['uninstall'] = {
    $uninstaller = @(Get-ChildItem -LiteralPath $InstallDirectory -Filter 'unins*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)
    Check 'uninstaller present' ($uninstaller.Count -eq 1)
    if ($uninstaller.Count -ne 1) { return }
    Check 'console closed' (-not (Get-Process -Name 'MissionController.UI' -ErrorAction SilentlyContinue))
    Check 'uninstaller exited 0' ((Invoke-Setup $uninstaller[0].FullName) -eq 0)
    # Inno's uninstaller re-launches itself from %TEMP% and the first process returns early.
    $gone = Wait-Until { -not (Test-Path -LiteralPath $InstallDirectory) } 60
    $left = @()
    if (-not $gone) { $left = @(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($InstallDirectory.Length + 1) }) }
    Note 'filesLeftInInstallDirectory' $left
    Check 'install directory removed' $gone
    Check 'uninstall registration removed' (-not (Test-Path -LiteralPath $uninstallKey))
    # Documented behaviour, measured: the installer never unregisters the guest or deletes its data.
    Check-GuestIntact
    Check 'data root retained' (Test-Path -LiteralPath $dataRoot)
}

$stageBody['remove-guest'] = {
    $receipt = Get-Receipt
    $owned = $receipt -and (Invoke-Guest 'cat /etc/splat/guest.id').Output -eq $receipt.Identity
    Check 'guest is the one this run imported' ([bool]$owned)
    if (-not $owned) { return }
    Write-Host ''
    Write-Host "   This unregisters $distro and deletes its disk at $storageDirectory," -ForegroundColor Yellow
    Write-Host "   then deletes $stateDirectory. It cannot be undone. Nothing else is removed." -ForegroundColor Yellow
    $typed = Read-Host "   Type the distribution name to proceed"
    Check 'operator confirmed the removal by name' ($typed -ceq $distro)
    if ($typed -cne $distro) { return }
    & $wsl --unregister $distro | Out-Null
    Check 'guest unregistered' ($LASTEXITCODE -eq 0 -and (Get-Distributions) -notcontains $distro)
    Check 'guest disk deleted' (-not (Test-Path -LiteralPath (Join-Path $storageDirectory 'ext4.vhdx')))
    $item = Get-Item -LiteralPath $stateDirectory -Force
    if ($item.Name -eq 'lite-guest' -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    }
    Check 'Lite guest state removed from the data root' (-not (Test-Path -LiteralPath $stateDirectory))
    $baseline = Read-Json (Join-Path $RunDirectory 'baseline.json')
    $now = @(Get-Distributions)
    Check 'every other distribution is still registered' (-not (Compare-Object @($baseline.distributions) $now))
    Check 'default distribution unchanged' ((Get-DefaultDistribution) -eq $baseline.defaultDistribution)
    Note 'dataRootEntriesLeft' @(Get-ChildItem -LiteralPath $dataRoot -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

function Write-Evidence {
    $records = @($stageNames | ForEach-Object { Read-Json (Get-StagePath $_) } | Where-Object { $_ })
    $passed = @($records | Where-Object { $_.verdict -eq 'PASS' }).Count
    $verdict = if ($passed -eq $stageNames.Count) { 'PASS' } else { 'INCOMPLETE' }
    $path = Join-Path $RunDirectory 'lite-guest-release.json'
    Write-Json $path ([ordered]@{
        schema = 1; kind = 'lite-guest-release'; verdict = $verdict; recordedUtc = [DateTime]::UtcNow.ToString('o')
        distribution = $distro; stagesPassed = $passed; stagesTotal = $stageNames.Count
        stagesMissing = @($stageNames | Where-Object { $name = $_; -not ($records | Where-Object { $_.stage -eq $name -and $_.verdict -eq 'PASS' }) })
        notMeasured = $notMeasured; stages = $records })
    return [pscustomobject]@{ Verdict = $verdict; Path = $path }
}

if ($Plan) {
    Write-Host "Lite guest release proof - nothing is changed. Guest: $distro  Run directory: $RunDirectory"
    foreach ($name in $stageNames) {
        $record = Read-Json (Get-StagePath $name)
        Write-Host ("   {0,-13} {1}" -f $name, $(if ($record) { $record.verdict } else { 'not run' }))
    }
    Write-Host 'Not measured by this run:'
    $notMeasured | ForEach-Object { Write-Host "   - $_" }
    return
}

New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
foreach ($name in $stageNames) {
    if ($Stage -and $name -ne $Stage) { continue }
    $existing = Read-Json (Get-StagePath $name)
    if (-not $Stage -and $existing -and $existing.verdict -in @('PASS', 'SKIPPED')) { continue }
    Write-Host "== $name" -ForegroundColor Cyan
    $script:checks = New-Object System.Collections.Generic.List[object]
    $script:facts = [ordered]@{}
    $started = [DateTime]::UtcNow.ToString('o')
    $outcome = $null
    if ($name -eq 'sleep' -and $SkipSleep) { $outcome = 'SKIPPED' }
    else {
        # A stage that throws is a failed stage with its reason recorded, not a lost run.
        try { $outcome = & $stageBody[$name] }
        catch { Check 'stage completed without an error' $false $_.Exception.Message }
    }
    if ($outcome -eq 'PENDING') {
        Write-Host '   Restart Windows now, sign in, and run the same command again.' -ForegroundColor Yellow
        exit 3
    }
    $failed = @($script:checks | Where-Object { -not $_.pass })
    $verdict = if ($outcome -eq 'SKIPPED') { 'SKIPPED' } elseif ($failed.Count -or -not $script:checks.Count) { 'FAIL' } else { 'PASS' }
    Write-Json (Get-StagePath $name) ([ordered]@{ stage = $name; verdict = $verdict; startedUtc = $started
        recordedUtc = [DateTime]::UtcNow.ToString('o'); facts = $script:facts; checks = $script:checks.ToArray() })
    if ($verdict -eq 'FAIL') {
        $evidence = Write-Evidence
        Write-Host "STOPPED at $name. Fix what failed and run the same command; passed stages are kept." -ForegroundColor Yellow
        Write-Host "   evidence so far: $($evidence.Path)"
        exit 1
    }
}

$evidence = Write-Evidence
Write-Host ''
Write-Host "LITE GUEST RELEASE PROOF: $($evidence.Verdict)" -ForegroundColor $(if ($evidence.Verdict -eq 'PASS') { 'Green' } else { 'Yellow' })
Write-Host "   $($evidence.Path)"
Write-Host "   probe record: $(Join-Path $RunDirectory 'probe-evidence\daemon-probe.json')"
if ($evidence.Verdict -ne 'PASS') { exit 1 }
exit 0
