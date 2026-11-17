# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries LLC. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
<#
.SYNOPSIS
    The v1 proof run in one command: the hostname egress proxy, the local IPC hooks and private
    /tmp proven under root, on this PC and inside a freshly installed SPLAT Guest on a clean second
    machine, from an installer built and signed from this commit.

.DESCRIPTION
    Each stage writes a record to the run directory. Re-running the same command resumes: a stage
    that passed is not repeated, and a stage that failed is. Exit 0 only when every stage passed.

      1 preflight  This commit is the one proven: tracked tree clean, signing identity configured,
                   Inno Setup, the guest build, and the second machine reachable with no SPLAT
                   Community installed there.
      2 reprove    packaging\reprove-substrate.ps1 in this PC's default WSL distribution: a root
                   daemon built from this tree, probe-daemon.sh (sections 19c IPC, 19d egress proxy,
                   19e private /tmp included) and the last-hop probe. Rewrites the canonical
                   evidence, which is what turns DocumentationDriftTests green for this BPF source.
      3 client     build-client-dist.ps1, signed. It runs the whole suite and refuses a red tree.
      4 mcp        publish-splat-mcp.ps1, signed: splat-mcp.exe and the daemon the installer ships.
      5 installer  build-community-installer.ps1 with the SPLAT Guest build, signed; the Setup's
                   Authenticode status must read Valid.
      6 remote     On the second machine: its own Ubuntu splat-agent is disabled and WSL shut down,
                   so no foreign BPF program sits on the shared kernel; then
                   prove-lite-guest-release.ps1 runs in its desktop session. That script stops at
                   five points for a person to click in the installer and the console, by design,
                   so someone must be at that machine. Its kernel-proof stage runs probe-daemon.sh
                   against the daemon the installer put in the guest. If it asks for a reboot,
                   restart that machine and sign in; this run relaunches it when it is back.
      7 report     The remote records fetched back and checked: release PASS, Setup signed Valid,
                   the guest's probe PASS on this tree's BPF source with every 19c/19d/19e check
                   true. The guest's probe record is copied into native\splat-agent\evidence.

    It changes this PC (the installed splat-agent unit is stopped and restarted by reprove) and
    the second machine (an install, a guest import, a reboot, an uninstall, its Ubuntu unit
    disabled for the run and its enablement put back afterwards). Nothing is committed or pushed.

.PARAMETER RemoteHost
    The ssh host of the clean second machine, as named in ~/.ssh/config. Not defaulted, so the
    machine's name never lands in the repository.

.PARAMETER SigningMetadata
    The Azure Artifact Signing metadata.json. Defaults to SPLAT_SIGNING_METADATA.

.PARAMETER Stage
    Run one stage again, whatever its recorded verdict.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\run-v1-proof.ps1 -RemoteHost <host>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RemoteHost,
    [string]$SigningMetadata = $env:SPLAT_SIGNING_METADATA,
    [string]$GuestBuildDirectory,
    [string]$CompilerPath = (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    [string]$RemoteUbuntu = 'Ubuntu',
    [int]$RemoteTimeoutMinutes = 480,
    [ValidateSet('preflight', 'reprove', 'client', 'mcp', 'installer', 'remote', 'report')][string]$Stage
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $GuestBuildDirectory) { $GuestBuildDirectory = Join-Path $root 'dist\splat-guest\20261014T000000Z-r2' }
$crate = Join-Path $root 'native\splat-agent'
$bpfSource = Join-Path $crate 'src\bpf\lease_lsm.bpf.c'
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$scp = Join-Path $env:SystemRoot 'System32\OpenSSH\scp.exe'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stageNames = @('preflight', 'reprove', 'client', 'mcp', 'installer', 'remote', 'report')
# The checks the remote guest's probe must hold, beyond its own PASS: the three features of v1.
$v1Checks = @(
    'ipc_host_controls_work', 'ipc_same_lease_allowed', 'ipc_lease_to_host_refused', 'ipc_lease_to_lease_refused',
    'ipc_host_into_lease_refused', 'ipc_netlink_refused_in_lease', 'ipc_getaddrinfo_survives_netlink_refusal',
    'ipc_receipts_in_each_lease_session',
    'egress_host_control_reaches', 'egress_allowed_host_fetched', 'egress_unlisted_host_refused',
    'egress_direct_dial_refused', 'egress_peer_proxy_refused', 'egress_receipt_signed_lists_host',
    'tmp_lease_wrote_its_tmp', 'tmp_host_file_invisible_in_lease', 'tmp_lease_file_absent_on_host',
    'tmp_next_lease_starts_empty')

$commit = (& git -C $root rev-parse HEAD).Trim()
$RunDirectory = Join-Path $root ('dist\v1-proof\' + $commit.Substring(0, 12))
New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
$remoteDir = 'splat-v1-proof'
$taskName = 'SPLAT v1 proof'

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-StagePath([string]$Name) { Join-Path $RunDirectory ('stage-{0}-{1}.json' -f ([array]::IndexOf($stageNames, $Name) + 1), $Name) }
function Read-Json([string]$Path) { if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } }
function Check([string]$Name, [bool]$Pass, [string]$Detail = '') {
    $script:checks.Add([ordered]@{ check = $Name; pass = $Pass; detail = $Detail })
    Write-Host ('   [{0}] {1}{2}' -f $(if ($Pass) { 'ok' } else { 'FAIL' }), $Name, $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor $(if ($Pass) { 'Gray' } else { 'Red' })
}
function Note([string]$Name, $Value) { $script:facts[$Name] = $Value }

function Invoke-Child([string]$Script, [string[]]$Arguments) {
    # A separate Windows PowerShell, so a script that calls `exit` ends itself and not this run,
    # and so pwsh 7's module path never reaches the 5.1 packaging scripts.
    & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments
    return $LASTEXITCODE
}

function Invoke-Remote([string]$Script) {
    # EncodedCommand: nothing to quote through ssh and cmd. Kept short; files travel by scp, because
    # cmd cuts a command line past 8191 characters.
    $full = "`$ProgressPreference='SilentlyContinue'; `$env:WSL_UTF8='1'`n" + $Script
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($full))
    $previous = $ErrorActionPreference
    # Native stderr under Stop is a terminating error in 5.1; an unreachable host is an answer here.
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $ssh -o ConnectTimeout=10 -o BatchMode=yes $RemoteHost "powershell -NoProfile -NonInteractive -EncodedCommand $encoded" 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output.Trim() }
    }
    finally { $ErrorActionPreference = $previous }
}

function Send-Remote([string]$Local, [string]$Remote) {
    & $scp -q -o BatchMode=yes $Local "${RemoteHost}:$Remote"
    if ($LASTEXITCODE -ne 0) { throw "scp of $Local to the second machine failed" }
}

function Assert-SameCommit {
    $now = (& git -C $root rev-parse HEAD).Trim()
    if ($now -ne $commit) { throw "HEAD moved from $commit to $now during the run; start again from one commit" }
}

$stageBody = @{}

$stageBody['preflight'] = {
    Note 'commit' $commit
    Note 'bpfSourceSha256' (Get-Sha256 $bpfSource)
    $dirty = @(& git -C $root status --porcelain --untracked-files=no)
    Check 'tracked tree clean, so the proof names a commit' ($dirty.Count -eq 0) ($dirty -join '; ')
    Check 'signing metadata configured' ([bool]$SigningMetadata -and (Test-Path -LiteralPath $SigningMetadata -PathType Leaf)) 'set SPLAT_SIGNING_METADATA or pass -SigningMetadata'
    Check 'Azure CLI present for the signing sign-in' ([bool](Get-Command az -ErrorAction SilentlyContinue))
    Check 'Inno Setup compiler present' (Test-Path -LiteralPath $CompilerPath -PathType Leaf) $CompilerPath
    $build = Read-Json (Join-Path $GuestBuildDirectory 'BUILD.json')
    Check 'SPLAT Guest build present' ([bool]$build) $GuestBuildDirectory
    if ($build) { Note 'guestArchiveSha256' $build.sha256 }
    $probe = Invoke-Remote @'
$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FE65C0A1-120A-4DFD-B251-CF9533C0BEE0}_is1'
"REACHED installed=$([bool](Test-Path $key)) user=$([bool](Get-CimInstance Win32_ComputerSystem).UserName)"
'@
    Check 'second machine reachable over ssh' ($probe.Output -match 'REACHED') $probe.Output
    Check 'no SPLAT Community installed there: a clean install' ($probe.Output -match 'installed=False')
}

$stageBody['reprove'] = {
    Assert-SameCommit
    $code = Invoke-Child (Join-Path $PSScriptRoot 'reprove-substrate.ps1') @()
    Check 'reprove-substrate.ps1 exited 0 (both probes PASS on this BPF source)' ($code -eq 0) "exit $code"
    $record = Read-Json (Join-Path $crate 'evidence\daemon-probe.json')
    if ($record) {
        $missing = @($v1Checks | Where-Object { $record.results.$_ -ne $true })
        Check 'this PC: every v1 check held' ($missing.Count -eq 0) ($missing -join ', ')
    }
}

$stageBody['client'] = {
    Assert-SameCommit
    $env:SPLAT_SIGNING_METADATA = $SigningMetadata
    $code = Invoke-Child (Join-Path $PSScriptRoot 'build-client-dist.ps1') @('-OutputDir', (Join-Path $RunDirectory 'client'))
    Check 'build-client-dist.ps1 exited 0 (suite green, signed, self-test passed)' ($code -eq 0) "exit $code"
    $exe = Join-Path $RunDirectory 'client\Client\MissionController.UI.exe'
    if (Test-Path -LiteralPath $exe) { Check 'console signed Valid' ((Get-AuthenticodeSignature -LiteralPath $exe).Status -eq 'Valid') }
}

$stageBody['mcp'] = {
    Assert-SameCommit
    $env:SPLAT_SIGNING_METADATA = $SigningMetadata
    $out = Join-Path $RunDirectory 'mcp'
    $code = Invoke-Child (Join-Path $PSScriptRoot 'publish-splat-mcp.ps1') @('-OutputDir', $out)
    Check 'publish-splat-mcp.ps1 exited 0' ($code -eq 0) "exit $code"
    $exe = Join-Path $out 'splat-mcp.exe'
    if (Test-Path -LiteralPath $exe) {
        Check 'splat-mcp.exe signed Valid' ((Get-AuthenticodeSignature -LiteralPath $exe).Status -eq 'Valid')
        Note 'daemonSha256' (Get-Sha256 (Join-Path $out 'splat-agent'))
    }
}

$stageBody['installer'] = {
    Assert-SameCommit
    $env:SPLAT_SIGNING_METADATA = $SigningMetadata
    $mcp = Join-Path $RunDirectory 'mcp'
    $out = Join-Path $RunDirectory 'installer'
    # build-community-installer.ps1 refuses an existing output directory; a failed attempt leaves one.
    Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    $code = Invoke-Child (Join-Path $PSScriptRoot 'build-community-installer.ps1') @(
        '-WindowsPayload', (Join-Path $RunDirectory 'client\Client'),
        '-McpBinary', (Join-Path $mcp 'splat-mcp.exe'), '-DaemonBinary', (Join-Path $mcp 'splat-agent'),
        '-McpBuildManifest', (Join-Path $mcp 'MCP-BUILD-MANIFEST.json'),
        '-CompilerPath', $CompilerPath, '-OutputDir', $out, '-GuestBuildDirectory', $GuestBuildDirectory)
    Check 'build-community-installer.ps1 exited 0' ($code -eq 0) "exit $code"
    $setup = Get-ChildItem -LiteralPath $out -Filter 'SPLAT-Community-*-Setup.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    Check 'installer built' ([bool]$setup)
    if ($setup) {
        $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
        Check 'installer signed Valid' ($signature.Status -eq 'Valid') ([string]$signature.Status)
        Note 'installer' $setup.Name
        Note 'installerSha256' (Get-Sha256 $setup.FullName)
        Note 'signer' $(if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' })
    }
}

$stageBody['remote'] = {
    Assert-SameCommit
    $setup = Get-ChildItem -LiteralPath (Join-Path $RunDirectory 'installer') -Filter 'SPLAT-Community-*-Setup.exe' | Select-Object -First 1
    # Ubuntu's own splat-agent shares the WSL kernel with the guest under test: its pinned programs
    # would sit on the same hooks, and the probe would be measuring two daemons. Its enablement is
    # recorded once, so a resumed run never records the state this run itself made.
    $prep = Invoke-Remote (@'
New-Item -ItemType Directory -Path "$env:USERPROFILE\__DIR__\crate\src\bpf" -Force | Out-Null
$state = "$env:USERPROFILE\__DIR__\ubuntu-unit.txt"
$names = @(wsl.exe --list --quiet | ForEach-Object { $_.Replace([string][char]0, '').Trim() })
if ($names -contains '__UBUNTU__') {
    if (-not (Test-Path $state)) { (wsl.exe -d __UBUNTU__ -u root -e systemctl is-enabled splat-agent 2>$null | Out-String).Trim() | Set-Content $state }
    wsl.exe -d __UBUNTU__ -u root -e systemctl disable --now splat-agent 2>$null | Out-Null
} elseif (-not (Test-Path $state)) { 'absent' | Set-Content $state }
wsl.exe --shutdown
"PREPARED unit=$(Get-Content $state)"
'@).Replace('__DIR__', $remoteDir).Replace('__UBUNTU__', $RemoteUbuntu)
    Check 'second machine prepared: its Ubuntu unit off, WSL shut down' ($prep.Output -match 'PREPARED') $prep.Output

    $runner = Join-Path $RunDirectory 'runner.ps1'
    # Runs in the desktop session, in a window someone at that machine answers. A child process,
    # so the release script's own `exit` still lets this record the code it ended with.
    [IO.File]::WriteAllText($runner, @'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = Get-ChildItem $here -Filter 'SPLAT-Community-*-Setup.exe' | Select-Object -First 1
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'prove-lite-guest-release.ps1') -Installer $installer.FullName -CrateDirectory (Join-Path $here 'crate')
$code = $LASTEXITCODE
[IO.File]::WriteAllText((Join-Path $here 'exit.txt'), "$code")
Write-Host "SPLAT v1 proof: the release run ended with exit $code. This window can be closed."
'@, $utf8)
    Send-Remote $setup.FullName "$remoteDir/"
    Send-Remote "$($setup.FullName).sha256" "$remoteDir/"
    Send-Remote (Join-Path $PSScriptRoot 'prove-lite-guest-release.ps1') "$remoteDir/"
    Send-Remote $runner "$remoteDir/"
    Send-Remote (Join-Path $crate 'probe-daemon.sh') "$remoteDir/crate/"
    Send-Remote $bpfSource "$remoteDir/crate/src/bpf/"

    $launch = (@'
$dir = "$env:USERPROFILE\__DIR__"
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $user) { 'NO_CONSOLE_USER'; return }
Remove-Item "$dir\exit.txt" -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dir\runner.ps1`""
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName '__TASK__' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName '__TASK__'
"STARTED boot=$((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o'))"
'@).Replace('__DIR__', $remoteDir).Replace('__TASK__', $taskName)
    $poll = (@'
$file = "$env:USERPROFILE\__DIR__\exit.txt"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
$user = [bool](Get-CimInstance Win32_ComputerSystem).UserName
if (Test-Path $file) { "EXIT=$((Get-Content $file -Raw).Trim()) boot=$boot user=$user" } else { "RUNNING boot=$boot user=$user" }
'@).Replace('__DIR__', $remoteDir)

    $deadline = (Get-Date).AddMinutes($RemoteTimeoutMinutes)
    $exit = $null
    $lastBoot = $null
    $needsLaunch = $true
    while ((Get-Date) -lt $deadline) {
        if ($needsLaunch) {
            $started = Invoke-Remote $launch
            if ($started.Output -match 'STARTED boot=(\S+)') {
                $lastBoot = $Matches[1]
                $needsLaunch = $false
                Write-Host '   The release proof is open on the second machine. Someone there answers its prompts;' -ForegroundColor Yellow
                Write-Host '   this window waits and polls. Nothing is needed here.' -ForegroundColor Yellow
            } else {
                Write-Host "   waiting for a signed-in desktop on the second machine ($($started.Output))"
            }
        } else {
            $state = Invoke-Remote $poll
            if ($state.Output -match 'EXIT=(-?\d+) boot=(\S+)') {
                $exit = [int]$Matches[1]
                if ($exit -ne 3) { break }
                # The release script's reboot stage: wait for a new boot and a signed-in user, then go on.
                if ($Matches[2] -ne $lastBoot -and $state.Output -match 'user=True') {
                    Write-Host '   the second machine restarted; relaunching the release proof to resume it'
                    $needsLaunch = $true
                } elseif ($Matches[2] -eq $lastBoot) {
                    Write-Host '   the release proof asks for a restart: restart the second machine and sign in' -ForegroundColor Yellow
                }
            }
        }
        Start-Sleep -Seconds 20
    }
    Note 'releaseExitCode' $exit
    Check 'release proof finished on the second machine' ($null -ne $exit -and $exit -ne 3) "exit $exit"
    Check 'release proof exited 0' ($exit -eq 0) "exit $exit"

    # Fetched whatever the verdict: a failed run's records are what says why.
    $fetch = Invoke-Remote (@'
$dir = "$env:USERPROFILE\__DIR__"
$zip = "$dir\release-evidence.zip"
Remove-Item $zip -ErrorAction SilentlyContinue
Compress-Archive -Path "$env:LOCALAPPDATA\SPLAT-proof\lite-guest-release\*" -DestinationPath $zip
Unregister-ScheduledTask -TaskName '__TASK__' -Confirm:$false -ErrorAction SilentlyContinue
$state = Get-Content "$dir\ubuntu-unit.txt" -ErrorAction SilentlyContinue
if ($state -eq 'enabled') { wsl.exe -d __UBUNTU__ -u root -e systemctl enable splat-agent 2>$null | Out-Null }
"FETCHABLE unit=$state"
'@).Replace('__DIR__', $remoteDir).Replace('__TASK__', $taskName).Replace('__UBUNTU__', $RemoteUbuntu)
    Check 'release records packed; Ubuntu unit enablement put back' ($fetch.Output -match 'FETCHABLE') $fetch.Output
    $local = Join-Path $RunDirectory 'remote'
    Remove-Item -LiteralPath $local, "$local.zip" -Recurse -Force -ErrorAction SilentlyContinue
    & $scp -q -o BatchMode=yes "${RemoteHost}:$remoteDir/release-evidence.zip" "$local.zip"
    Check 'release records fetched' ($LASTEXITCODE -eq 0)
    if ($LASTEXITCODE -eq 0) { Expand-Archive -LiteralPath "$local.zip" -DestinationPath $local }
}

$stageBody['report'] = {
    $local = Join-Path $RunDirectory 'remote'
    $release = Read-Json (Join-Path $local 'lite-guest-release.json')
    Check 'release proof verdict PASS' ($release -and $release.verdict -eq 'PASS') ([string]$release.verdict)
    $preflight = Read-Json (Join-Path $local 'stage-01-preflight.json')
    $signature = if ($preflight) { [string]$preflight.facts.installerAuthenticode } else { '' }
    Check 'installer signature Valid on the second machine' ($signature -eq 'Valid') $signature
    $installed = Read-Json (Get-StagePath 'installer')
    Check 'the installer run there is the one built here' ($preflight -and $installed -and $preflight.facts.installerSha256 -eq $installed.facts.installerSha256)
    $record = Read-Json (Join-Path $local 'probe-evidence\daemon-probe.json')
    Check 'guest probe verdict PASS' ($record -and $record.verdict -eq 'PASS') ([string]$record.verdict)
    Check "guest probe ran this tree's BPF source" ($record -and $record.bpf_source_sha256 -eq (Get-Sha256 $bpfSource))
    if ($record) {
        $missing = @($v1Checks | Where-Object { $record.results.$_ -ne $true })
        Check 'guest: every v1 check held (19c IPC, 19d egress proxy, 19e private /tmp)' ($missing.Count -eq 0) ($missing -join ', ')
        if ($missing.Count -eq 0 -and $record.verdict -eq 'PASS') {
            $target = Join-Path $crate ('evidence\' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd') + '-splat-guest-release')
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $local 'probe-evidence\daemon-probe.json') -Destination $target -Force
            Copy-Item -LiteralPath (Join-Path $local 'lite-guest-release.json') -Destination $target -Force
            Note 'evidenceCopiedTo' $target
        }
    }
}

foreach ($name in $stageNames) {
    if ($Stage -and $name -ne $Stage) { continue }
    $existing = Read-Json (Get-StagePath $name)
    if (-not $Stage -and $existing -and $existing.verdict -eq 'PASS') { Write-Host "== $name (passed earlier, kept)"; continue }
    Write-Host "== $name" -ForegroundColor Cyan
    $script:checks = New-Object System.Collections.Generic.List[object]
    $script:facts = [ordered]@{}
    $started = [DateTime]::UtcNow.ToString('o')
    try { & $stageBody[$name] }
    catch { Check 'stage completed without an error' $false $_.Exception.Message }
    $failed = @($script:checks | Where-Object { -not $_.pass })
    $verdict = if ($failed.Count -or -not $script:checks.Count) { 'FAIL' } else { 'PASS' }
    $text = ([ordered]@{ stage = $name; verdict = $verdict; commit = $commit; startedUtc = $started
        recordedUtc = [DateTime]::UtcNow.ToString('o'); facts = $script:facts; checks = $script:checks.ToArray() } | ConvertTo-Json -Depth 6)
    [IO.File]::WriteAllText((Get-StagePath $name), $text + "`n", $utf8)
    if ($verdict -eq 'FAIL') {
        Write-Host "STOPPED at $name. Fix what failed and run the same command; passed stages are kept." -ForegroundColor Yellow
        Write-Host "   records: $RunDirectory"
        exit 1
    }
}
Write-Host ''
Write-Host "V1 PROOF RUN: PASS on $($commit.Substring(0, 12))" -ForegroundColor Green
Write-Host "   records : $RunDirectory"
Write-Host '   evidence: native\splat-agent\evidence\daemon-probe.json, last-hop-probe.json, and the guest record beside them'
exit 0
