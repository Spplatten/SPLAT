<#
.SYNOPSIS
    Re-proves the Linux substrate in one command: a daemon built from this tree, started as root,
    both probes run against it with their evidence written into the tree, the installed service
    put back, and the two verdicts printed against the hash of the kernel program that ships.

.DESCRIPTION
    Every change to lease_lsm.bpf.c, to the daemon or to the lease path withdraws the README's
    "Enforcing, proven under root" and "Demonstrated end to end": DocumentationDriftTests binds
    both to evidence files that carry the SHA-256 of the BPF source they exercised, and the suite
    stays red until probe-daemon.sh and probe-last-hop.ps1 are re-run against the source that
    ships. Until this script existed that was three runs in two terminals, with a sudo prompt in
    the middle (docs/GUIDE-operator.md, step 1), so the cost of proof set the pace of every
    kernel-side change - and four of them landed unproven between 2026-09-20 and 2026-09-21.

    No password is needed. `wsl.exe -u root` runs a command as root in the guest without one, which
    is how `splat-mcp provision` and the bridge already work; `sudo` inside run-daemon.sh is what
    prompts, and this script does not use it. The run is still the operator's: the permission
    classifier refuses an agent every route to a root daemon, so this is for your own terminal.

    In order:
      1. Read the installed unit's state, so it can be put back exactly; refuse to go on if `bpf`
         is not on the guest's boot line or a lease ceiling would refuse what the probes dial.
      2. Build the daemon in the guest as the default user, touching the BPF source first so the
         kernel program is recompiled rather than reused from a previous build.
      3. Stop the installed unit if it is running, and wait for the port to be free. A daemon that
         is not this build answering the probes would prove the wrong program.
      4. Let probe-daemon.sh own the fresh root daemon so its SIGKILL/restart checks run without
         competing for the singleton lock; record into this tree's evidence directory.
      5. After that daemon is stopped, start the same binary for the host's last-hop probe.
      6. Run probe-last-hop.ps1 from this PowerShell, with its evidence directory pointed the same way.
      7. Always: stop the fresh daemon, and restart the installed unit if it was running.
      8. Read both evidence files back and compare their bpf_source_sha256 with the tree's.

    Exit 0 only when both verdicts are PASS, both hashes equal the tree's, and both files were
    written by this run. Anything else exits 1 and says which of those failed. A failed probe never
    overwrites standing PASS evidence - both probes write *.INCOMPLETE.json beside it instead - so
    a bad run costs nothing but the time it took.

.PARAMETER Listen
    Where the fresh daemon binds and both probes dial. Loopback only, on purpose.

.PARAMETER Egress
    The operator egress policy the last-hop probe starts splat-mcp with. Keep 127.0.0.1:80 in it,
    and if the guest holds a lease ceiling (/etc/splat/policy.json) keep 127.0.0.1:80 and
    127.0.0.1:53 in THAT, or the probes fail for a reason that has nothing to do with the kernel.

.PARAMETER SkipBuild
    Use the binary a previous run built. Only when the source has not changed since.

.PARAMETER Distribution
    The WSL distribution to use; default is WSL's own default.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\reprove-substrate.ps1
#>
[CmdletBinding()]
param(
    [string] $Listen = '127.0.0.1:50051',
    [string] $Egress = '127.0.0.1:80',
    [switch] $SkipBuild,
    [string] $Distribution
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$crate = Join-Path $root 'native\splat-agent'
$evidenceDir = Join-Path $crate 'evidence'
$bpfSource = Join-Path $crate 'src\bpf\lease_lsm.bpf.c'
$startedUtc = (Get-Date).ToUniversalTime()

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { Write-Error 'wsl.exe not found: there is no guest to prove anything in.'; exit 1 }
if (-not (Test-Path $bpfSource)) { Write-Error "no kernel program at $bpfSource"; exit 1 }

# `wsl.exe` arguments common to every call. `-d` only when asked, so the default distribution
# stays whatever the user configured - the same one provision installed into.
$wslBase = @()
if ($Distribution) { $wslBase = @('-d', $Distribution) }

function Invoke-Guest([string] $script, [switch] $AsRoot) {
    # Run from a file rather than passed to `sh -c`: Windows PowerShell 5.1 does not escape quotes
    # inside a native argument, so an inline script arrives in the guest cut wherever it quoted.
    # stderr is folded into stdout inside the guest, because 2>&1 on a native command here turns
    # ordinary progress output into terminating errors under ErrorActionPreference Stop.
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ('splat-reprove-' + [guid]::NewGuid().ToString('N') + '.sh')
    [System.IO.File]::WriteAllText($file, ("exec 2>&1`n" + $script).Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
    try {
        $guestFile = (& wsl.exe @wslBase -e wslpath -a $file | Out-String).Trim()
        $user = @()
        if ($AsRoot) { $user = @('-u', 'root') }
        $output = (& wsl.exe @wslBase @user -e sh $guestFile | Out-String).Trim()
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    finally {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-GuestPath([string] $windowsPath) {
    $guest = (& wsl.exe @wslBase -e wslpath -a $windowsPath | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $guest) { Write-Error "WSL could not resolve $windowsPath"; exit 1 }
    if ($guest.Contains("'")) { Write-Error "refusing a path the guest script would have to unquote: $guest"; exit 1 }
    return $guest
}

function Test-PortAnswers([string] $endpoint) {
    $addr, $port = $endpoint -split ':', 2
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($addr, [int]$port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(1000)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Dispose() }
}

function Wait-Until([scriptblock] $condition, [int] $seconds, [string] $what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $condition) { return $true }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "  waited ${seconds}s for $what and it did not happen"
    return $false
}

$treeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bpfSource).Hash.ToLowerInvariant()
Write-Host "== re-proving the substrate against lease_lsm.bpf.c $($treeHash.Substring(0, 12))..." -ForegroundColor Cyan
Write-Host "   listen : $Listen"
Write-Host "   egress : $Egress"
Write-Host "   evidence: $evidenceDir"

$guestCrate = ConvertTo-GuestPath $crate
$guestEvidence = ConvertTo-GuestPath $evidenceDir

Write-Host "[1/8] the guest's state: the installed unit, the boot line, the lease ceiling" -ForegroundColor Cyan
# All three read before anything is changed, because each is a way the run fails for a reason
# that says nothing about the kernel: a unit to put back exactly as it was, `bpf` absent from the
# boot line (the program cannot attach, and the daemon exits), and a ceiling that does not admit
# what the probes dial - which turned a healthy kernel into an INCOMPLETE on 2026-09-21.
$state = Invoke-Guest -AsRoot @'
echo "UNIT=$(systemctl is-active splat-agent 2>/dev/null)"
echo "CMDLINE=$(cat /proc/cmdline)"
echo "POLICY_BEGIN"
cat /etc/splat/policy.json 2>/dev/null
echo
echo "POLICY_END"
'@
$unitWasActive = ($state.Output -match '(?m)^UNIT=active\s*$')
Write-Host ("   splat-agent.service: {0}" -f ([regex]::Match($state.Output, '(?m)^UNIT=(\S*)').Groups[1].Value))

# The same reading of the boot line that `doctor` and `provision` make: the lsm= list must name bpf.
$cmdline = [regex]::Match($state.Output, '(?m)^CMDLINE=(.*)$').Groups[1].Value
$lsmList = @($cmdline -split '\s+' | Where-Object { $_.StartsWith('lsm=') } | ForEach-Object { $_.Substring(4) -split ',' })
if ($lsmList -notcontains 'bpf') {
    Write-Error 'bpf is NOT on the guest kernel''s boot command line, so no BPF-LSM program can attach and the daemon would exit. `splat-mcp provision --apply` appends the lsm= stanza to .wslconfig; then `wsl --shutdown`, which is yours.'
    exit 1
}
Write-Host '   boot line: bpf is on the lsm= list'

$policyText = [regex]::Match($state.Output, '(?s)POLICY_BEGIN\r?\n(.*?)\r?\nPOLICY_END').Groups[1].Value.Trim()
if ($policyText) {
    try { $policy = $policyText | ConvertFrom-Json }
    catch { Write-Error "the guest's lease ceiling at /etc/splat/policy.json is not JSON this script can read: $($_.Exception.Message)"; exit 1 }
    # What the probes name: 127.0.0.1:80 for the connect checks, 127.0.0.1:53 for the datagram
    # check, and six executables. A ceiling that leaves one out refuses those leases before the
    # kernel sees them, and the run reads as a kernel failure.
    $missing = @()
    if ($null -ne $policy.allowedEgress) {
        foreach ($endpoint in @('127.0.0.1:80', '127.0.0.1:53')) {
            if (@($policy.allowedEgress) -notcontains $endpoint) { $missing += $endpoint }
        }
    }
    $prefixes = @($policy.allowedExecPrefixes | ForEach-Object { if ($_.EndsWith('/')) { $_ } else { "$_/" } })
    foreach ($exe in @('/usr/bin/id', '/bin/cat', '/bin/sh', '/usr/bin/curl', '/bin/sleep', '/usr/bin/python3')) {
        if (-not ($prefixes | Where-Object { $exe.StartsWith($_) })) { $missing += $exe }
    }
    if ($missing.Count -gt 0) {
        Write-Error ("the guest's lease ceiling at /etc/splat/policy.json does not admit what the probes use: {0}. " -f ($missing -join ', ') +
            'Re-run `splat-mcp provision --apply --egress 127.0.0.1:80,127.0.0.1:53,<your endpoints>` so it does, or remove the ceiling for the length of this run.')
        exit 1
    }
    Write-Host '   lease ceiling: present, and it admits what the probes dial and run'
}
else {
    Write-Host '   lease ceiling: none - the token alone bounds a lease on this guest'
}

if (-not $SkipBuild) {
    Write-Host "[2/8] building the daemon in the guest (a touched BPF source, so the kernel program is recompiled)" -ForegroundColor Cyan
    $build = Invoke-Guest (@'
set -e
cd '__CRATE__'
export EXTRA_CFLAGS=-Wno-error CFLAGS=-Wno-error
# Not /tmp, which any guest user can write to before the first build and so own what root runs.
export CARGO_TARGET_DIR="$HOME/.cache/splat-agent-target"
# rustup puts cargo on PATH from .bashrc, which this shell never reads.
CARGO="$(command -v cargo || echo "$HOME/.cargo/bin/cargo")"
command -v python3 >/dev/null || { echo "python3 is required by probe-daemon.sh"; exit 8; }
touch build.rs src/bpf/lease_lsm.bpf.c
"$CARGO" build --release
echo "BIN=$CARGO_TARGET_DIR/release/splat-agent"
'@).Replace('__CRATE__', $guestCrate)
    $tail = ($build.Output -split "`n" | Select-Object -Last 15) -join "`n"
    if ($build.ExitCode -ne 0) { Write-Host $tail; Write-Error "the daemon build failed (exit $($build.ExitCode))"; exit 1 }
    $bin = [regex]::Match($build.Output, 'BIN=(\S+)').Groups[1].Value
    if (-not $bin) { Write-Host $tail; Write-Error 'the build reported success but named no binary'; exit 1 }
}
else {
    Write-Host "[2/8] build skipped; using the previous binary" -ForegroundColor Cyan
    $bin = (Invoke-Guest 'echo "$HOME/.cache/splat-agent-target/release/splat-agent"').Output
}
$binCheck = Invoke-Guest ("test -x '{0}' && echo OK" -f $bin)
if ($binCheck.Output -ne 'OK') { Write-Error "no executable daemon at $bin in the guest"; exit 1 }
Write-Host "   daemon : $bin"

$daemon = $null
$daemonLog = Join-Path ([System.IO.Path]::GetTempPath()) ('splat-reprove-daemon-' + [guid]::NewGuid().ToString('N') + '.log')
$daemonErr = "$daemonLog.err"

try {
    Write-Host "[3/8] freeing $Listen" -ForegroundColor Cyan
    if ($unitWasActive) {
        $stop = Invoke-Guest -AsRoot 'systemctl stop splat-agent; echo "RC=$?"'
        if ($stop.Output -notmatch 'RC=0') { Write-Host $stop.Output; Write-Error 'could not stop the installed unit'; exit 1 }
        Write-Host '   installed unit stopped for the length of this run'
    }
    if (-not (Wait-Until { -not (Test-PortAnswers $Listen) } 15 "$Listen to stop answering")) {
        Write-Error "something other than the installed unit is listening on $Listen; the probes would prove the wrong program"
        exit 1
    }

    Write-Host "[4/8] probe-daemon.sh owns the fresh daemon, including SIGKILL and restart" -ForegroundColor Cyan
    # The lifecycle probe must own the only daemon. Starting the driver's instance first
    # holds agent.lock and prevents section 19 from ever exercising pinned enforcement.
    # bpffs is mounted by the installed unit's ExecStartPre, not by the guest. A guest the unit was
    # never installed in - the shipped SPLAT Guest, imported fresh on 2026-10-23 - has none, and the
    # daemon refuses to pin. The same idempotent line as the unit, so the run proves the daemon, not
    # whether some earlier service happened to leave a mount behind.
    $probe = Invoke-Guest -AsRoot (@'
mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf
cd '__CRATE__'
SPLAT_PROBE_DAEMON='__BIN__' SPLAT_EVIDENCE_DIR='__EVIDENCE__' bash probe-daemon.sh '__LISTEN__'
'@).Replace('__CRATE__', $guestCrate).Replace('__BIN__', $bin).Replace('__EVIDENCE__', $guestEvidence).Replace('__LISTEN__', $Listen)
    $probe.Output -split "`n" | ForEach-Object { Write-Host "   $_" }

    Write-Host "[5/8] starting the fresh daemon for the last-hop probe" -ForegroundColor Cyan
    # Its own token, ceiling and workload identity defaults, exactly as the installed unit runs it.
    # Redirected to files: under this script's own console the daemon's log would interleave with
    # the probes' output, and a daemon that dies at startup has to be readable afterwards.
    $daemon = Start-Process -FilePath 'wsl.exe' -ArgumentList ($wslBase + @('-u', 'root', '-e', $bin, '--listen', $Listen)) `
        -RedirectStandardOutput $daemonLog -RedirectStandardError $daemonErr -WindowStyle Hidden -PassThru
    $up = Wait-Until { $daemon.HasExited -or (Test-PortAnswers $Listen) } 30 "the daemon to listen at $Listen"
    if ($daemon.HasExited -or -not $up) {
        Write-Host '--- daemon output ---'
        Get-Content -LiteralPath $daemonLog, $daemonErr -ErrorAction SilentlyContinue | Select-Object -Last 30 | ForEach-Object { Write-Host "   $_" }
        Write-Error 'the fresh daemon did not come up; the usual causes are `bpf` missing from the boot line, a ceiling the daemon cannot trust, or a verifier rejection of the new program'
        exit 1
    }
    $log = Get-Content -LiteralPath $daemonLog, $daemonErr -ErrorAction SilentlyContinue | Out-String
    if ($log -notmatch 'kernel enforcement is live') {
        Write-Host '   WARNING: the daemon is listening but its log does not yet say "kernel enforcement is live"; the probes will say whether it enforces'
    }

    Write-Host "[6/8] probe-last-hop.ps1, from this host" -ForegroundColor Cyan
    try {
        & (Join-Path $crate 'probe-last-hop.ps1') -Egress $Egress -EvidenceDir $evidenceDir
        Write-Host "   probe-last-hop.ps1 exited $LASTEXITCODE"
    }
    catch {
        Write-Host "   probe-last-hop.ps1 did not complete: $($_.Exception.Message)"
    }
}
finally {
    Write-Host "[7/8] putting the guest back" -ForegroundColor Cyan
    # SIGTERM, not a kill of wsl.exe: the daemon's shutdown path ends any lease it could no longer
    # police and says so in its log, and that path is part of what a re-proof is for. Only the daemon
    # this run started, matched by its listen address: a daemon the operator has running by hand on
    # another port is not this script's to stop.
    if ($daemon) {
        $null = Invoke-Guest -AsRoot ('pkill -TERM -f ' + "'splat-agent --listen $Listen'" + '; echo "RC=$?"')
        if (-not $daemon.HasExited -and -not $daemon.WaitForExit(10000)) { try { $daemon.Kill() } catch { } }
    }
    if ($unitWasActive) {
        $start = Invoke-Guest -AsRoot 'systemctl start splat-agent; echo "RC=$?"'
        if ($start.Output -match 'RC=0') { Write-Host '   installed unit started again' }
        else { Write-Host "   WARNING: the installed unit did not start again: $($start.Output)" }
    }
    $lastLines = Get-Content -LiteralPath $daemonLog, $daemonErr -ErrorAction SilentlyContinue | Select-Object -Last 4
    if ($lastLines) { $lastLines | ForEach-Object { Write-Host "   daemon: $_" } }
    Remove-Item -LiteralPath $daemonLog, $daemonErr -Force -ErrorAction SilentlyContinue
}

Write-Host "[8/8] the verdicts, against the source that ships" -ForegroundColor Cyan
$failures = @()
foreach ($name in @('daemon-probe.json', 'last-hop-probe.json')) {
    $path = Join-Path $evidenceDir $name
    $incomplete = Join-Path $evidenceDir ($name -replace '\.json$', '.INCOMPLETE.json')
    if (-not (Test-Path $path)) { $failures += "$name was not written"; continue }
    $record = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    $recorded = [datetime]::Parse($record.recorded_utc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
    $fresh = $recorded -ge $startedUtc.AddMinutes(-1)
    # As a string, so a record without the field reads as a stale hash rather than throwing here.
    $recordHash = [string] $record.bpf_source_sha256
    $hashOk = ($recordHash -eq $treeHash)
    $hashText = if ($hashOk) { 'matches the tree' } elseif ($recordHash.Length -ge 12) { 'STALE: ' + $recordHash.Substring(0, 12) } else { 'STALE: none recorded' }
    Write-Host ("   {0,-22} verdict {1,-10} hash {2}  written by this run: {3}" -f $name, $record.verdict, $hashText, $fresh)
    if ($record.verdict -ne 'PASS') { $failures += "$name is $($record.verdict)" }
    if (-not $hashOk) { $failures += "$name names another kernel program than the one in the tree" }
    if (-not $fresh) { $failures += "$name was not written by this run - the probe fell back to leaving the standing evidence alone" }
    if ((Test-Path $incomplete) -and ((Get-Item $incomplete).LastWriteTimeUtc -ge $startedUtc.AddMinutes(-1))) {
        $failures += "this run wrote $(Split-Path $incomplete -Leaf); read it for the check that failed"
    }
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host 'RE-PROOF INCOMPLETE:' -ForegroundColor Yellow
    $failures | ForEach-Object { Write-Host "   - $_" }
    Write-Host '   A failure is a finding, not a setup problem: paste the whole run.'
    exit 1
}

Write-Host 'RE-PROOF PASS: both probes passed against the kernel program in the tree.' -ForegroundColor Green
Write-Host '   Next: commit native/splat-agent/evidence/daemon-probe.json and last-hop-probe.json, restore the'
Write-Host '   README''s "Enforcing, proven under root" and "Demonstrated end to end" wording, and run'
Write-Host '   `dotnet test --filter DocumentationDriftTests`, which holds the README to these two files.'
exit 0
