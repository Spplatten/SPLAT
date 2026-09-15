<#
.SYNOPSIS
  Records the last hop: an MCP client's request travelling from splat-mcp, through the C# bridge,
  into the daemon, and being refused by the kernel.

.DESCRIPTION
  Every other probe in this folder starts at the daemon's own socket. This one starts where a real
  caller starts - stdin of `splat-mcp.exe` - so the thing under test is the whole chain:

      JSON-RPC on stdio -> McpServerHandler -> McpEgressPolicy -> LeaseSpec
        -> WslLeasedExecutor (loopback TCP, root-owned token) -> splat-agent -> BPF-LSM

  It is a client and nothing more: the daemon must already be running as root in the guest
  (`bash run-daemon.sh`), and this script never elevates. The one privileged step - reading the
  daemon's 0600 token - happens inside the bridge, which is itself part of what is being proven.

  Four checks have to hold together, because refusals alone would also be produced by a chain that
  is simply broken: a permitted command must run (as nobody, not as the daemon's root), a permitted
  endpoint must stay reachable, an unleased second exec must be refused by the kernel, and an
  address outside the lease must be refused by the kernel. A fifth records that a request outside
  the OPERATOR's egress policy is turned away in the MCP host, before any lease exists, and says so
  in those words rather than dressing a policy check up as a kernel denial.

.PARAMETER Exe
  splat-mcp.exe. Built if absent.

.PARAMETER Egress
  The operator egress policy this run starts the server with. The permitted-endpoint check dials
  the first endpoint in it; the refused check dials 1.1.1.1, which is not in it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File native\splat-agent\probe-last-hop.ps1
#>
[CmdletBinding()]
param(
    [string] $Exe,
    [string] $Egress = "127.0.0.1:80",
    [string] $EvidenceDir
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $EvidenceDir) { $EvidenceDir = Join-Path $PSScriptRoot "evidence" }
if (-not $Exe) { $Exe = Join-Path $repo "src\splat-mcp\bin\Debug\net10.0-windows\splat-mcp.exe" }

# dotnet is not on PATH on the build host; the runbook uses this same user-local root.
$dotnet = Join-Path $env:LOCALAPPDATA "Microsoft\dotnet\dotnet.exe"
# Built every run, not only when the binary is missing. A stale exe is the failure this evidence
# can least afford: the first run of this probe recorded six False against a build that predated
# the flag it was passing, which says nothing about the kernel and everything about the artifact.
if (-not $PSBoundParameters.ContainsKey("Exe")) {
    if (-not (Test-Path $dotnet)) { throw "dotnet not found at $dotnet." }
    Write-Host "  building splat-mcp from the tree"
    & $dotnet build (Join-Path $repo "src\splat-mcp\splat-mcp.csproj") -c Debug -nologo -v q
}
if (-not (Test-Path $Exe)) { throw "$Exe does not exist." }

$workspace = Join-Path ([System.IO.Path]::GetTempPath()) ("splat-last-hop-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workspace | Out-Null

# @() or a single endpoint indexes as a STRING, and [0] would be the character "1".
$firstEndpoint = @($Egress -split "[,;\s]+" | Where-Object { $_ })[0]
$permittedUrl = "http://" + ($firstEndpoint -replace ":80$", "") + "/"
$traceId = "last-hop-" + [guid]::NewGuid().ToString("N")

function New-ToolCall([int] $id, [hashtable] $arguments) {
    @{ jsonrpc = "2.0"; id = $id; method = "tools/call";
       params = @{ name = "run_command"; arguments = $arguments } }
}

# One line per message, in the order a client would send them. The server reads stdin to its end,
# so closing the file is what ends the session - no kill, no timeout race.
$requests = @(
    @{ jsonrpc = "2.0"; id = 1; method = "initialize"; params = @{
        protocolVersion = "2024-11-05"; capabilities = @{}
        clientInfo = @{ name = "splat-last-hop-probe"; version = "1" } } },

    # 2. CONTROL. If this does not run, every refusal below is explained by a broken chain.
    (New-ToolCall 2 @{ command = "/usr/bin/id"; args = @("-u"); timeoutSeconds = 20
                       traceId = $traceId; clientName = "splat-last-hop-probe" }),

    # 3. The lease allow-lists exactly the command asked for, so sh runs and its exec of dpkg is the
    #    one the caller never declared. bprm_check_security must refuse it.
    (New-ToolCall 3 @{ command = "/bin/sh"; args = @("-c", "dpkg --version"); timeoutSeconds = 20 }),

    # 4. CONTROL for egress: the endpoint the operator approved must survive the whole chain. A
    #    refused TCP connection is fine - the kernel PERMITTED the syscall, which is the property.
    (New-ToolCall 4 @{ command = "/usr/bin/curl"
                       args = @("--max-time", "3", "-s", "-o", "/dev/null", $permittedUrl)
                       allowNetwork = $true; timeoutSeconds = 20 }),

    # 5. Inside the lease, outside the allow-list: socket_connect must refuse it.
    (New-ToolCall 5 @{ command = "/usr/bin/curl"
                       args = @("--max-time", "3", "-s", "-o", "/dev/null", "http://1.1.1.1/")
                       allowNetwork = $true; timeoutSeconds = 20 }),

    # 6. Outside the OPERATOR's policy: refused in the MCP host before a lease is requested at all,
    #    and labelled as this host's own check rather than a kernel denial.
    (New-ToolCall 6 @{ command = "/usr/bin/curl"
                       args = @("--max-time", "3", "-s", "-o", "/dev/null", "http://203.0.113.7/")
                       allowNetwork = $true; allowedEgressIps = @("203.0.113.7"); timeoutSeconds = 20 })
)

$reqFile = Join-Path $workspace "requests.jsonl"
$outFile = Join-Path $workspace "stdout.jsonl"
$errFile = Join-Path $workspace "stderr.txt"
$lines = $requests | ForEach-Object { $_ | ConvertTo-Json -Depth 8 -Compress }
# No byte order mark: the server's first stdin line has to parse as JSON, and EF BB BF does not.
[System.IO.File]::WriteAllText($reqFile, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "== last hop: MCP client -> splat-mcp -> bridge -> daemon -> kernel =="
Write-Host "   server : $Exe"
Write-Host "   egress : $Egress   (permitted probe dials $permittedUrl, refused probe dials 1.1.1.1)"

$proc = Start-Process -FilePath $Exe -ArgumentList @("--egress", $Egress, "--workspace", $workspace) `
    -RedirectStandardInput $reqFile -RedirectStandardOutput $outFile -RedirectStandardError $errFile `
    -NoNewWindow -PassThru
if (-not $proc.WaitForExit(240000)) {
    try { $proc.Kill() } catch {}
    throw "splat-mcp did not finish within 240s; see $outFile"
}

$responses = @{}
foreach ($line in (Get-Content -LiteralPath $outFile)) {
    if (-not $line.Trim()) { continue }
    try { $msg = $line | ConvertFrom-Json } catch { continue }
    if ($null -ne $msg.id) { $responses[[int]$msg.id] = $msg }
}

function Get-Text([int] $id) {
    $msg = $responses[$id]
    if (-not $msg -or -not $msg.result -or -not $msg.result.content) { return "" }
    ($msg.result.content | ForEach-Object { $_.text }) -join "`n"
}
function Get-AnchorHash([int] $id) {
    $text = Get-Text $id
    $m = [regex]::Match($text, '"anchorHash"\s*:\s*"([0-9a-fA-F]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ""
}

$control   = Get-Text 2
$exec      = Get-Text 3
$egressOk  = Get-Text 4
$egressBad = Get-Text 5
$policy    = Get-Text 6

foreach ($pair in @(@(2, "control"), @(3, "unleased-exec"), @(4, "egress-permitted"), @(5, "egress-refused"), @(6, "outside-policy"))) {
    $head = ((Get-Text $pair[0]) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join " | "
    Write-Host ("  [{0}] {1}" -f $pair[1], $head)
}

# A violation is only the kernel's when it arrived as one: the bridge forwards VIOLATION events and
# the handler prints them under this header. Matching on "denied" or "not permitted" anywhere in the
# output would also match curl's own message for a connection the kernel allowed and nobody answered.
function Test-KernelRefusal([string] $text, [string] $hook) {
    return ($text -match "\[KERNEL VIOLATION CONTAINMENT REPORT\]") -and ($text -match "-EPERM") -and ($text -match [regex]::Escape("Detail=$hook"))
}

$ranAsNobody      = $control -match "\b65534\b"
$execBlocked      = Test-KernelRefusal $exec "bprm_check_security"
$dpkgLeaked       = ($exec -match "(?i)dpkg") -and ($exec -match "(?i)package management program version")
$permittedAllowed = ($egressOk -match "\[Process Exited with code") -and ($egressOk -notmatch "\[KERNEL VIOLATION CONTAINMENT REPORT\]")
$egressBlocked    = Test-KernelRefusal $egressBad "socket_connect"
$policyRefused    = ($policy -match "\[SPLAT POLICY\]") -and ($policy -match "not a kernel denial") -and ($policy -notmatch "\[Process Exited with code")

$bpfSource = Join-Path $PSScriptRoot "src\bpf\lease_lsm.bpf.c"
$bpfSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $bpfSource).Hash.ToLowerInvariant()
$kernel = (& wsl.exe -- uname -r) -join ""

$violationLines = @()
foreach ($text in @($exec, $egressBad)) {
    $violationLines += ($text -split "`n" | Where-Object { $_ -match "-EPERM:" } | ForEach-Object { $_.Trim() })
}

$evidence = [ordered]@{
    schema = 1
    bpf_source_sha256 = $bpfSha
    kernel_release = $kernel
    protocol_version = 3
    recorded_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    subject = "the last hop: a run_command from an MCP client, through splat-mcp and the C# bridge, refused in the kernel"
    transport = "stdio JSON-RPC to splat-mcp.exe; loopback TCP 127.0.0.1:50051 to splat-agent"
    operator_egress_policy = $Egress
    trace_id = $traceId
    audit_anchor_sha256 = (Get-AnchorHash 2)
    results = [ordered]@{
        permitted_command_ran_as_nobody = [bool] $ranAsNobody
        unleased_second_exec_blocked_by_kernel = [bool] $execBlocked
        unleased_exec_output_leaked = [bool] $dpkgLeaked
        permitted_endpoint_reached_the_syscall = [bool] $permittedAllowed
        egress_outside_the_lease_blocked_by_kernel = [bool] $egressBlocked
        outside_operator_policy_refused_before_any_lease = [bool] $policyRefused
    }
    violations = $violationLines
}
$evidence.verdict = if (
    $evidence.results.permitted_command_ran_as_nobody -and
    $evidence.results.unleased_second_exec_blocked_by_kernel -and
    -not $evidence.results.unleased_exec_output_leaked -and
    $evidence.results.permitted_endpoint_reached_the_syscall -and
    $evidence.results.egress_outside_the_lease_blocked_by_kernel -and
    $evidence.results.outside_operator_policy_refused_before_any_lease
) { "PASS" } else { "INCOMPLETE" }

Write-Host ""
foreach ($k in $evidence.results.Keys) { Write-Host ("  {0,-48}: {1}" -f $k, $evidence.results[$k]) }

$path = Join-Path $EvidenceDir "last-hop-probe.json"
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
# A failed run must not erase a passing one - the same rule probe-daemon.sh follows, and for the
# same reason: the runs most likely to fail (daemon not started, stale binary) say nothing about
# the kernel, and a claim in the README is bound to this file.
if ($evidence.verdict -ne "PASS" -and (Test-Path $path)) {
    $standing = ""
    try { $standing = (Get-Content -Raw -LiteralPath $path | ConvertFrom-Json).verdict } catch {}
    if ($standing -eq "PASS") {
        $path = Join-Path $EvidenceDir "last-hop-probe.INCOMPLETE.json"
        Write-Host ""
        Write-Host "  NOT overwriting the standing PASS evidence with this INCOMPLETE run."
    }
}
[System.IO.File]::WriteAllText($path, (($evidence | ConvertTo-Json -Depth 8) + "`n"), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ""
Write-Host "  evidence written: $path  (verdict $($evidence.verdict))"

if ($evidence.verdict -ne "PASS") {
    Write-Host ""
    Write-Host "  Nothing here is a measurement unless the CONTROLS held. If the control command did"
    Write-Host "  not run at all, start the daemon as root in the guest and re-run:"
    Write-Host "      wsl bash -lc 'cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash run-daemon.sh'"
    Write-Host "  server stderr: $errFile"
    exit 1
}

Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
exit 0
