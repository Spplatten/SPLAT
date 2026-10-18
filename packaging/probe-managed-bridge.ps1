# The roadmap 2.4 gate is three runs against one managed deployment, in this order:
#   1. Admitted standard account:   -Configuration <bridge.json> -Executable <splat-mcp.exe> -OutputPath owner.json
#   2. Unadmitted standard account: -ExpectDenied -OwnerEvidence <a copy of owner.json it can read> -OutputPath denied.json
#   3. Elevated: splat-mcp audit --managed --configuration <bridge.json> --probe owner.json --output audit.json
# Run 2 counts only beside a PASS from run 1 within the hour; run 3 reads the ledger that run 1 is denied.
# Then the service lifecycle, elevated, with run 1 repeated after the first two: Restart-Service
# <instance>; splat-mcp provision --managed --upgrade --apply from a newly published build, which
# restores the previous build if the new one does not stay running; and splat-mcp unmount --managed
# --apply, which moves the retained ledger aside so the same instance can be installed again.
[CmdletBinding(DefaultParameterSetName = 'Owner')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Owner')][string]$Configuration,
    [Parameter(Mandatory, ParameterSetName = 'Owner')][string]$Executable,
    [Parameter(Mandatory)][string]$OutputPath,
    # bridge.json's directory admits the service and its operators only, so an unadmitted account
    # takes the pipe and the service identity from the owner's evidence instead.
    [Parameter(ParameterSetName = 'Denied')][switch]$ExpectDenied,
    [Parameter(Mandatory, ParameterSetName = 'Denied')][string]$OwnerEvidence
)
$ErrorActionPreference = 'Stop'
$deniedRun = $PSCmdlet.ParameterSetName -eq 'Denied'
$config = Get-Content -LiteralPath $(if ($deniedRun) { $OwnerEvidence } else { $Configuration }) -Raw | ConvertFrom-Json
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$groups = (& whoami.exe /groups /fo csv | Out-String)
if ($groups -match 'S-1-5-32-544') { throw 'Run this probe as a standard account, not a filtered administrator.' }
$result = [ordered]@{ Schema = 2; At = [DateTimeOffset]::UtcNow.ToString('o'); FinishedAt = $null; CallerSid = $identity.User.Value;
    CallerName = $identity.Name; ServiceSid = $config.ServiceSid; PipeName = $config.PipeName; StandardAccount = $true;
    Checks = [ordered]@{}; Admissions = @(); Responses = @(); Error = $null; Verdict = 'INCOMPLETE' }
function Invoke-Bridge($Requests) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable, ('managed --configuration "{0}"' -f $Configuration))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        foreach ($request in $Requests) { $process.StandardInput.WriteLine($request.Line) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(90000)) { $process.Kill(); throw 'Bridge request timed out.' }
        @{ Exit = $process.ExitCode; Output = $out.GetAwaiter().GetResult(); Error = $err.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
# The params text is built once and sent verbatim, so its SHA-256 is the request_sha256 the service
# writes in the admission row - the value run 3 finds that row by.
function Tool($Id, $Name, $Arguments) {
    $params = @{ name = $Name; arguments = $Arguments } | ConvertTo-Json -Depth 12 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($params)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    [pscustomobject]@{ Id = $Id; Tool = $Name; Sha256 = $digest; Line = ('{{"jsonrpc":"2.0","id":{0},"method":"tools/call","params":{1}}}' -f $Id, $params) }
}
# Only the tools the service admits get an admission row; run 3 expects exactly one per entry here.
function Admit($Request, $ClaimedPrincipal) {
    $entry = [ordered]@{ Id = $Request.Id; Tool = $Request.Tool; RequestSha256 = $Request.Sha256 }
    if ($ClaimedPrincipal) { $entry.ClaimedPrincipal = $ClaimedPrincipal }
    $script:result.Admissions += [pscustomobject]$entry
}
try {
    if ($deniedRun) {
        # A denial means something only beside a recent owner PASS on the same pipe and service.
        $ownerAge = [DateTimeOffset]::UtcNow - [DateTimeOffset]$config.At
        $result.Checks.OwnerControlPassed = $config.Verdict -eq 'PASS' -and [bool]$config.PipeName -and
            $config.CallerSid -ne $identity.User.Value -and $ownerAge -ge [TimeSpan]::Zero -and $ownerAge -lt [TimeSpan]::FromHours(1)
        # ACCESS_DENIED from CreateFile means the pipe exists and its ACL refused this SID. A stopped
        # service or an absent pipe ends in a timeout instead, which is not a denial. The rights are the
        # client's own (ManagedBridgeClient.ClientRights). Before ReadAttributes joined them, an admitted
        # SID was refused too, so this denial proved nothing.
        $client = [IO.Pipes.NamedPipeClientStream]::new('.', $config.PipeName,
            [IO.Pipes.PipeAccessRights]'ReadData, WriteData, ReadAttributes, ReadPermissions, Synchronize', [IO.Pipes.PipeOptions]::None,
            [Security.Principal.TokenImpersonationLevel]::Identification, [IO.HandleInheritability]::None)
        $aclDenied = $false
        try { $client.Connect(3000) } catch [UnauthorizedAccessException] { $aclDenied = $true } catch { } finally { $client.Dispose() }
        $result.Checks.UnadmittedSidDenied = $aclDenied
    } else {
        $first = Tool 1 'get_substrate_health' @{}
        Admit $first
        $health = Invoke-Bridge @($first)
        if ($health.Exit -ne 0) { throw $health.Error }
        $response = $health.Output.Trim() | ConvertFrom-Json
        # The reply is recorded before it is read: an error reply used to throw "Cannot index into a
        # null array" here and leave an INCOMPLETE record that never said what the bridge answered.
        $result.Responses += $response
        if (-not $response.result.content) { throw "The bridge answered get_substrate_health without a result: $($health.Output.Trim())" }
        $status = $response.result.content[0].text | ConvertFrom-Json
        $result.Checks.OwnerPositiveControl = $status.Authenticated -and $status.Enforcing
        # This exercises the exact root/token bypass from row 2.4 under the same caller SID that
        # subsequently obtains a governed lease. No token content is retained on accidental access.
        $direct = & (Join-Path $env:SystemRoot 'System32\wsl.exe') -d $config.Distribution -u root -e /bin/cat /etc/splat/agent.token 2>&1 | Out-String
        $result.Checks.DirectDistroTokenDenied = $LASTEXITCODE -ne 0 -and $direct.Replace([string][char]0, '') -match 'WSL_E_DISTRO_NOT_FOUND'
        foreach ($file in @('ledger.key', 'ledger.db', 'distro\ext4.vhdx')) {
            $denied = $false
            try { $stream = [IO.File]::Open((Join-Path $config.StateDirectory $file), 'Open', 'Read', 'ReadWrite'); $stream.Dispose() }
            catch [UnauthorizedAccessException] { $denied = $true }
            $result.Checks["PrivateFileDenied:$file"] = $denied
        }
        $configDenied = $false
        try { $stream = [IO.File]::Open($Configuration, 'Open', 'Write', 'ReadWrite'); $stream.Dispose() }
        catch [UnauthorizedAccessException] { $configDenied = $true }
        $result.Checks.ConfigurationWriteDenied = $configDenied
        $injectionDenied = $false
        try {
            $fake = [IO.Pipes.NamedPipeServerStream]::new($config.PipeName, [IO.Pipes.PipeDirection]::InOut, 9,
                [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
            $fake.Dispose()
        } catch { $injectionDenied = $_.Exception.ToString() -match 'UnauthorizedAccessException|Access.*denied' }
        $result.Checks.PipeInstanceInjectionDenied = $injectionDenied
        # A shared loopback socket, if visible on this WSL build, must still reject a forged key.
        $tcp = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $tcp.ConnectAsync('127.0.0.1', [int]$config.Port)
            if ($connect.Wait(3000) -and $tcp.Connected) {
                $stream = $tcp.GetStream(); $stream.ReadTimeout = 3000; $stream.WriteTimeout = 3000
                $bytes = [Text.Encoding]::UTF8.GetBytes("{`"type`":`"HEALTH`",`"auth`":`"forged`"}`n")
                $stream.Write($bytes, 0, $bytes.Length)
                $buffer = New-Object byte[] 4096
                try { $count = $stream.Read($buffer, 0, $buffer.Length); $reply = [Text.Encoding]::UTF8.GetString($buffer, 0, $count) }
                catch [IO.IOException] { $reply = '' }
                $result.Checks.DirectDaemonUnauthenticatedDenied = $reply -notmatch '"enforcing"\s*:\s*true'
            } else { $result.Checks.DirectDaemonUnauthenticatedDenied = $true }
        } catch [Management.Automation.MethodInvocationException] {
            $result.Checks.DirectDaemonUnauthenticatedDenied = $_.Exception.InnerException.ToString() -match 'SocketException'
        } finally { $tcp.Dispose() }
        # The claimed principal is scored by run 3: the admission row must name this caller instead.
        $spoof = Tool 2 'run_command' @{ command = '/usr/bin/id'; args = @(); operatorIdentity = 'SYSTEM'; principalId = 'S-1-5-18' }
        $code = Tool 3 'run_code' @{ language = 'python'; code = "import socket`ns=socket.socket()`ntry:`n s.connect(('127.0.0.1',9))`n print('UNEXPECTED_CONNECT')`nexcept OSError as e:`n print('DENIED_ERRNO',e.errno)" }
        $hostTool = Tool 4 'fs_read' @{ path = (Join-Path $config.StateDirectory 'ledger.key') }
        # 203.0.113.7 is documentation space (RFC 5737), outside any real operator egress policy.
        $egress = Tool 5 'run_command' @{ command = '/bin/echo'; args = @('egress-bypass'); allowNetwork = $true; allowedEgressIps = @('203.0.113.7') }
        Admit $spoof 'S-1-5-18'; Admit $code; Admit $egress
        $run = Invoke-Bridge @($spoof, $code, $hostTool, $egress)
        if ($run.Exit -ne 0) { throw $run.Error }
        $responses = @($run.Output.Split("`n") | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        $result.Responses += $responses
        # Scored by id, so a missing response fails its own check instead of shifting the others.
        $byId = @{}; foreach ($reply in $responses) { $byId[[string]$reply.id] = $reply }
        $result.Checks.GovernedLeaseRunsAsNobody = $byId['2'].result.content[0].text -match 'uid=65534'
        $result.Checks.LiveKernelConnectDenial = $byId['3'].result.content[0].text -match 'DENIED_ERRNO 1' -and
            $byId['3'].result.content[0].text -match 'KERNEL VIOLATION CONTAINMENT REPORT'
        $result.Checks.PrivilegedHostToolDenied = $byId['4'].error.code -eq -32601
        # The last-hop probe's predicate for a refusal the MCP host made before any lease existed.
        $egressText = [string]$byId['5'].result.content[0].text
        $result.Checks.EgressOutsidePolicyRefused = [string]$config.Egress -notmatch '203\.0\.113\.7' -and
            $egressText -match '\[SPLAT POLICY\]' -and $egressText -match 'not a kernel denial' -and $egressText -notmatch '\[Process Exited with code'
        $last = Tool 6 'get_substrate_health' @{}
        Admit $last
        $result.Checks.OwnerStillEnforcing = ((Invoke-Bridge @($last)).Output -match 'Enforcing')
    }
    if ($result.Checks.Count -gt 0 -and @($result.Checks.Values | Where-Object { $_ -ne $true }).Count -eq 0) { $result.Verdict = 'PASS' }
} catch { $result.Error = $_.Exception.ToString() }
$result.FinishedAt = [DateTimeOffset]::UtcNow.ToString('o')
[IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
if ($result.Verdict -ne 'PASS') { exit 1 }
