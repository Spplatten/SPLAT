[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Configuration,
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$ExpectDenied
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$groups = (& whoami.exe /groups /fo csv | Out-String)
if ($groups -match 'S-1-5-32-544') { throw 'Run this probe as a standard account, not a filtered administrator.' }
$result = [ordered]@{ Schema = 1; At = [DateTimeOffset]::UtcNow.ToString('o'); CallerSid = $identity.User.Value;
    ServiceSid = $config.ServiceSid; StandardAccount = $true; Checks = [ordered]@{}; Responses = @(); Error = $null; Verdict = 'INCOMPLETE' }
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
        foreach ($request in $Requests) { $process.StandardInput.WriteLine(($request | ConvertTo-Json -Depth 12 -Compress)) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(90000)) { $process.Kill(); throw 'Bridge request timed out.' }
        @{ Exit = $process.ExitCode; Output = $out.GetAwaiter().GetResult(); Error = $err.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
function Tool($Id, $Name, $Arguments) { @{ jsonrpc = '2.0'; id = $Id; method = 'tools/call'; params = @{ name = $Name; arguments = $Arguments } } }
try {
    $health = Invoke-Bridge @( (Tool 1 'get_substrate_health' @{}) )
    if ($ExpectDenied) {
        $result.Checks.UnadmittedSidDenied = $health.Exit -ne 0 -and [string]::IsNullOrEmpty($health.Output)
    } else {
        if ($health.Exit -ne 0) { throw $health.Error }
        $response = $health.Output.Trim() | ConvertFrom-Json
        $status = $response.result.content[0].text | ConvertFrom-Json
        $result.Checks.OwnerPositiveControl = $status.Authenticated -and $status.Enforcing
        $result.Responses += $response
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
        $requests = @(
            (Tool 2 'run_command' @{ command = '/usr/bin/id'; args = @(); operatorIdentity = 'SYSTEM'; principalId = 'S-1-5-18' }),
            (Tool 3 'run_code' @{ language = 'python'; code = "import socket`ns=socket.socket()`ntry:`n s.connect(('127.0.0.1',9))`n print('UNEXPECTED_CONNECT')`nexcept OSError as e:`n print('DENIED_ERRNO',e.errno)" }),
            (Tool 4 'fs_read' @{ path = (Join-Path $config.StateDirectory 'ledger.key') }),
            (Tool 5 'run_command' @{ command = '/bin/echo'; args = @('egress-bypass'); allowNetwork = $true; allowedIps = @('1.1.1.1'); allowedPorts = @(443) })
        )
        $run = Invoke-Bridge $requests
        if ($run.Exit -ne 0) { throw $run.Error }
        $responses = @($run.Output.Split("`n") | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        $result.Responses += $responses
        $result.Checks.GovernedLeaseRunsAsNobody = $responses[0].result.content[0].text -match 'uid=65534'
        $result.Checks.LiveKernelConnectDenial = $responses[1].result.content[0].text -match 'DENIED_ERRNO 1' -and
            $responses[1].result.content[0].text -match 'KERNEL VIOLATION CONTAINMENT REPORT'
        $result.Checks.PrivilegedHostToolDenied = $responses[2].error.code -eq -32601
        $result.Checks.OwnerStillEnforcing = ((Invoke-Bridge @( (Tool 6 'get_substrate_health' @{}) )).Output -match 'Enforcing')
    }
    if (@($result.Checks.Values | Where-Object { $_ -ne $true }).Count -eq 0) { $result.Verdict = 'PASS' }
} catch { $result.Error = $_.Exception.ToString() }
[IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
if ($result.Verdict -ne 'PASS') { exit 1 }
