param(
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{32}$')][string]$TaskId,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($env:SPLAT_A2A_CALLER_TOKEN)) { throw 'Set SPLAT_A2A_CALLER_TOKEN for the task owner.' }
# Pass 1 is an authenticated control-path experiment, not a sensor adapter. It must only name a
# disposable, already admitted task owned by this token. OS TLS validation is left enabled.
$request = @{ jsonrpc='2.0'; id='manual-cancel'; method='CancelTask'; params=@{ id=$TaskId; historyLength=0 } }
$headers = @{
    Authorization=('Bearer ' + $env:SPLAT_A2A_CALLER_TOKEN)
    'A2A-Version'='1.0'
    'A2A-Extensions'='urn:splat:a2a:template-lease:v1'
}
$response = Invoke-RestMethod -Method Post -Uri "https://127.0.0.1:$Port/a2a" -Headers $headers -ContentType 'application/json' -Body ($request | ConvertTo-Json -Depth 5) -TimeoutSec 10
if ($response.error) { throw ('Control rejected request: ' + $response.error.code) }
if ($response.result.id -ne $TaskId) { throw 'Response names a different task.' }
# The full result retains artifacts for independent receipt verification. A terminal task state
# or cancellationRequested=true is not itself proof that the cgroup drained.
$response.result | ConvertTo-Json -Depth 20
