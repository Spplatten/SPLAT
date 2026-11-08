# SPDX-License-Identifier: AGPL-3.0-only
# Option B in one command: the end-to-end cancellation proof on the real kernel, driven by a labelled
# synthetic control event (docs/FALCON-CANCELLATION-PILOT.md, "One-command run"). The operator runs it
# at a milestone, because three steps need what an agent session must not do:
#   - it installs the committed witness and fixture in the guest as root;
#   - it derives the daemon outcome-key pin as root, unless -DaemonKeySha256 supplies one;
#   - it asks Windows to trust two one-day certificates for 127.0.0.1, and removes them when it ends.
# -DryRun does everything else and starts no workload: it stages and hashes the committed bytes, reads
# what the guest has deployed and its ceiling, builds, makes and inspects the certificates, imports the
# pilot agent into a throwaway database, and starts and stops the A2A host on it.
# Evidence goes to the ignored private/, like the native witness check.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$Distro,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$DaemonKeySha256,
    [string]$DotNetPath = (Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'),
    [switch]$DryRun)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss')
$run = Join-Path $repoRoot "private\cancellation-pilot-$stamp"
$state = Join-Path $run 'state'
$pilotDir = '/usr/local/lib/splat/pilot'
$utf8 = New-Object Text.UTF8Encoding($false)
$sha256 = [Security.Cryptography.SHA256]::Create()
function Hex([byte[]]$bytes) { return ([BitConverter]::ToString($sha256.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant() }
function Random([int]$count) { $bytes = New-Object byte[] $count; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); return $bytes }

# Reads and installs only; no shell between an argument and its program.
function Guest([string[]]$argv, [switch]$Root) {
    $prefix = @('-d', $Distro); if ($Root) { $prefix += @('-u', 'root') }
    $out = & wsl.exe @prefix -e @argv
    if ($LASTEXITCODE -ne 0) { throw "Guest command failed in '$Distro': $($argv -join ' ')" }
    return $out
}
function GuestTest([string[]]$argv) { & wsl.exe -d $Distro -e @argv; return $LASTEXITCODE -eq 0 }
function WslPath([string]$path) {
    $converted = & wsl.exe -d $Distro -e wslpath -a -u $path.Replace('\', '/')
    if ($LASTEXITCODE -ne 0 -or -not $converted) { throw "WSL distribution '$Distro' cannot map $path." }
    return ([string]$converted).Trim()
}

# An end-entity certificate for 127.0.0.1 alone: once trusted it vouches for itself and can sign nothing.
function New-PilotCertificate([string]$name, [string]$password) {
    $key = New-Object Security.Cryptography.RSACng 2048
    $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest("CN=SPLAT cancellation pilot $name",
        $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = New-Object Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    $san.AddIpAddress([Net.IPAddress]::Loopback)
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $true)))
    $usages = New-Object Security.Cryptography.OidCollection
    [void]$usages.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($usages, $false)))
    $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment', $true)))
    $now = [DateTimeOffset]::UtcNow
    $cert = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(1))
    $pfx = Join-Path $state "$name.pfx"; $cer = Join-Path $state "$name.cer"
    [IO.File]::WriteAllBytes($pfx, $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    [IO.File]::WriteAllBytes($cer, $cert.RawData)
    $public = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $cert.RawData)
    $ip = $public.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) }
    $basic = $public.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    if (-not ($ip -match '127\.0\.0\.1') -or $basic.CertificateAuthority) { throw "Certificate $name is not an end-entity certificate for 127.0.0.1." }
    return [pscustomobject]@{ Pfx = $pfx; Cer = $cer; Thumbprint = $public.Thumbprint; Sha256 = (Hex $cert.RawData); Certificate = $public }
}
function Test-Trusted($certificate) {
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    return $chain.Build($certificate)
}
function Get-FreePort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop(); return $port
}
function Wait-Listening($process, [int]$port, [string]$log) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) { throw "The A2A host exited ($($process.ExitCode)); see $log" }
        $client = New-Object Net.Sockets.TcpClient
        try { $client.Connect([Net.IPAddress]::Loopback, $port); return } catch { Start-Sleep -Milliseconds 250 } finally { $client.Dispose() }
    }
    throw "The A2A host did not listen within 60 s; see $log"
}

$trusted = @(); $a2aHost = $null; $code = 2
New-Item -ItemType Directory -Path $state -Force | Out-Null
try {
    # The committed bytes, not the CRLF working copy: the witness refuses to run unless its pin matches
    # its own file. Both files are ASCII, so git's lines rejoined with LF reproduce the blob, as checked.
    $staged = @{}
    foreach ($name in 'witness.py', 'workload_fixture.py') {
        $path = "native/experiments/alert-cancellation/$name"
        $lines = & git -C $repoRoot show "HEAD:$path"
        if ($LASTEXITCODE -ne 0) { throw "Cannot read $path at HEAD." }
        $file = Join-Path $state $name
        [IO.File]::WriteAllText($file, (($lines -join "`n") + "`n"), $utf8)
        if ((& git -C $repoRoot rev-parse "HEAD:$path") -ne (& git -C $repoRoot hash-object --no-filters -- $file)) { throw "Staged $name is not the committed blob." }
        $staged[$name] = Hex ([IO.File]::ReadAllBytes($file))
    }

    # SPLAT's host reads the daemon token from the default distribution, and its leases run wherever that
    # daemon runs; native identities read from any other guest would name the wrong processes.
    $default = @((& wsl.exe -l -v) -replace "`0", '' | ForEach-Object { if ($_ -match '^\*\s+(\S+)') { $Matches[1] } })
    if ($default.Count -ne 1 -or $default[0] -ne $Distro) {
        throw "SPLAT's host reaches the daemon of the default WSL distribution ($($default -join ', ')), not '$Distro'."
    }
    Write-Output "Guest '$Distro': $(Guest @('/usr/bin/python3', '--version'))"
    # The pilot templates run /usr/bin/python3 for 300 s; the ceiling shortens longer leases, never refuses them.
    $readable = GuestTest @('/usr/bin/test', '-r', '/etc/splat/policy.json')
    if (-not (GuestTest @('/usr/bin/test', '-e', '/etc/splat/policy.json'))) {
        Write-Output 'Ceiling: none installed, so nothing narrows the pilot leases.'
    } elseif (-not $readable -and $DryRun) {
        Write-Output 'Ceiling: readable only by root; the real run reads it as root.'
    } else {
        $ceiling = (Guest -Root:(-not $readable) @('/usr/bin/cat', '/etc/splat/policy.json')) -join "`n" | ConvertFrom-Json
        $admits = @($ceiling.allowedExecPrefixes | Where-Object { '/usr/bin/python3'.StartsWith($(if ($_.EndsWith('/')) { $_ } else { "$_/" })) })
        if ($admits.Count -eq 0) { throw 'The guest ceiling does not admit /usr/bin/python3.' }
        if ($null -ne $ceiling.maxLeaseDurationSeconds -and $ceiling.maxLeaseDurationSeconds -lt 300) { throw "The guest ceiling caps leases below the pilot's 300 s." }
        Write-Output 'Ceiling: admits /usr/bin/python3 for 300 s.'
    }

    if (-not $DryRun) {
        foreach ($name in $staged.Keys) {
            Guest -Root @('/usr/bin/install', '-D', '-o', 'root', '-g', 'root', '-m', '0644', (WslPath (Join-Path $state $name)), "$pilotDir/$name") | Out-Null
        }
    }
    foreach ($name in $staged.Keys) {
        $target = "$pilotDir/$name"
        if (-not (GuestTest @('/usr/bin/test', '-f', $target))) {
            if ($DryRun) { Write-Output "Deployed ${name}: absent (the real run installs it)"; continue }
            throw "$target was not installed."
        }
        $deployed = ([string](Guest @('/usr/bin/sha256sum', $target))).Split(' ')[0]
        $owner = [string](Guest @('/usr/bin/stat', '-c', '%U:%a', $target))
        $verdict = if ($deployed -eq $staged[$name] -and $owner.Trim() -eq 'root:644') { 'the committed bytes, root:644' } else { "differs ($owner)" }
        if (-not $DryRun -and $verdict -ne 'the committed bytes, root:644') { throw "$target is not the committed bytes, root-owned 0644." }
        Write-Output "Deployed ${name}: $verdict"
    }

    if (-not $DaemonKeySha256 -and -not $DryRun) {
        # The pin comes from the guest's own key file before the run, never from the receipt under test.
        $line = [string](Guest -Root @('/bin/sh', '-c', 'openssl rsa -in /etc/splat/outcome.key -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum'))
        $DaemonKeySha256 = $line.Split(' ')[0]
        if ($DaemonKeySha256 -notmatch '^[0-9a-f]{64}$' -or $DaemonKeySha256 -eq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
            throw 'Could not derive the daemon outcome-key pin from /etc/splat/outcome.key.'
        }
        Write-Output "Daemon outcome key (from the guest's key file): $DaemonKeySha256"
    }

    foreach ($project in 'src\splat-alert-sidecar\splat-alert-sidecar.csproj', 'src\splat-mcp\splat-mcp.csproj') {
        & $DotNetPath build (Join-Path $repoRoot $project) -c Release -m:1 -p:UseSharedCompilation=false -nologo -v:q
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
    }
    $sidecarDll = Join-Path $repoRoot 'src\splat-alert-sidecar\bin\Release\net10.0\splat-alert-sidecar.dll'
    $mcpDll = Join-Path $repoRoot 'src\splat-mcp\bin\Release\net10.0-windows\splat-mcp.dll'
    foreach ($built in $sidecarDll, $mcpDll) { if (-not (Test-Path -LiteralPath $built)) { throw "Missing build output $built." } }

    $password = [Convert]::ToBase64String((Random 24))
    $env:SPLAT_A2A_CERT_PASSWORD = $password; $env:SPLAT_ALERT_CERT_PASSWORD = $password
    $a2aCert = New-PilotCertificate 'a2a' $password
    $sidecarCert = New-PilotCertificate 'sidecar' $password
    if ($DryRun) {
        Write-Output "Certificates: end-entity, 127.0.0.1 only; trusted now: $(Test-Trusted $a2aCert.Certificate) (the real run asks Windows to trust them)"
    } else {
        foreach ($cert in $a2aCert, $sidecarCert) {
            # Windows asks the operator to confirm each one. Declining stops the run here.
            Import-Certificate -FilePath $cert.Cer -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
            $trusted += $cert.Thumbprint
            if (-not (Test-Trusted $cert.Certificate)) { throw "Windows does not trust the pilot certificate $($cert.Thumbprint)." }
        }
    }

    $env:SPLAT_DB_PATH = Join-Path $state 'pilot.db'
    $contract = Join-Path $repoRoot 'native\experiments\alert-cancellation\cancellation-pilot.contract.json'
    $imported = (& $DotNetPath $mcpDll import-agent --cancellation-pilot $contract) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $imported.contractSha256) { throw 'The pilot agent did not import.' }
    Write-Output "Pilot agent: $($imported.agentId)@$($imported.contractSha256)"

    $a2aPort = Get-FreePort; $sidecarPort = Get-FreePort
    while ($sidecarPort -eq $a2aPort) { $sidecarPort = Get-FreePort }
    $ownerBytes = Random 32
    $ownerToken = [Convert]::ToBase64String($ownerBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $config = [ordered]@{ schemaVersion = 1; agentId = $imported.agentId; agentVersion = $imported.contractSha256; port = $a2aPort
        certificateFile = $a2aCert.Pfx
        callers = @([ordered]@{ tenantId = 'pilot'; callerId = 'operator'; tokenSha256 = (Hex ([Text.Encoding]::ASCII.GetBytes($ownerToken)))
            skills = @('pilot_target', 'pilot_control'); expiresUtc = [DateTime]::UtcNow.AddHours(1).ToString('o') })
        maxConcurrentTasks = 2; maxTasks = 8; cancellationPilot = $true }
    $a2aJson = Join-Path $state 'a2a.json'
    [IO.File]::WriteAllText($a2aJson, (ConvertTo-Json -InputObject $config -Depth 5), $utf8)
    $hostLog = Join-Path $run 'a2a-host.err.log'
    $a2aHost = Start-Process -FilePath $DotNetPath -ArgumentList "`"$mcpDll`" a2a --configuration `"$a2aJson`"" -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $run 'a2a-host.out.log') -RedirectStandardError $hostLog
    $null = $a2aHost.Handle
    Wait-Listening $a2aHost $a2aPort $hostLog
    Write-Output "A2A host: listening on 127.0.0.1:$a2aPort with the pilot agent loaded."
    if ($DryRun) {
        $code = 0
        Write-Output "DRY RUN complete; no workload was started. $run"
        return
    }

    $request = [ordered]@{ version = 1; a2aPort = $a2aPort; a2aCertificateSha256 = $a2aCert.Sha256; sidecarPort = $sidecarPort
        sidecarCertificateFile = $sidecarCert.Pfx; sidecarCertificateSha256 = $sidecarCert.Sha256; distribution = $Distro
        guestWitnessPath = "$pilotDir/witness.py"; guestWitnessSha256 = $staged['witness.py']; daemonKeySha256 = $DaemonKeySha256
        timeoutSeconds = 60; operatorEvidenceReference = "b-synthetic-control-$stamp" }
    $requestJson = Join-Path $state 'request.json'
    [IO.File]::WriteAllText($requestJson, (ConvertTo-Json -InputObject $request), $utf8)
    $env:SPLAT_A2A_CALLER_TOKEN = $ownerToken
    & $DotNetPath $sidecarDll --orchestrate-cancellation-pilot $requestJson (Join-Path $run 'pilot')
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "The cancellation proof did not pass (exit $code); run directory: $run" }
    Write-Output "PASS_CANCELLATION_CHAIN; evidence: $(Join-Path $run 'pilot\evidence')"
} finally {
    foreach ($name in 'SPLAT_A2A_CALLER_TOKEN', 'SPLAT_A2A_CERT_PASSWORD', 'SPLAT_ALERT_CERT_PASSWORD', 'SPLAT_DB_PATH') {
        Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
    }
    if ($null -ne $a2aHost -and -not $a2aHost.HasExited) { Stop-Process -Id $a2aHost.Id -Force; $a2aHost.WaitForExit(5000) | Out-Null }
    foreach ($thumbprint in $trusted) {
        # Windows asks again; declining leaves a certificate that expires within a day.
        Remove-Item -LiteralPath "Cert:\CurrentUser\Root\$thumbprint" -ErrorAction Continue
    }
    Get-ChildItem -LiteralPath $state -Filter '*.pfx' -ErrorAction SilentlyContinue | Remove-Item -Force
}
