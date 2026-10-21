[CmdletBinding()]
param(
    [ValidateSet('Install','Upgrade','Remove','GuestInstall','GuestUpgrade','GuestRemove')][string]$Mode,
    [ValidatePattern('^Splat[A-Za-z0-9]{0,14}$')][string]$Instance = 'SplatManaged',
    [string]$Executable, [string]$Rootfs, [string]$RootfsSha256,
    [string]$OperatorSid, [string]$Egress = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $Instance
$manifestPath = Join-Path $root 'deployment.json'
$configPath = Join-Path $root 'bridge.json'
$state = Join-Path $root 'state'
$installedExe = Join-Path $root 'bin\splat-mcp.exe'
$installedScript = Join-Path $root 'bin\managed-deployment.ps1'
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
$adminSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$systemSid = [Security.Principal.SecurityIdentifier]'S-1-5-18'

function Write-Json($Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
function Set-ProtectedDirectory($Path, [string[]]$Readers, [string]$Writer = '') {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($adminSid)
    foreach ($sid in @($adminSid, $systemSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    foreach ($sid in $Readers) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($Writer) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$Writer, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-Password {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    # Never serialize the credential. SCM stores its own service logon secret.
    ConvertTo-SecureString ('aA1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
}
function Invoke-Guest([string]$Script) {
    # sh reads the script from a file of exact bytes: UTF-8 with no BOM, LF line endings. It used to
    # arrive through Process.StandardInput, whose Windows PowerShell writer prefixes the console
    # encoding's BOM on a UTF-8 system and whose WriteLine ends the text with CRLF. sh then ran
    # '﻿set', wrote /etc/wsl.conf as 'wsl.conf\r', and compared pid 1 against 'systemd\r', so
    # systemd never started and every managed install failed with an empty error (2026-10-14).
    $id = [Guid]::NewGuid().ToString('N')
    $scriptFile = Join-Path $env:TEMP "splat-guest-$id.sh"
    $stdoutFile = Join-Path $env:TEMP "splat-guest-$id.out"
    $stderrFile = Join-Path $env:TEMP "splat-guest-$id.err"
    [IO.File]::WriteAllBytes($scriptFile, [Text.UTF8Encoding]::new($false).GetBytes($Script.Replace("`r", '').TrimEnd("`n") + "`n"))
    try {
        $process = Start-Process -FilePath $wsl -ArgumentList @('-d', $Instance, '-u', 'root', '-e', '/bin/sh', '-s') -NoNewWindow -PassThru `
            -RedirectStandardInput $scriptFile -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        $null = $process.Handle  # Without a handle taken while it runs, Windows PowerShell can lose ExitCode.
        if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'Managed guest command timed out.' }
        $output = ([IO.File]::ReadAllText($stdoutFile) + [IO.File]::ReadAllText($stderrFile)).Replace([string][char]0, '')
        if ($process.ExitCode -ne 0) { throw "Managed guest command failed (exit $($process.ExitCode)): $output" }
        if ($output) { Write-Output $output }
    } finally { Remove-Item -LiteralPath $scriptFile, $stdoutFile, $stderrFile -ErrorAction SilentlyContinue }
}

if ($Mode -in @('GuestInstall', 'GuestUpgrade', 'GuestRemove')) {
    # Only the provisioned account may operate this registration. Parent directories and the
    # manifest are admin-owned; guest output is never interpreted as a Windows command.
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $manifest.AccountSid) { throw 'Wrong guest owner.' }
    if ($manifest.Instance -ne $Instance -or $manifest.Root -ne $root) { throw 'Foreign deployment manifest.' }
    # Host drive access is needed only while the installed executable's daemon is copied in. Mode
    # 0700 and disabled Windows interop keep leased uid 65534 away from it meanwhile, and the final
    # configuration is restored even when the bootstrap fails, so a failed run never leaves the
    # Windows drives mounted in the guest.
    # The daemon guards /etc/sudoers in every lease and refuses a lease whose guarded path does not
    # resolve, so a guest without sudo could run no lease at all (2026-10-20). This guest belongs to
    # SPLAT and has no sudo, so it gets an empty, root-only sudoers: nothing reads it, and a lease has an
    # inode to protect. Only here, never on an operator's own distro, where a stray sudoers would keep
    # a later sudo install from bringing its own.
    function Invoke-Bootstrap([string]$LogName) {
        Invoke-Guest @'
set -eu
printf '[boot]\nsystemd=true\n[automount]\noptions="umask=077"\n[interop]\nenabled=false\nappendWindowsPath=false\n' > /etc/wsl.conf
test -e /etc/sudoers || install -m 0440 -o root -g root /dev/null /etc/sudoers
'@
        & $wsl --terminate $Instance
        if ($LASTEXITCODE -ne 0) { throw 'Could not restart the managed distro.' }
        Invoke-Guest 'test "$(cat /proc/1/comm)" = systemd'
        & $installedExe bridge-bootstrap --configuration $configPath > (Join-Path $state $LogName) 2>&1
        $bootstrapExit = $LASTEXITCODE
        Invoke-Guest @'
set -eu
printf '[boot]\nsystemd=true\n[automount]\nenabled=false\n[interop]\nenabled=false\nappendWindowsPath=false\n' > /etc/wsl.conf
'@
        & $wsl --terminate $Instance
        if ($LASTEXITCODE -ne 0) { throw 'Could not apply final guest isolation.' }
        if ($bootstrapExit -ne 0) { throw 'Managed daemon bootstrap did not prove enforcement.' }
    }
    try {
        if ($Mode -eq 'GuestInstall') {
            if ((& $wsl --list --quiet | Out-String).Replace([string][char]0, '').Trim()) { throw 'The new service account already has a distro.' }
            [IO.File]::WriteAllText((Join-Path $env:USERPROFILE '.wslconfig'), "[wsl2]`nkernelCommandLine=lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf`n", [Text.UTF8Encoding]::new($false))
            & $wsl --import $Instance (Join-Path $state 'distro') (Join-Path $root $manifest.RootfsFile) --version 2
            if ($LASTEXITCODE -ne 0) { throw 'WSL import failed.' }
            Invoke-Bootstrap 'bootstrap.log'
        } elseif ($Mode -eq 'GuestUpgrade') {
            # The registration and its state stay; only the daemon the new executable carries moves in.
            $names = @((& $wsl --list --quiet | Out-String).Replace([string][char]0, '').Split("`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($names -notcontains $Instance) { throw 'The managed distro is missing; an upgrade cannot recreate it.' }
            Invoke-Bootstrap 'upgrade-bootstrap.log'
        } else {
            $names = @((& $wsl --list --quiet | Out-String).Replace([string][char]0, '').Split("`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (@($names | Where-Object { $_ -ne $Instance }).Count) { throw 'Foreign distros under service account; refusing removal.' }
            if ($names -contains $Instance) {
                & $wsl --terminate $Instance
                & $wsl --unregister $Instance
                if ($LASTEXITCODE -ne 0) { throw 'Managed distro removal failed.' }
            }
            # There can be no unrelated guest in this account. This releases its swap/profile;
            # it never invokes shutdown in the operator account.
            & $wsl --shutdown
            if ($LASTEXITCODE -ne 0) { throw 'Managed account VM did not stop.' }
        }
        Write-Json (Join-Path $state "$Mode.json") @{ Success = $true; AccountSid = $manifest.AccountSid; At = [DateTimeOffset]::UtcNow.ToString('o') }
        exit 0
    } catch {
        Write-Json (Join-Path $state "$Mode.json") @{ Success = $false; Error = $_.Exception.Message }
        throw
    }
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Managed deployment requires an elevated Windows terminal.' }

function Start-Owner([PSCredential]$Credential, [string]$Action) {
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode {1} -Instance {2}' -f $installedScript, $Action, $Instance
    $receiptPath = Join-Path $state "$Action.json"
    # A receipt from an earlier attempt must not answer for this one. It is kept beside it, renamed,
    # because the state directory is the deployment's record.
    if (Test-Path -LiteralPath $receiptPath) {
        Move-Item -LiteralPath $receiptPath -Destination ('{0}.{1}.previous' -f $receiptPath, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    }
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Credential $Credential -LoadUserProfile -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(300000)) { $process.Kill(); throw 'Service-account bootstrap timed out; deployment retained for managed unmount.' }
    # The receipt is the verdict, because it is the one place the account's run records why it
    # failed. Testing the exit code first turned every failure into "inspect state", which hid that
    # reason, and an exit code this session cannot read compared as non-zero.
    if (-not (Test-Path -LiteralPath $receiptPath)) {
        throw "Service-account $Action stopped before writing its receipt (exit code '$($process.ExitCode)'); inspect $state."
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if (-not $receipt.Success) { throw "Service-account $Action failed: $($receipt.Error)" }
}
function Assert-Manifest {
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Deployment root is a reparse point.' }
    $script:manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.Schema -ne 1 -or $manifest.Instance -ne $Instance -or $manifest.Root -ne $root) { throw 'Foreign deployment manifest.' }
    $acl = Get-Acl -LiteralPath $manifestPath
    if ($acl.Owner -notin @($adminSid.Translate([Security.Principal.NTAccount]).Value, $systemSid.Translate([Security.Principal.NTAccount]).Value)) { throw 'Manifest is not administrator-owned.' }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band 0xD0156) -and
            $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($adminSid.Value, $systemSid.Value)) { throw 'Manifest is writable by an untrusted principal.' }
    }
}

if ($Mode -eq 'Remove') {
    Assert-Manifest
    $account = Get-LocalUser -Name $Instance -ErrorAction SilentlyContinue
    if ($account -and $account.SID.Value -ne $manifest.AccountSid) { throw 'Account was substituted; refusing removal.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='$Instance'"
    if ($service) {
        if ($service.PathName -ne $manifest.ServiceCommand -or $service.StartName -ne ".\$Instance") { throw 'Service was substituted; refusing removal.' }
        Stop-Service -Name $Instance -ErrorAction Stop
    }
    if ($account) {
        # Rotate only this manifest-owned account. No password is kept in a file for uninstall.
        $password = New-Password
        Set-LocalUser -SID $account.SID -Password $password
        Start-Owner ([PSCredential]::new(".\$Instance", $password)) 'GuestRemove'
    }
    if ($service) {
        $result = Invoke-CimMethod -InputObject $service -MethodName Delete
        if ($result.ReturnValue -ne 0) { throw 'Service deletion failed.' }
    }
    if ($account) { Remove-LocalUser -SID $account.SID }
    $profile = Get-CimInstance Win32_UserProfile | Where-Object SID -EQ $manifest.AccountSid
    # WSL and the profile service let go of a removed account's profile only after the processes that
    # held it have exited, so the first attempt can find it in use (0x80070020, 2026-10-21). Every step
    # above skips what is already gone, so a removal that still cannot finish here says so and is re-run.
    for ($attempt = 1; $profile; $attempt++) {
        try { $profile | Remove-CimInstance; $profile = $null }
        catch {
            if ($attempt -ge 24) { throw "The removed account's profile is still in use after two minutes. The service, account and distro are already gone; restart Windows and run this unmount again to finish. ($($_.Exception.Message))" }
            Start-Sleep -Seconds 5
        }
    }
    # Preserve the keyed audit ledger and receipts. Dropping an endpoint must not erase evidence.
    Set-ProtectedDirectory $state @()
    $manifest.Status = 'Removed; audit state retained'
    Write-Json $manifestPath $manifest
    # The retained root moves aside, readable by administrators only. Left in place it refused every
    # reinstall, and its bridge.json kept the desktop failing closed against a service that was gone.
    $archive = '{0}.removed-{1}' -f $root, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    try {
        Set-ProtectedDirectory $root @()
        Rename-Item -LiteralPath $root -NewName (Split-Path -Leaf $archive)
    } catch {
        Write-Warning "Removed $Instance, but its retained state could not be moved aside ($($_.Exception.Message)). It is still at $root; move it before reinstalling."
        exit 0
    }
    Write-Output "Removed $Instance service/account/distro; protected audit state retained at $archive."
    exit 0
}

if ($Mode -eq 'Upgrade') {
    Assert-Manifest
    if ([string]$manifest.Status -notlike 'Installed*') { throw "Instance $Instance is not installed (status: $($manifest.Status))." }
    $account = Get-LocalUser -Name $Instance -ErrorAction SilentlyContinue
    if (-not $account -or $account.SID.Value -ne $manifest.AccountSid) { throw 'Account is missing or was substituted; refusing upgrade.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='$Instance'"
    if (-not $service -or $service.PathName -ne $manifest.ServiceCommand -or $service.StartName -ne ".\$Instance") { throw 'Service is missing or was substituted; refusing upgrade.' }
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Published executable is missing.' }
    if ([IO.Path]::GetFullPath($Executable) -eq [IO.Path]::GetFullPath($installedExe)) { throw 'Run the upgrade from the newly published splat-mcp.exe, not the installed copy.' }
    $newHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
    if ($newHash -eq (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash) {
        Write-Output "$Instance already runs this build ($newHash); nothing to upgrade."
        exit 0
    }
    # The guest step runs as the service account, whose password nobody keeps, so each start rotates
    # it and hands the new one to the service manager before the account runs anything.
    function Start-Build {
        $password = New-Password
        Set-LocalUser -SID $account.SID -Password $password
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        try {
            $change = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{
                StartName = ".\$Instance"; StartPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($change.ReturnValue -ne 0) { throw "The service manager refused the rotated credential ($($change.ReturnValue))." }
        Start-Owner ([PSCredential]::new(".\$Instance", $password)) 'GuestUpgrade'
        $errorLog = Join-Path $state 'service-error.log'
        $before = if (Test-Path -LiteralPath $errorLog) { (Get-Item -LiteralPath $errorLog).Length } else { 0 }
        Start-Service -Name $Instance
        Start-Sleep -Seconds 15
        $after = if (Test-Path -LiteralPath $errorLog) { (Get-Item -LiteralPath $errorLog).Length } else { 0 }
        if ((Get-Service -Name $Instance).Status -ne 'Running' -or $after -ne $before) { throw 'The service did not stay running; see service-error.log in the private state.' }
    }
    $previousExe = "$installedExe.previous"
    Stop-Service -Name $Instance -ErrorAction Stop
    Copy-Item -LiteralPath $installedExe -Destination $previousExe -Force
    try {
        # The new script replaces the old one and stays even on rollback: it is the one that knows
        # GuestUpgrade, which a rollback needs to put the previous build's daemon back in the guest.
        Copy-Item -LiteralPath $Executable -Destination $installedExe -Force
        Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force
        Start-Build
    } catch {
        $failure = $_.Exception.Message
        Stop-Service -Name $Instance -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $previousExe -Destination $installedExe -Force
        try { Start-Build; $restored = 'the previous build is running again' }
        catch { $restored = "the previous build did not restart either ($($_.Exception.Message)), so the service is stopped" }
        throw "Upgrade failed ($failure); $restored."
    }
    $manifest | Add-Member -NotePropertyName ExecutableSha256 -NotePropertyValue $newHash -Force
    $manifest | Add-Member -NotePropertyName UpgradedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
    $manifest.Status = 'Installed; requires managed boundary probe'
    Write-Json $manifestPath $manifest
    Write-Output "Upgraded $Instance to $newHash; the previous build is kept as $previousExe. Run the managed boundary probe again."
    exit 0
}

if ($Mode -ne 'Install') { throw 'Specify Install, Upgrade or Remove.' }
# wsl --import is handed a file whose name says what it holds. Canonical's .wsl images are gzip, and a
# fixed rootfs.tar.xz name mislabelled exactly the archive this deployment's runbook points at.
function Get-RootfsName([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try { $head = New-Object byte[] 262; $read = $stream.Read($head, 0, $head.Length) } finally { $stream.Dispose() }
    if ($read -ge 2 -and $head[0] -eq 0x1F -and $head[1] -eq 0x8B) { return 'rootfs.tar.gz' }
    if ($read -ge 6 -and $head[0] -eq 0xFD -and $head[1] -eq 0x37 -and $head[2] -eq 0x7A -and $head[3] -eq 0x58 -and $head[4] -eq 0x5A -and $head[5] -eq 0x00) { return 'rootfs.tar.xz' }
    if ($read -eq 262 -and [Text.Encoding]::ASCII.GetString($head, 257, 5) -eq 'ustar') { return 'rootfs.tar' }
    throw 'The rootfs is not a tar, tar.gz or tar.xz archive.'
}
if (-not (Test-Path -LiteralPath $Rootfs -PathType Leaf) -or $RootfsSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
    (Get-FileHash -LiteralPath $Rootfs -Algorithm SHA256).Hash -ne $RootfsSha256) { throw 'Rootfs must match its independently obtained publisher SHA-256.' }
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Published executable is missing.' }
$rootfsFile = Get-RootfsName $Rootfs
$operators = @($OperatorSid.Split(',') | Select-Object -Unique)
foreach ($sid in $operators) {
    if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Explicit Windows account SIDs are required.' }
    $null = [Security.Principal.SecurityIdentifier]$sid
}
if (Test-Path -LiteralPath $root) { throw 'Deployment directory exists; refusing to adopt or overwrite it.' }
if (Get-LocalUser -Name $Instance -ErrorAction SilentlyContinue) { throw 'Account exists; refusing to adopt it.' }
if (Get-Service -Name $Instance -ErrorAction SilentlyContinue) { throw 'Service exists; refusing to adopt it.' }
if (Test-Path -LiteralPath (Join-Path $env:SystemDrive "Users\$Instance")) { throw 'An account profile path already exists.' }

# LSA changes only the new account's service-logon right; no machine-wide policy import is used.
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class SplatServiceLogon {
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public uint Length; public IntPtr Root, Name; public uint Flags; public IntPtr Descriptor, Qos; }
    [StructLayout(LayoutKind.Sequential)] struct Unicode { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref Attributes attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr handle, byte[] sid, Unicode[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
    public static void Grant(string value) {
        var attributes = new Attributes { Length = (uint)Marshal.SizeOf(typeof(Attributes)) };
        IntPtr policy; uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out policy);
        if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
        var right = "SeServiceLogonRight"; IntPtr buffer = Marshal.StringToHGlobalUni(right);
        try {
            var sid = new SecurityIdentifier(value); var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            status = LsaAddAccountRights(policy, bytes, new[] { new Unicode { Length = (ushort)(right.Length * 2), MaximumLength = (ushort)((right.Length + 1) * 2), Buffer = buffer } }, 1);
            if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
        } finally { Marshal.FreeHGlobal(buffer); LsaClose(policy); }
    }
}
'@
$null = New-Item -ItemType Directory -Path $root
Set-ProtectedDirectory $root @()
$password = New-Password
$account = New-LocalUser -Name $Instance -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'SPLAT managed endpoint; do not use interactively'
$manifest = [ordered]@{ Schema = 1; Instance = $Instance; Root = $root; AccountSid = $account.SID.Value; Status = 'Installing'; ServiceCommand = ('"{0}" bridge-service --configuration "{1}"' -f $installedExe, $configPath); RootfsFile = $rootfsFile }
Write-Json $manifestPath $manifest
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
Set-ProtectedDirectory $root (@($account.SID.Value) + $operators)
$null = New-Item -ItemType Directory -Path (Join-Path $root 'bin'), $state, (Join-Path $root 'workspace')
Set-ProtectedDirectory $state @() $account.SID.Value
Set-ProtectedDirectory (Join-Path $root 'workspace') @() $account.SID.Value
Copy-Item -LiteralPath $Executable -Destination $installedExe
Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript
Copy-Item -LiteralPath $Rootfs -Destination (Join-Path $root $rootfsFile)
if ((Get-FileHash -LiteralPath (Join-Path $root $rootfsFile)).Hash -ne $RootfsSha256) { throw 'Copied rootfs hash changed.' }
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
Write-Json $configPath @{ Schema = 1; ServiceName = $Instance; ServiceSid = $account.SID.Value; PipeName = "$Instance-bridge"; Distribution = $Instance;
    Port = $port; StateDirectory = $state; WorkspaceDirectory = (Join-Path $root 'workspace'); OperatorSids = $operators; Egress = $Egress }
$key = New-Object byte[] 64
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($key); [IO.File]::WriteAllBytes((Join-Path $state 'ledger.key'), $key) } finally { [Array]::Clear($key, 0, $key.Length); $rng.Dispose() }
[SplatServiceLogon]::Grant($account.SID.Value)
$credential = [PSCredential]::new(".\$Instance", $password)
Start-Owner $credential 'GuestInstall'
# Only this exact newly created staging file is removed. The guest's disk is never the input image.
Remove-Item -LiteralPath (Join-Path $root $rootfsFile)
$null = New-Service -Name $Instance -BinaryPathName $manifest.ServiceCommand -Credential $credential -StartupType Automatic -Description 'SPLAT Windows caller boundary and private policy/audit host'
Start-Service -Name $Instance
$manifest.Status = 'Installed; requires managed boundary probe'
Write-Json $manifestPath $manifest
Write-Output "Installed $Instance. Client: splat-mcp managed --configuration `"$configPath`"."
