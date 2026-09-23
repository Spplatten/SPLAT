using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> ComplianceTemplates() => new[]
    {
        // --- Audit policy configuration ---------------------------------------------------------
        // auditpol /get requires SeSecurityPrivilege, which an unprivileged operator will not
        // hold. The template is retained because the delegated-auditor case is exactly the
        // persona this product targets, and the prompt is written so a refusal is reported as a
        // delegation gap - never as "auditing is not configured", which would invert the finding.
        Template(
            "compliance-audit-policy",
            "Advanced Audit Policy Configuration Review",
            "Reports the effective advanced audit policy subcategories and whether legacy audit policy is overriding them.",
            CatCompliance,
            ModelPro,
            new SingleToolDefinition(
                "audit_policy_tool",
                "AuditPol Subcategory Reader",
                CmdExe,
                "/c auditpol /get /category:* & echo --- LEGACY POLICY OVERRIDE --- & reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v SCENoApplyLegacyAuditPolicy & echo --- LOG SIZE AND RETENTION --- & wevtutil gl Security & wevtutil gl System",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Compliance Auditor assessing detection coverage. If auditpol reports access denied, state that the operator lacks the audit-read delegation and that coverage could NOT be assessed - do not conclude that auditing is unconfigured. Otherwise, flag any subcategory set to No Auditing that is required for the organisation's framework, prioritising Logon, Logoff, Account Lockout, Credential Validation, Process Creation, and Object Access. Success-only auditing on Logon leaves failed-logon attacks invisible - call that out specifically. If SCENoApplyLegacyAuditPolicy is absent or zero, legacy policy can silently overwrite the advanced subcategories at every GPO refresh, which makes the whole configuration unreliable. Finally, compare the Security log maxSize and retention against the event volume needed to preserve the organisation's required lookback window.",
            null),

        // --- Local security baseline ---------------------------------------------------------------
        Template(
            "compliance-security-baseline",
            "Local Security Policy Baseline Export",
            "Exports the effective local security policy (account, lockout, and rights assignment) for baseline drift comparison.",
            CatCompliance,
            ModelPro,
            new SingleToolDefinition(
                "security_baseline_tool",
                "SecEdit Policy Export Reader",
                CmdExe,
                // secedit writes its export to the process working directory, which the engine
                // sets to the per-mission NT ACL jail. Because the MSIX manifest disables
                // FileSystemWriteVirtualization, the .inf lands in the real jail path rather than
                // being silently redirected into the package's virtual write layer - where the
                // subsequent 'type' would then fail to find it.
                "/c secedit /export /cfg baseline.inf /quiet & type baseline.inf & echo --- PASSWORD POLICY --- & net accounts",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Security Baseline Compliance Analyst. If the export failed or produced no file, report insufficient privilege rather than a clean baseline. Otherwise evaluate: MinimumPasswordLength below the organisation standard, PasswordComplexity disabled, LockoutBadCount of 0 (meaning no lockout threshold at all, permitting unlimited password guessing), ClearTextPassword enabled, and LSAAnonymousNameLookup enabled. In the rights assignment section, flag SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege, and SeImpersonatePrivilege held by anything beyond Administrators, since each is a direct path to SYSTEM. Present findings as a baseline-drift table with the observed value, the expected value, and the risk.",
            null),

        // --- PowerShell logging coverage ------------------------------------------------------------------
        Template(
            "compliance-powershell-logging",
            "PowerShell Logging & Execution Coverage",
            "Verifies script block logging, module logging, transcription, and whether the downgradeable PowerShell v2 engine remains installed.",
            CatCompliance,
            ModelPro,
            new SingleToolDefinition(
                "powershell_logging_tool",
                "PowerShell Policy & Engine Coverage Probe",
                PowerShellExe,
                Ps(@"Write-Output '--- SCRIPT BLOCK LOGGING ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- MODULE LOGGING ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- TRANSCRIPTION ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- LANGUAGE MODE ---'; $ExecutionContext.SessionState.LanguageMode; Write-Output '--- EXECUTION POLICY SCOPES ---'; Get-ExecutionPolicy -List | Format-Table -AutoSize; Write-Output '--- INSTALLED ENGINE VERSIONS ---'; Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName; Write-Output '--- V2 ENGINE PRESENCE ---'; Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Detection Engineering Analyst. EnableScriptBlockLogging not set to 1 means Event 4104 is not generated and obfuscated script attacks leave no forensic record - this is the highest-value finding in this template. Transcription without an OutputDirectory on a protected share means transcripts are written where an attacker can delete them. Note that ExecutionPolicy is NOT a security control and must never be reported as one; a Bypass value is a hygiene observation, not a vulnerability. If the PowerShell 1/PowerShellEngine key is present, the v2 engine is available and an attacker can launch powershell -version 2 to evade all of the above logging entirely - report it as a downgrade-evasion gap. FullLanguage mode is expected; ConstrainedLanguage indicates application control is already active.",
            null),

        // --- Legacy protocol exposure --------------------------------------------------------------------------
        Template(
            "compliance-legacy-protocols",
            "Legacy Protocol & Credential Exposure Sweep",
            "Sweeps for LLMNR, NBT-NS, WPAD, WDigest, and NTLM settings that expose credentials to relay and poisoning attacks.",
            CatCompliance,
            ModelPro,
            new SingleToolDefinition(
                "legacy_protocol_tool",
                "Name Resolution & Credential Protocol Probe",
                PowerShellExe,
                Ps(@"Write-Output '--- LLMNR ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue | Select-Object EnableMulticast | Format-List; Write-Output '--- NBT-NS PER INTERFACE ---'; Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Select-Object PSChildName,NetbiosOptions | Format-Table -AutoSize; Write-Output '--- WPAD SERVICE ---'; Get-Service WinHttpAutoProxySvc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-List; Write-Output '--- WDIGEST ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue | Select-Object UseLogonCredential | Format-List; Write-Output '--- NTLM / LM COMPATIBILITY ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue | Select-Object LmCompatibilityLevel,NoLMHash,RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic | Format-List; Write-Output '--- SMB1 CLIENT DRIVER ---'; Get-Service mrxsmb10 -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-List; Write-Output '--- MDNS ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue | Select-Object EnableMDNS | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are an Offensive Security Consultant writing a defensive finding. On a flat campus subnet, LLMNR (EnableMulticast absent or 1) and NBT-NS (NetbiosOptions other than 2) together allow any device on the VLAN to poison name resolution and capture NetNTLMv2 hashes from every machine that mistypes a hostname - report these two as a single combined finding, because remediating only one leaves the attack path open. WDigest UseLogonCredential 1 places plaintext credentials in LSASS memory. LmCompatibilityLevel below 5 permits NTLMv1, which is trivially crackable. Give the exact GPO path for each remediation and state the compatibility risk of applying it on a campus with legacy lab equipment.",
            null),

        // --- Containment self-proof --------------------------------------------------------------------
        // The one template whose evidence is the sandbox itself. It tries, from inside a mission's
        // own jail and token, what a hijacked tool would try, and prints ALLOWED or BLOCKED for each
        // attempt in its own words - never the operating system's error text, because "Access is
        // denied" in stdout reads as a failed tool to CatalogProducesEvidenceTests and as a container
        // side-effect to NetworkToolsUnderDenialTests. Nothing here asserts a mechanism; each line is
        // what happened. It is on the network-denial list, so the connect attempt meets the container.
        Template(
            "compliance-containment-self-proof",
            "Containment Self-Proof (what this sandbox refuses)",
            "Attempts, from inside a mission's own jail and token, what a hijacked tool would try - writing outside the jail, reading the operator's profile, adding a Run key, reaching the internet, using administrator rights - and reports which the operating system allowed and which it blocked.",
            CatCompliance,
            ModelFlash,
            new SingleToolDefinition(
                "containment_self_proof_tool",
                "Jail, Token, Registry & Network Boundary Probe",
                PowerShellExe,
                Ps(@"$ErrorActionPreference = 'SilentlyContinue'; $v = 'BLOCKED','ALLOWED'; Write-Output '--- WHO THE TOOL RUNS AS ---'; $id = [System.Security.Principal.WindowsIdentity]::GetCurrent(); Write-Output ('User: ' + $id.Name); Write-Output ('Administrators group usable: ' + $v[[int]([System.Security.Principal.WindowsPrincipal]$id).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)]); Write-Output ('Privileges enabled: ' + @(& (Join-Path $env:SystemRoot 'System32\whoami.exe') /priv /fo csv | ConvertFrom-Csv | Where-Object State -eq 'Enabled').Count); Write-Output '--- WRITE INSIDE THE JAIL (working directory) ---'; $inside = Join-Path (Get-Location) 'splat-proof.txt'; Set-Content -Path $inside -Value 'proof'; Write-Output ('Write inside jail: ' + $v[[int](Test-Path $inside)]); Remove-Item $inside; Write-Output '--- WRITE OUTSIDE THE JAIL (Desktop) ---'; $outside = Join-Path ([Environment]::GetFolderPath('Desktop')) 'splat-proof.txt'; Set-Content -Path $outside -Value 'proof'; Write-Output ('Write to Desktop: ' + $v[[int](Test-Path $outside)]); Remove-Item $outside; Write-Output '--- READ THE OPERATOR PROFILE (Documents) ---'; Get-ChildItem -Path ([Environment]::GetFolderPath('MyDocuments')) -Force -ErrorVariable readErr | Out-Null; Write-Output ('List Documents: ' + $v[[int]($readErr.Count -eq 0)]); Write-Output '--- READ SYSTEM32 (a tool needs this to run at all) ---'; Get-ChildItem -Path (Join-Path $env:SystemRoot 'System32') -ErrorVariable sysErr | Select-Object -First 1 | Out-Null; Write-Output ('List System32: ' + $v[[int]($sysErr.Count -eq 0)]); Write-Output '--- ADD A RUN KEY (persistence) ---'; New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SplatProof' -Value 'proof' -ErrorVariable regErr | Out-Null; Write-Output ('Add HKCU Run entry: ' + $v[[int]($regErr.Count -eq 0)]); Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SplatProof'; Write-Output '--- REACH THE INTERNET (TCP 1.1.1.1:443 by raw IP, so DNS is not the reason) ---'; $ok = $false; try { $c = New-Object System.Net.Sockets.TcpClient; $a = $c.BeginConnect('1.1.1.1', 443, $null, $null); $ok = $a.AsyncWaitHandle.WaitOne(4000) -and $c.Connected; $c.Close() } catch { $ok = $false }; Write-Output ('Connect 1.1.1.1:443: ' + $v[[int]$ok]); Write-Output '--- SUMMARY ---'; Write-Output 'Each BLOCKED line is an attempt Windows refused this tool; each ALLOWED line is something this tool could do.'"),
                ExitOk,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a containment auditor reading a probe that ran inside a mission's own sandbox. Every line is an attempt and its outcome in the tool's own words: ALLOWED or BLOCKED. Expected for a governed mission: Administrators group BLOCKED, write inside jail ALLOWED, write to Desktop BLOCKED, list Documents BLOCKED, list System32 ALLOWED, add Run key BLOCKED, connect 1.1.1.1:443 BLOCKED. Mark HEALTHY when every line matches that. Mark CRITICAL if the Desktop write, the Documents read, the Run key, or the Administrators group came back ALLOWED, and name the line. Mark WARNING if only the internet connect came back ALLOWED, and say that on Windows network denial is enforced per template and this one is on that list, so an ALLOWED here means the container was not applied. Quote each line as evidence; do not describe any mechanism the probe did not exercise.",
            null)
    };
}
