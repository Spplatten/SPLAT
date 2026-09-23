using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> EndpointSecurityTemplates() => new[]
    {
        // --- Defender posture -------------------------------------------------------------------
        // Defender's WMI provider grants Authenticated Users read access, so the restricted
        // Medium-integrity token is left ENABLED: the template can observe Defender policy but
        // structurally cannot mutate it, even if the model is prompt-injected by hostile output.
        Template(
            "secops-defender-status",
            "Defender Endpoint & Tamper Protection Audit",
            "Audits Microsoft Defender real-time protection state, tamper protection source, signature freshness, and attack surface reduction rules. Scan exclusions are shown only where Windows lets a non-administrator read them.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "defender_status_tool",
                "Defender Computer Status & Preference Query",
                PowerShellExe,
                Ps(@"Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,TamperProtectionSource,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,NISSignatureVersion,DefenderSignaturesOutOfDate,QuickScanAge,FullScanAge,AMRunningMode | Format-List; Write-Output '--- DEFENDER POLICY PREFERENCES ---'; Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,DisableIOAVProtection,MAPSReporting,SubmitSamplesConsent,PUAProtection,ExclusionPath,ExclusionProcess,ExclusionExtension | Format-List; Write-Output '--- ATTACK SURFACE REDUCTION RULES ---'; $asrIds = @(Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue); Write-Output ('ASR RULES CONFIGURED: ' + $asrIds.Count); $asrIds; Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are an Endpoint Security Engineer. Mark the endpoint NON-COMPLIANT if tamper protection is off, real-time or behavior monitoring is disabled, signatures are older than 3 days, DefenderSignaturesOutOfDate is True, or AMRunningMode is anything other than Normal. Treat every ExclusionPath/ExclusionProcess entry as a potential persistence blind spot and call out broad exclusions (drive roots, profile roots, wildcards) explicitly. For ASR, the Ids and Actions arrays are positional - pair them by index and report any rule set to 0 (Disabled) or 6 (Warn) rather than 1 (Block); 'ASR RULES CONFIGURED: 0' means no rule is configured on this host, which is itself a finding, not missing data. This sensor runs without administrator rights by design - SPLAT strips them before the tool starts, and an elevated console does not change that - and Windows Defender shows exclusions only to administrators, so 'N/A: Must be an administrator to view exclusions' is the expected reading here, not a failure of the audit: report exclusions as NOT VERIFIABLE FROM THIS SENSOR, do not recommend re-running with elevated credentials, and do not lower the status for that alone.",
            null),

        // --- Process & handle inspection -------------------------------------------------------
        Template(
            "secops-process-scan",
            "Active Process & Handle Security Inspector",
            "Queries active running processes, parent process IDs, and memory utilization.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "process_tree_tool",
                "Process Tree & Image Path Reporter",
                PowerShellExe,
                // tasklist /v looks up a window title and an owner for every process: 105 s under
                // the restricted token against 0.9 s without /v. That ran past the 45 s timeout, the
                // job was killed (99 is the launcher's own timeout code, not tasklist's) and the model
                // got a truncated list. It never had parent IDs or image paths either, both of which
                // the prompt needs. CommandLine is left out on purpose: it is where tokens passed as
                // arguments live, and DLP should not be the only thing between them and the model.
                Ps(@"Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,SessionId,WorkingSetSize,ExecutablePath | Sort-Object ProcessId | ConvertTo-Csv -NoTypeInformation"),
                ExitOkOrPartial,
                TimeoutSeconds: 45,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 60),
            "You are a Tier-2 SecOps Analyst. Walk the process tree by ParentProcessId and flag parent-child pairs that do not belong together, such as an Office application or a browser starting a shell or a script host. Flag any system-named binary (svchost.exe, lsass.exe, csrss.exe, services.exe) whose ExecutablePath is outside System32, any executable running from a user-writable directory such as AppData or Temp, and duplicated instances of single-instance system processes (lsass.exe, wininit.exe, services.exe). ExecutablePath is blank for processes this restricted token cannot open, which is normal for SYSTEM processes and is not a finding by itself.",
            null),

        // --- Persistence / autoruns ---------------------------------------------------------------
        Template(
            "endpoint-persistence-audit",
            "Autorun & Persistence Mechanism Audit",
            "Enumerates Run keys, auto-start services, and enabled scheduled tasks to surface unauthorised persistence footholds.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "persistence_audit_tool",
                "Registry Run Key, Service & Scheduled Task Enumerator",
                PowerShellExe,
                // Filtering uses comparison-statement syntax (Where-Object Prop -eq Value) rather
                // than a scriptblock. The execution engine performs literal {Token} substitution
                // over this argument string, so keeping the command entirely free of curly braces
                // removes any possibility of a PowerShell block colliding with a parameter name.
                Ps(@"Write-Output '--- HKLM RUN KEYS ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- HKCU RUN KEYS ---'; Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- WINLOGON SHELL / USERINIT ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object Shell,Userinit,AppSetup | Format-List; Write-Output '--- AUTO-START SERVICES ---'; Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object StartMode -eq 'Auto' | Select-Object Name,DisplayName,PathName,StartName,State | Format-Table -AutoSize; Write-Output '--- ENABLED SCHEDULED TASKS ---'; Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne 'Disabled' | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(384),
                MaxCpuPercent: 60),
            "You are a Threat Hunter. Flag any autorun entry whose executable lives in a user-writable location (AppData, ProgramData, Temp, Downloads, Public) or is launched through an interpreter (powershell, wscript, cscript, mshta, rundll32, regsvr32). Report Win32_Service PathName values containing spaces without surrounding quotes as unquoted service path privilege escalation. Verify Winlogon Shell is exactly explorer.exe and Userinit exactly userinit.exe - any appended command is a classic logon hijack. Rank findings by exploitability, and state clearly which entries are expected enterprise management agents.",
            null),

        // --- BitLocker / TPM compliance --------------------------------------------------------------
        Template(
            "endpoint-bitlocker-compliance",
            "BitLocker Encryption & TPM Compliance",
            "Reports volume encryption state, protector types, and TPM readiness for full-disk-encryption compliance reporting.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "bitlocker_compliance_tool",
                "BitLocker Volume & TPM State Query",
                PowerShellExe,
                // Protectors are projected to KeyProtectorId and KeyProtectorType ONLY. The
                // KeyProtector object also carries RecoveryPassword, which holds the live 48-digit
                // recovery key - formatting the object wholesale would ship the key that defeats
                // full-disk encryption straight into the egress stream. The narrow projection is a
                // hard data-boundary control, not a formatting preference.
                Ps(@"Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeType,EncryptionMethod,VolumeStatus,ProtectionStatus,EncryptionPercentage,AutoUnlockEnabled,CapacityGB | Format-Table -AutoSize; Write-Output '--- KEY PROTECTOR TYPES (VALUES DELIBERATELY EXCLUDED) ---'; Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector -ErrorAction SilentlyContinue | Select-Object KeyProtectorId,KeyProtectorType | Format-Table -AutoSize; Write-Output '--- TPM STATE ---'; Get-Tpm -ErrorAction SilentlyContinue | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,ManufacturerVersion,LockoutCount | Format-List; Write-Output '--- ENCRYPTION POLICY ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -ErrorAction SilentlyContinue | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Data Protection Compliance Officer. Under the zero-admin operator model an unprivileged technician sees volume status but may see no protector or TPM detail - if those sections are empty or access-denied, say the encryption state was read but protector recoverability could not be verified at this privilege level, and do not infer a missing protector from missing output. Mark any fixed volume NON-COMPLIANT if VolumeStatus is not FullyEncrypted or ProtectionStatus is not On. Flag EncryptionMethod weaker than XtsAes128 as below baseline. A volume whose only protector is TpmPin or Tpm with no RecoveryPassword protector cannot be recovered after a board replacement - report it as a recoverability gap. TpmReady False or TpmPresent False blocks silent encryption entirely on that model. Never request, infer, or display a recovery key value.",
            null),

        // --- Credential Guard / LSA hardening -----------------------------------------------------------
        Template(
            "endpoint-credential-guard",
            "Credential Guard, VBS & LSA Protection Audit",
            "Verifies virtualization-based security, Credential Guard enforcement, LSA protected process state, and legacy credential caching.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "credential_guard_tool",
                "DeviceGuard WMI & LSA Registry Probe",
                PowerShellExe,
                Ps(@"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus,RequiredSecurityProperties,AvailableSecurityProperties | Format-List; Write-Output '--- LSA PROTECTION ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue | Select-Object RunAsPPL,RunAsPPLBoot,LmCompatibilityLevel,NoLMHash,RestrictAnonymous,RestrictAnonymousSAM,DisableRestrictedAdmin | Format-List; Write-Output '--- WDIGEST PLAINTEXT CACHING ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue | Select-Object UseLogonCredential | Format-List; Write-Output '--- CACHED DOMAIN LOGON COUNT ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object CachedLogonsCount | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Windows Platform Security Architect. If the DeviceGuard section is empty or access-denied, report that VBS state requires elevated WMI access and was not read - the registry findings below remain valid on their own. In SecurityServicesConfigured/Running, 1 is Credential Guard and 2 is HVCI - a service configured but NOT running means policy was applied and the hardware or firmware prerequisite failed, which is a silent compliance gap worth escalating. Flag RunAsPPL not set to 1 (LSASS unprotected against credential dumping), WDigest UseLogonCredential set to 1 (plaintext credentials resident in memory), LmCompatibilityLevel below 5, and CachedLogonsCount above 4 on a desktop. Give the specific GPO or registry remediation for each gap.",
            null),

        // --- Application control -------------------------------------------------------------------------
        Template(
            "endpoint-applocker-wdac",
            "AppLocker & WDAC Application Control Audit",
            "Reports effective AppLocker rule collection enforcement modes and WDAC code integrity policy enforcement state.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "app_control_tool",
                "AppLocker Effective Policy & Code Integrity Query",
                PowerShellExe,
                // The effective policy is summarised to per-collection enforcement mode rather than
                // dumped as XML: a campus AppLocker policy routinely exceeds several hundred KB,
                // and shipping it whole would dominate the model's context window with rule noise
                // while burning egress token budget for no additional analytic value.
                Ps(@"Write-Output '--- APPLOCKER RULE COLLECTIONS ---'; Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections -ErrorAction SilentlyContinue | Select-Object RuleCollectionType,EnforcementMode,Count | Format-Table -AutoSize; Write-Output '--- APPLICATION IDENTITY SERVICE ---'; Get-Service AppIDSvc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-List; Write-Output '--- WDAC CODE INTEGRITY ---'; Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue | Select-Object CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus | Format-List; Write-Output '--- SMART APP CONTROL ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue | Select-Object VerifiedAndReputablePolicyState | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are an Application Control Engineer. If no rule collections are returned, distinguish 'no AppLocker policy applied' from 'policy not readable at this privilege level' and say which you cannot rule out. AppLocker enforcement is meaningless unless AppIDSvc is Running - a policy in Enabled mode with the service stopped provides zero protection and is the single most common misconfiguration, so check it first. Report each rule collection's EnforcementMode, treating AuditOnly as unenforced. A collection with zero rules while another is enforced causes an implicit deny for that file type - flag it as a likely outage source. For WDAC, distinguish Audit from Enforced code integrity. Summarise the true application-control posture in one sentence before detailing gaps.",
            null),

        // --- Host firewall -------------------------------------------------------------------------------
        Template(
            "endpoint-firewall-audit",
            "Windows Firewall Profile & Inbound Rule Audit",
            "Reports per-profile firewall enablement, default actions, logging configuration, and enabled inbound allow rules.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "firewall_audit_tool",
                "NetFirewall Profile & Rule Enumerator",
                PowerShellExe,
                Ps(@"Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,LogAllowed,LogBlocked,LogFileName | Format-List; Write-Output '--- ENABLED INBOUND ALLOW RULES ---'; Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Select-Object -First {MaxRuleCount} -Property DisplayName,Profile,Grouping,PolicyStoreSourceType | Format-Table -AutoSize; Write-Output '--- CONNECTION SECURITY RULES ---'; Get-NetIPsecRule -ErrorAction SilentlyContinue | Select-Object DisplayName,Enabled,Mode,InboundSecurity,OutboundSecurity | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Network Security Engineer. Any profile with Enabled False is a finding, and the Public profile is the highest severity because campus devices roam onto untrusted networks. DefaultInboundAction of Allow negates the firewall entirely. AllowLocalFirewallRules True permits users to punch their own holes through policy - flag it. In the inbound allow rules, prioritise anything exposing RDP, SMB, WinRM, or a database port, and note whether it is scoped to the Domain profile only or is also live on Public. PolicyStoreSourceType Local indicates a rule created outside GPO, meaning it escapes central review.",
            new Dictionary<string, string>
            {
                { "MaxRuleCount", "80" }
            }),

        // --- Removable media -------------------------------------------------------------------------------
        Template(
            "endpoint-usb-device-control",
            "Removable Media History & Device Control Policy",
            "Enumerates currently attached and historically mounted removable storage alongside the applied device control policy.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "usb_device_control_tool",
                "PnP Device & USBSTOR History Enumerator",
                PowerShellExe,
                Ps(@"Write-Output '--- PRESENT STORAGE / USB DEVICES ---'; Get-PnpDevice -PresentOnly -Class USB,DiskDrive,WPD -ErrorAction SilentlyContinue | Select-Object Status,Class,FriendlyName,InstanceId | Format-Table -AutoSize; Write-Output '--- USBSTOR HISTORICAL ENUMERATION ---'; Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName; Write-Output '--- REMOVABLE STORAGE POLICY ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\*' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- DEFENDER DEVICE CONTROL ---'; Get-MpPreference -ErrorAction SilentlyContinue | Select-Object EnableDeviceControl,DeviceControlDefaultEnforcement | Format-List; Write-Output '--- BITLOCKER TO GO POLICY ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -ErrorAction SilentlyContinue | Select-Object RDVDenyWriteAccess,RDVDenyCrossOrg,RDVRequireEncryption | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Data Loss Prevention Analyst. USBSTOR subkeys are a persistent historical record of every mass-storage device ever mounted, so decode each into vendor, product and serial and note that presence here does not mean the device is currently attached. Flag the absence of any Deny_Write or Deny_Execute policy on a device holding regulated data. RDVDenyWriteAccess not set means unencrypted removable media can be written freely - the primary uncontrolled exfiltration path on a campus endpoint. Recommend a device control posture proportionate to the machine's role.",
            null),

        // --- MDM / Intune enrollment ---------------------------------------------------------------------------
        Template(
            "endpoint-mdm-enrollment",
            "Intune / MDM Enrollment & Policy Sync Health",
            "Reports MDM enrollment state, management authority, and Intune Management Extension health for co-managed fleet devices.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "mdm_enrollment_tool",
                "MDM Enrollment Registry & Agent Probe",
                PowerShellExe,
                Ps(@"Write-Output '--- MDM ENROLLMENTS ---'; Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object ProviderID -ne $null | Select-Object PSChildName,UPN,ProviderID,EnrollmentState,EnrollmentType,AADResourceID | Format-List; Write-Output '--- INTUNE MANAGEMENT EXTENSION ---'; Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-List; Write-Output '--- CO-MANAGEMENT WORKLOADS ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\CoManagementFlags' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- APPLIED MDM POLICY AREAS ---'; Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName; Write-Output '--- MDM SYNC TASK ---'; Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue | Select-Object TaskName,State | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Unified Endpoint Management Engineer. EnrollmentState 1 means enrolled and 4 means unmanaged-but-registered; anything other than 1 with a populated ProviderID indicates a partial enrollment that will silently stop receiving policy. A stopped IntuneManagementExtension halts Win32 app delivery and PowerShell script policy while device configuration continues to apply - explain that split to the operator rather than reporting a blanket failure. Missing EnterpriseMgmt scheduled tasks mean the device will never sync again without re-enrollment. Give the concrete recovery path.",
            null),

        // --- Incident response triage snapshot -------------------------------------------------------
        // The first look a SOC responder takes at a suspect host, from one sensor: what is talking to
        // whom, what is running from where and whether it is signed, who can log in, and what is
        // scheduled to run again. Joins are left to the model on OwningProcess = ProcessId, as every
        // other template here does, so the script stays free of calculated-property braces.
        Template(
            "secops-ir-triage-snapshot",
            "Incident Response Triage Snapshot",
            "Captures the first-hour incident picture on a suspect host: live connections and their owning processes, executables running from user-writable paths and their signature state, local accounts and administrators, non-Microsoft scheduled tasks and services, and the DNS cache.",
            CatEndpoint,
            ModelPro,
            new SingleToolDefinition(
                "ir_triage_tool",
                "Connection, Process, Signature, Account & Persistence Snapshot",
                PowerShellExe,
                Ps(@"Write-Output '--- TCP CONNECTIONS (ESTABLISHED / LISTEN) ---'; Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object State -in 'Established','Listen' | Sort-Object State,OwningProcess | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,CreationTime | Format-Table -AutoSize; Write-Output '--- UDP ENDPOINTS ---'; Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize; Write-Output '--- PROCESSES WITH PATH, PARENT AND COMMAND LINE ---'; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate | Format-Table -AutoSize; Write-Output '--- EXECUTABLES RUNNING FROM USER-WRITABLE LOCATIONS ---'; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object ExecutablePath -match 'AppData|ProgramData|\\Temp\\|Downloads|\\Public\\' | Select-Object ProcessId,Name,ExecutablePath,CommandLine | Format-Table -AutoSize -Wrap; Write-Output '--- RUNNING EXECUTABLES WHOSE SIGNATURE IS NOT VALID ---'; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object ExecutablePath -ne $null | Select-Object -ExpandProperty ExecutablePath -Unique | Get-AuthenticodeSignature -ErrorAction SilentlyContinue | Where-Object Status -ne 'Valid' | Select-Object Status,Path | Format-Table -AutoSize -Wrap; Write-Output '--- LOCAL ACCOUNTS ---'; Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description | Format-Table -AutoSize; Write-Output '--- LOCAL ADMINISTRATORS (S-1-5-32-544) ---'; Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize; Write-Output '--- SCHEDULED TASKS NOT AUTHORED BY MICROSOFT ---'; Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object Author -notlike 'Microsoft*' | Where-Object TaskPath -notlike '\Microsoft\*' | Select-Object TaskName,TaskPath,State,Author | Format-Table -AutoSize; Write-Output '--- SERVICES OUTSIDE WINDOWS AND PROGRAM FILES ---'; Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object PathName -notmatch 'Windows|Program Files' | Select-Object Name,State,StartMode,StartName,PathName | Format-Table -AutoSize -Wrap; Write-Output '--- DNS CLIENT CACHE ---'; Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry,Data,TimeToLive | Sort-Object Entry -Unique | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 180,
                MaxMemoryBytes: Mb(512),
                MaxCpuPercent: 60),
            "You are a SOC incident responder taking the first look at a host. Join connections to processes on OwningProcess = ProcessId. Mark CRITICAL for an established connection owned by a process whose executable is unsigned or runs from AppData, ProgramData, Temp, Downloads or Public; for a listener on a port with no recognisable service behind it; and for a non-Microsoft scheduled task or service whose binary lives in a user-writable path. Mark WARNING for a signature Status other than Valid, an enabled local account with no logon on record, and a DNS cache entry for a dynamic-DNS, tunnelling or paste-site domain. Quote the process ID, executable path and remote address for every finding. NotSigned on a Microsoft Store or catalog-signed binary is expected - say so rather than escalating it. This sensor runs without administrator rights by design: processes owned by other users may show no path or command line, and Prefetch and the Security event log are out of its reach; report those as not visible from this sensor, never as absent.",
            null)
    };
}
