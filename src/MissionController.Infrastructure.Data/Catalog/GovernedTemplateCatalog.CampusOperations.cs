using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    /// <summary>
    /// Tier-1 / field-support runbooks for the workflows named in the product scope: campus lab
    /// and branch office diagnostics, printer queues, and shared-workstation hygiene.
    ///
    /// Deliberately scoped to the WORKSTATION side of each problem. Server-role administration
    /// (IIS app pools, Hyper-V hosts, SQL instances, DHCP server scopes) is excluded: the product
    /// is defined as an appliance for Windows Enterprise Workstations, those roles require the
    /// standing elevation the zero-local-admin pillar forbids, and a template that cannot run
    /// under the shipped privilege model is worse than no template at all.
    /// </summary>
    private static IEnumerable<SingleToolTemplate> CampusOperationsTemplates() => new[]
    {
        // --- Print queue triage ------------------------------------------------------------------
        Template(
            "campus-print-queue-triage",
            "Print Queue & Spooler Triage",
            "Reports installed printers, port bindings, stuck jobs, and spooler health for campus print escalations.",
            CatCampus,
            ModelFlash,
            new SingleToolDefinition(
                "print_queue_tool",
                "Printer, Port & Spooler Job Reporter",
                PowerShellExe,
                Ps(@"Write-Output '--- INSTALLED PRINTERS ---'; Get-Printer -ErrorAction SilentlyContinue | Select-Object Name,DriverName,PortName,Shared,Published,PrinterStatus,Location | Format-Table -AutoSize; Write-Output '--- PORT BINDINGS ---'; Get-PrinterPort -ErrorAction SilentlyContinue | Select-Object Name,Description,PrinterHostAddress,PortNumber | Format-Table -AutoSize; Write-Output '--- QUEUED JOBS ---'; Get-Printer -ErrorAction SilentlyContinue | Get-PrintJob -ErrorAction SilentlyContinue | Select-Object PrinterName,Id,JobStatus,UserName,SubmittedTime,Size,TotalPages | Format-Table -AutoSize; Write-Output '--- SPOOLER SERVICE ---'; Get-Service Spooler -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-List; Write-Output '--- POINT AND PRINT RESTRICTIONS ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- SPOOLER RPC HARDENING ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -ErrorAction SilentlyContinue | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are assisting a Tier-1 field technician at a print escalation. Lead with the practical answer: which queue is stuck and what to do. A job in Error or Paused status at the head of a queue blocks every job behind it, so name it and its owner. PrinterStatus values other than Normal or Idle indicate a device-side fault (paper, toner, offline) that no amount of client-side work will fix - say so rather than suggesting driver reinstalls. Check the port's PrinterHostAddress resolves to the expected building print server. Separately, note whether RestrictDriverInstallationToAdministrators is set, since an unset value leaves the PrintNightmare driver-install path open on a shared campus machine.",
            null),

        // --- Switchport / neighbour identification --------------------------------------------------------
        Template(
            "campus-switchport-neighbor",
            "Switchport & Upstream Neighbour Identification",
            "Identifies the upstream switch, port, and VLAN a workstation is connected to for physical-layer campus troubleshooting.",
            CatCampus,
            ModelPro,
            new SingleToolDefinition(
                "switchport_neighbor_tool",
                "ARP, Neighbour & Link Layer Reporter",
                CmdExe,
                // There is no supported user-space LLDP reader on stock Windows, so the switch is
                // inferred indirectly: the ARP entry for the default gateway gives the upstream
                // MAC whose OUI identifies the vendor, and the link speed plus adapter state
                // bounds which port profile is in play. This is the most a zero-admin workstation
                // template can establish without an agent, and the prompt says so explicitly
                // rather than letting the model overstate its certainty.
                "/c ipconfig /all & echo --- ARP TABLE --- & arp -a & echo --- NEIGHBOUR CACHE --- & netsh interface ipv4 show neighbors & echo --- LINK STATE --- & netsh interface show interface & echo --- ADAPTER SPEED AND DUPLEX --- & wmic nic where NetEnabled=true get Name,Speed,MACAddress,NetConnectionID /format:list",
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Campus Network Field Engineer. Identify the default gateway and its MAC address from the ARP table, and derive the hardware vendor from the MAC OUI prefix. State clearly that this identifies the upstream layer-3 device, NOT the specific access switch or port - do not fabricate a port number, and say what the network team would need to query (the switch MAC address table, using this workstation's MAC) to complete the identification. Report the negotiated link speed and flag anything below the port's expected capability, since a 100Mbps negotiation on a gigabit campus drop almost always means a damaged cable or a failing patch panel termination. Note the subnet and whether it matches the expected building VLAN.",
            null),

        // --- Multi-building latency sweep -------------------------------------------------------------------
        Template(
            "campus-subnet-latency-sweep",
            "Multi-Building Subnet Latency Sweep",
            "Measures latency and loss to a set of campus anchor hosts to localise a fault to a building, uplink, or core.",
            CatCampus,
            ModelPro,
            new SingleToolDefinition(
                "subnet_latency_tool",
                "Sequential Anchor Host Latency Probe",
                CmdExe,
                // Probes walk outward: gateway, then building anchor, then core anchor. Comparing
                // the three isolates the fault to a segment in one mission - a single ping to an
                // external host proves only that something on the path is broken, which is the
                // least actionable possible result for a field technician.
                "/c echo --- LOCAL GATEWAY --- & ping -n {ProbeCount} {GatewayHost} & echo --- BUILDING ANCHOR --- & ping -n {ProbeCount} {BuildingAnchorHost} & echo --- CORE ANCHOR --- & ping -n {ProbeCount} {CoreAnchorHost} & echo --- EXTERNAL REFERENCE --- & ping -n {ProbeCount} {ExternalHost}",
                ExitOkOrPartial,
                TimeoutSeconds: 180,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40),
            "You are a Campus Network Operations Analyst. Compare the four probe stages and localise the fault to the first segment where latency or loss degrades materially, since everything beyond it inherits the same degradation and must not be reported as a separate fault. Clean gateway with degraded building anchor points at the building uplink. Clean building with degraded core points at the distribution layer. Degradation at every stage including the gateway points at the local adapter, cable, or the access port itself. Report minimum, maximum and average per stage - a high maximum with a normal average indicates intermittent buffering or a duplex mismatch rather than saturation. State the segment to escalate to and the evidence.",
            new Dictionary<string, string>
            {
                { "GatewayHost", "192.168.1.1" },
                { "BuildingAnchorHost", "192.168.1.10" },
                { "CoreAnchorHost", "10.0.0.1" },
                { "ExternalHost", "8.8.8.8" },
                { "ProbeCount", "8" }
            }),

        // --- Resolver cache hygiene ---------------------------------------------------------------------------
        Template(
            "campus-dns-cache-hygiene",
            "DNS Resolver Cache & Suffix Search Audit",
            "Inspects the resolver cache, suffix search order, and registration behaviour behind stale-record complaints in lab environments.",
            CatCampus,
            ModelFlash,
            new SingleToolDefinition(
                "dns_cache_hygiene_tool",
                "Resolver Cache & Suffix Order Reporter",
                PowerShellExe,
                // Read-only by design. Flushing is a state change, and the governed model requires
                // a remediation to be an explicit operator decision recorded in the audit ledger,
                // not a side effect of running a diagnostic. The prompt recommends the flush; the
                // template never performs it.
                Ps(@"Write-Output '--- RESOLVER CACHE ---'; Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry,RecordName,RecordType,Status,Section,TimeToLive,Data | Format-Table -AutoSize; Write-Output '--- SUFFIX SEARCH ORDER ---'; Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue | Select-Object UseSuffixSearchList,SuffixSearchList,UseDevolution,DevolutionLevel | Format-List; Write-Output '--- PER-INTERFACE DNS ---'; Get-DnsClient -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,ConnectionSpecificSuffix,RegisterThisConnectionsAddress,UseSuffixWhenRegistering | Format-Table -AutoSize; Write-Output '--- SERVER ASSIGNMENT ---'; Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Tier-1 support assistant. Identify cached entries for internal hosts whose TimeToLive is long enough to outlast a server move, and any negative (Status other than Success) cache entry for a host the user is actively trying to reach - a cached failure is the most common cause of 'it works on my colleague's machine'. Confirm the suffix search list contains the campus domain, since a missing suffix breaks short-name resolution while fully qualified names keep working, which users report as intermittent. Flag any interface with RegisterThisConnectionsAddress enabled on a guest or wireless network, as it publishes the workstation into DNS from an untrusted segment. Recommend a resolver flush where warranted, and state plainly that this diagnostic did not perform one.",
            null),

        // --- Shared workstation profile health -------------------------------------------------------------------
        Template(
            "campus-user-profile-health",
            "Shared Workstation User Profile Health",
            "Audits local, temporary, and orphaned user profiles plus folder redirection state on shared lab machines.",
            CatCampus,
            ModelPro,
            new SingleToolDefinition(
                "user_profile_health_tool",
                "Profile List & Redirection State Reader",
                PowerShellExe,
                Ps(@"Write-Output '--- USER PROFILES ---'; Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Select-Object LocalPath,SID,Special,Loaded,RoamingConfigured,Status,LastUseTime | Format-Table -AutoSize; Write-Output '--- PROFILE LIST REGISTRY ---'; Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Select-Object PSChildName,ProfileImagePath,State,RefCount | Format-Table -AutoSize; Write-Output '--- FOLDER REDIRECTION ---'; Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- PROFILE POLICY ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue | Select-Object DeleteRoamingCache,ProfileUnloadTimeout,CompatibleRUPSecurity | Format-List; Write-Output '--- FREE SPACE ---'; Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object DriveType -eq 3 | Select-Object DeviceID,FreeSpace,Size | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Shared Workstation Engineer supporting teaching labs. A ProfileList key whose name ends in .bak, or a profile with State indicating a temporary profile, means the user logged on to a broken profile and their work is being written to a directory that is discarded at logoff - report this first and urgently, because data loss is in progress. Count profiles never used in the last 60 days and estimate the disk they hold, since profile accumulation is the standard cause of lab machines filling up mid-term. Confirm folder redirection points at a server path rather than a local one; a locally redirected Documents folder on a shared lab machine means student work never leaves the workstation. Note whether DeleteRoamingCache is set, which is the usual remediation for this class of machine.",
            null),

        // --- Lab image drift ---------------------------------------------------------------------------------------
        Template(
            "campus-lab-image-drift",
            "Lab Workstation Image & Build Drift",
            "Captures the build identity, install date, domain membership and management agent state to detect drift from the approved lab image.",
            CatCampus,
            ModelPro,
            new SingleToolDefinition(
                "image_drift_tool",
                "Build Identity & Management Agent Reporter",
                PowerShellExe,
                Ps(@"Write-Output '--- BUILD IDENTITY ---'; Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime,SystemDirectory | Format-List; Write-Output '--- UBR AND EDITION ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Select-Object ProductName,DisplayVersion,CurrentBuild,UBR,EditionID,InstallationType | Format-List; Write-Output '--- HARDWARE IDENTITY ---'; Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Name,Domain,PartOfDomain,Manufacturer,Model,TotalPhysicalMemory,SystemFamily | Format-List; Write-Output '--- BIOS AND SERIAL ---'; Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object Manufacturer,Name,SMBIOSBIOSVersion,ReleaseDate,SerialNumber | Format-List; Write-Output '--- MANAGEMENT AGENTS ---'; Get-Service -ErrorAction SilentlyContinue | Where-Object Name -in 'CcmExec','IntuneManagementExtension','Sense','WinDefend','gpsvc' | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            "You are a Deployment Engineer auditing a lab bench. Report the full build identity as CurrentBuild.UBR, because two machines can share a build number while differing by months of cumulative updates - the UBR is the real drift signal. Compare InstallDate against the expected imaging date for the lab and flag a machine imaged outside the cycle or rebuilt manually. PartOfDomain false on a lab workstation means it is receiving no policy at all and is the highest-severity finding available here. For management agents, a stopped CcmExec or gpsvc means the machine is silently unmanaged while still appearing in inventory; Sense stopped means EDR telemetry has ceased. List the serial and model so the asset record can be reconciled.",
            null)
    };
}
