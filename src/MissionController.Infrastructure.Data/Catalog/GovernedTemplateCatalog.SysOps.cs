using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> SysOpsTemplates() => new[]
    {
        // --- Storage -------------------------------------------------------------------------------
        Template(
            "sysops-disk-space",
            "System Storage & Drive Volume Health",
            "Audits disk volume sizes, free space percentages, and filesystem health.",
            CatSysOps,
            ModelFlash,
            new SingleToolDefinition(
                "disk_volume_tool",
                "Volume Capacity & Health Query",
                PowerShellExe,
                // wmic is gone from Windows 11, and this template answered "'wmic' is not recognized"
                // for as long as nobody ran it. The perf class supplies the percentage free, so the
                // prompt's 15% line is a comparison rather than the model dividing twelve-digit byte
                // counts. Both halves need WMI, which is why the network is not denied here: inside
                // the container Get-CimInstance is refused and DriveInfo returns nothing at all.
                Ps(@"Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,OperationalStatus,SizeRemaining,Size | Format-Table -AutoSize; Write-Output '--- PERCENT FREE ---'; Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk | Where-Object Name -Match ':' | Select-Object Name,PercentFreeSpace,FreeMegabytes | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 40),
            Plain("Capacity and health thresholds already define the verdict; healthy volumes do not require incident hypotheses.",
                "You are a Senior Windows System Administrator. Analyze the storage volume output and report any drives with less than 15% free space with remediation suggestions. A HealthStatus other than Healthy means the file system itself has reported a fault; say so before any advice about capacity."),
            null),

        // --- Patch compliance -------------------------------------------------------------------------
        Template(
            "sysops-patch-compliance",
            "Windows Update & Patch Compliance Audit",
            "Reports update history, pending reboot state, WSUS/Intune update policy, and recently installed hotfixes.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "patch_compliance_tool",
                "Update Session History & Hotfix Reporter",
                PowerShellExe,
                // The Update Session COM API is queried instead of the WUA cmdlets because
                // QueryHistory works for a standard user, whereas the management cmdlets require
                // elevation - the zero-admin pillar makes the COM path the only viable one.
                // Max($total,1) keeps the request valid on a machine with no recorded history
                // without needing an if-block, preserving this file's brace-free invariant.
                Ps(@"$s = New-Object -ComObject Microsoft.Update.Session; $searcher = $s.CreateUpdateSearcher(); $total = $searcher.GetTotalHistoryCount(); $searcher.QueryHistory(0, [Math]::Min([Math]::Max($total,1), {MaxHistoryCount})) | Select-Object Date,Title,ResultCode,HResult | Format-Table -AutoSize; Write-Output '--- PENDING REBOOT INDICATORS ---'; Write-Output ('CBS RebootPending: ' + (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')); Write-Output ('WU RebootRequired: ' + (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')); Write-Output '--- UPDATE POLICY ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue | Format-List; Write-Output '--- RECENT HOTFIXES ---'; Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 25 -Property HotFixID,Description,InstalledOn | Format-Table -AutoSize; Write-Output '--- OS BUILD ---'; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 150,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Reasoned("You are a Patch Management Engineer. ResultCode 2 is Succeeded, 3 SucceededWithErrors, 4 Failed, 5 Aborted - list every non-2 result with its HResult and the update title. A repeatedly failing update is a higher priority than a single miss because it will never self-heal. Either pending-reboot indicator being true means the patch level reported is not the patch level in effect, so state that caveat before any compliance conclusion. From the update policy, identify whether the endpoint targets WSUS, Intune, or public Windows Update, and flag deferral values that exceed the organisation's patch window. Read the OS build and the hotfix list against what you know of Windows servicing: which release the build belongs to, whether that release is still in support, and roughly how far behind the newest cumulative update the installed set is - all as knowledge with its date. A build number or KB you cite from knowledge goes in the analysis, never in a finding."),
            new Dictionary<string, string>
            {
                { "MaxHistoryCount", "60" }
            }),

        // --- Software inventory -----------------------------------------------------------------------------
        Template(
            "sysops-software-inventory",
            "Installed Software Inventory & EOL Detection",
            "Enumerates installed software from the uninstall registry for licence reconciliation and end-of-life version detection.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "software_inventory_tool",
                "Uninstall Registry Inventory Reader",
                PowerShellExe,
                // Deliberately reads the uninstall keys rather than Win32_Product. Enumerating
                // Win32_Product triggers an MSI self-heal/reconfiguration pass against EVERY
                // installed package, generating MsiInstaller 1035/1004 events and, on a large
                // fleet, a self-inflicted repair storm. This is the single most damaging WMI
                // class an inventory template can touch, so it is never used here.
                Ps(@"Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -ne $null | Sort-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,EstimatedSize | Format-Table -AutoSize; Write-Output '--- PER-USER INSTALLS ---'; Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -ne $null | Select-Object DisplayName,DisplayVersion,Publisher | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(384),
                MaxCpuPercent: 50),
            Reasoned("You are a Software Asset Manager. Group the inventory by publisher and flag anything end-of-life or unsupported (legacy Java runtimes, Flash, old .NET Framework versions, browsers well behind current, unsupported Office builds). Separately list per-user installs, since these bypass machine-wide packaging and are invisible to SCCM inventory - on a shared campus workstation they are the usual source of licence and vulnerability drift. Identify remote-access and file-sync tools that may violate policy. Do not attempt to price or licence-audit; report only what is present and its support status. You know what the listing does not: for each product you flag, state the support status you know - the end-of-life date, or the currently supported major version the installed one is behind - as knowledge with the caveat that your knowledge has a date, and rank by exposure: browsers, Java, PDF readers, remote-access and file-sync tools first, because they open documents and connections from outside."),
            null),

        // --- Service failures ---------------------------------------------------------------------------------
        Template(
            "sysops-service-failures",
            "Service Failure & Crash Loop Detection",
            "Correlates stopped automatic services with Service Control Manager failure events to identify crash loops.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "service_failure_tool",
                "Service State & SCM Event Correlator",
                PowerShellExe,
                // Events are fetched with -MaxEvents then filtered client-side rather than with
                // -FilterHashtable. FilterHashtable requires a literal hashtable, whose braces
                // would sit inside the {Token}-substituted argument string; accepting a slightly
                // wider fetch is the correct trade for eliminating that collision class entirely.
                Ps(@"Write-Output '--- STOPPED AUTOMATIC SERVICES ---'; Get-Service -ErrorAction SilentlyContinue | Where-Object Status -ne 'Running' | Where-Object StartType -eq 'Automatic' | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize; Write-Output '--- SERVICE CONTROL MANAGER FAILURE EVENTS ---'; Get-WinEvent -LogName System -MaxEvents {MaxEventCount} -ErrorAction SilentlyContinue | Where-Object Id -in 7000,7001,7009,7011,7022,7023,7024,7031,7034 | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List; Write-Output '--- SERVICE RECOVERY CONFIGURATION ---'; Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object State -ne 'Running' | Where-Object StartMode -eq 'Auto' | Select-Object Name,ExitCode,ServiceSpecificExitCode,StartName | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Reasoned("You are a Windows Platform Engineer. An automatic service in Stopped state is only a finding if it did not stop deliberately - use the SCM events to tell the difference. Event 7031/7034 with a rising restart count is a crash loop and the top priority. Event 7000 with a timeout message usually means a dependency or network resource was unavailable at boot rather than a broken binary. Event 7009 is a start timeout, commonly caused by slow disk on shared campus hardware rather than the service itself. Report the owning StartName for each failure, since a service running as a domain account will fail permanently after a password change."),
            new Dictionary<string, string>
            {
                { "MaxEventCount", "300" }
            }),

        // --- Event log triage -----------------------------------------------------------------------------------
        Template(
            "sysops-event-triage",
            "System & Application Event Log Sweep",
            "Sweeps the System and Application channels for critical and error events to produce a prioritised triage summary.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "event_triage_tool",
                "System & Application Channel Sweep",
                PowerShellExe,
                // System and Application are user-readable channels by default, so this sweep
                // works for an unprivileged Tier-1 technician - unlike the Security channel,
                // which needs an explicit Event Log Readers delegation.
                Ps(@"Write-Output '--- SYSTEM CHANNEL (CRITICAL/ERROR/WARNING) ---'; Get-WinEvent -LogName System -MaxEvents {MaxEventCount} -ErrorAction SilentlyContinue | Where-Object Level -le 3 | Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | Format-List; Write-Output '--- APPLICATION CHANNEL (CRITICAL/ERROR) ---'; Get-WinEvent -LogName Application -MaxEvents {MaxEventCount} -ErrorAction SilentlyContinue | Where-Object Level -le 2 | Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | Format-List; Write-Output '--- UNEXPECTED SHUTDOWNS ---'; Get-WinEvent -LogName System -MaxEvents {MaxEventCount} -ErrorAction SilentlyContinue | Where-Object Id -in 41,1001,6008 | Select-Object TimeCreated,Id,ProviderName,Message | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 150,
                MaxMemoryBytes: Mb(384),
                MaxCpuPercent: 60),
            Reasoned("You are a Tier-2 Escalation Engineer. Do not list events chronologically - cluster them by provider and root cause, then rank clusters by operational impact and state how many occurrences each represents. Event 41 with 6008 means the machine lost power or hard-hung rather than shutting down, which points at hardware, thermal, or driver faults, not software. Disk provider errors (Event 7, 51, 153) indicate failing storage and outrank everything else on the list. Explicitly separate benign recurring noise from genuine faults, and name the single most likely root cause with the evidence supporting it. The narrative is the point: build the timeline across providers, say which cluster is the cause and which are its symptoms, and name the driver, service or hardware component most likely responsible with the specific event pairs that support it. Where you know the usual fix for an event id - a driver family, a cumulative update, a service dependency - say so as knowledge."),
            new Dictionary<string, string>
            {
                { "MaxEventCount", "250" }
            }),

        // --- Time synchronisation ----------------------------------------------------------------------------------
        Template(
            "sysops-time-sync",
            "W32Time Sync & Kerberos Skew Diagnostic",
            "Reports the time service source, stratum, offset and poll interval, and measures live offset against the domain time source.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "time_sync_tool",
                "W32Time Status & Stripchart Probe",
                CmdExe,
                // The configuration is read from the registry because 'w32tm /query /configuration'
                // asks the running service, which refuses the restricted token with 0x80070005 - and
                // only while it runs. W32Time starts on a trigger, so the same template produced
                // evidence one day and an access-denied the next.
                @"/c w32tm /query /status /verbose & echo --- CONFIGURATION --- & reg query HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters & reg query HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient & echo --- PEERS --- & w32tm /query /peers & echo --- LIVE OFFSET SAMPLES --- & w32tm /stripchart /computer:{TimeSourceHost} /samples:{SampleCount} /dataonly",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40),
            Reasoned("You are an Active Directory Time Service Engineer. Kerberos rejects any ticket whose timestamp is outside the 5-minute default skew tolerance, so an offset approaching that threshold is an imminent total authentication outage for this machine - lead with the offset and its distance from the limit. Confirm the source is the domain hierarchy rather than an internet NTP server or the local CMOS clock, since a domain member syncing externally will drift out of the domain's own consensus. Flag a stratum that is unexpectedly high, a last-successful-sync timestamp that is stale, and a poll interval that has backed off after repeated failures."),
            new Dictionary<string, string>
            {
                { "TimeSourceHost", "time.windows.com" },
                { "SampleCount", "5" }
            }),

        // --- Memory pressure -----------------------------------------------------------------------------------------
        Template(
            "sysops-memory-pressure",
            "Memory Pressure & Handle Leak Analysis",
            "Reports physical and virtual memory headroom, pagefile utilisation, and the top memory and handle consumers.",
            CatSysOps,
            ModelFlash,
            new SingleToolDefinition(
                "memory_pressure_tool",
                "OS Memory, Pagefile & Process Consumer Query",
                PowerShellExe,
                Ps(@"Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory,SizeStoredInPagingFiles,FreeSpaceInPagingFiles | Format-List; Write-Output '--- PAGEFILE ---'; Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage | Format-List; Write-Output '--- TOP MEMORY CONSUMERS ---'; Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First {TopProcessCount} -Property Name,Id,WorkingSet64,PrivateMemorySize64,Handles,Threads | Format-Table -AutoSize; Write-Output '--- TOP HANDLE CONSUMERS ---'; Get-Process -ErrorAction SilentlyContinue | Sort-Object Handles -Descending | Select-Object -First {TopProcessCount} -Property Name,Id,Handles | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Plain("Report the measured memory totals and largest consumers; a single snapshot cannot establish a leak or its history.",
                "You are a Windows Performance Analyst. Memory values from Win32_OperatingSystem are in kilobytes - convert to GB before reporting and state the free physical memory as a percentage of total. Pagefile CurrentUsage well below PeakUsage indicates past pressure that has since cleared, which is useful history rather than a live fault, so distinguish the two. A process whose PrivateMemorySize64 greatly exceeds its WorkingSet64 is paged out and may be idle rather than leaking. Handle counts above roughly 10,000 for a single process suggest a handle leak; name the process and whether it is a user application or a management agent."),
            new Dictionary<string, string>
            {
                { "TopProcessCount", "15" }
            }),

        // --- Boot performance ------------------------------------------------------------------------------------------
        Template(
            "sysops-boot-performance",
            "Boot & Logon Performance Degradation",
            "Analyses boot duration, startup impact events, and logon path delays on shared campus workstations.",
            CatSysOps,
            ModelPro,
            new SingleToolDefinition(
                "boot_performance_tool",
                "Diagnostics-Performance Channel Reader",
                PowerShellExe,
                Ps(@"Write-Output '--- BOOT PERFORMANCE EVENTS ---'; Get-WinEvent -LogName Microsoft-Windows-Diagnostics-Performance/Operational -MaxEvents {MaxEventCount} -ErrorAction SilentlyContinue | Where-Object Id -in 100,101,102,103,106,109,110 | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List; Write-Output '--- LAST BOOT / UPTIME ---'; Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object LastBootUpTime,LocalDateTime | Format-List; Write-Output '--- STARTUP COMMANDS ---'; Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name,Command,Location,User | Format-Table -AutoSize; Write-Output '--- FAST STARTUP ---'; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue | Select-Object HiberbootEnabled | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Reasoned("You are a Desktop Performance Engineer supporting shared lab machines. If the Diagnostics-Performance channel returns nothing, state that the channel is unreadable or disabled rather than reporting fast boot times. Event 100 carries total boot duration, 101 names an application that slowed startup, 102 a driver, and 109 a service - attribute delay to the specific named component rather than reporting an aggregate. HiberbootEnabled 1 means Fast Startup is on, so LastBootUpTime reflects a hybrid resume and the machine may not have truly rebooted for patching in weeks; check uptime against that and say so plainly. Rank remediations by seconds recovered per user logon."),
            new Dictionary<string, string>
            {
                { "MaxEventCount", "80" }
            })
    };
}
