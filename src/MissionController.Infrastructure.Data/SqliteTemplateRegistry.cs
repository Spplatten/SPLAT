using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Templates;

public sealed class SqliteTemplateRegistry : ITemplateRegistry
{
    private readonly SqliteStorageContext _context;

    public SqliteTemplateRegistry(SqliteStorageContext context)
    {
        _context = context;
        InitializeDefaultCatalogAsync().GetAwaiter().GetResult();
    }

    private async Task InitializeDefaultCatalogAsync()
    {
        var existing = await GetAllTemplatesAsync();
        if (existing.Count == 0)
        {
            // Seed Fleet with 8 Governed Autonomous AI Agents + Governed 1-Click Fix Actions
            var defaultTemplates = new List<SingleToolTemplate>
            {
                // 1. Atlas-Net (Network Intelligence Agent)
                new(
                    "net-dns-audit",
                    "Atlas-Net (Network Intelligence Agent)",
                    "Autonomously audits ping latency, packet loss, DNS resolution, and rogue listening sockets.",
                    "Networking",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "net-dns-tool",
                        "Windows Ping & DNS Diagnostic Sensor",
                        "ping.exe",
                        "-n {PacketCount} -w {TimeoutMs} {TargetHost}",
                        new[] { 0, 1 },
                        TimeoutSeconds: 30,
                        MaxMemoryBytes: 64 * 1024 * 1024,
                        MaxCpuPercent: 50,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Atlas-Net, a Senior Network Intelligence AI Agent. Analyze ping packet roundtrips, socket states, and DNS latency. Provide: 1) Executive Health Summary, 2) Root Cause Analysis, 3) Plain-English Remediation.",
                    new List<TemplateParameterField>
                    {
                        new("TargetHost", "Target Host / IP", "FQDN or IP to test connectivity", "8.8.8.8", true),
                        new("PacketCount", "Ping Packet Count", "Number of echo requests", "4", true),
                        new("TimeoutMs", "Timeout (ms)", "Timeout per ping packet", "1000", true),
                        new("UserInstruction", "Operator Directive", "Custom investigation focus for Atlas-Net", "", false, true)
                    },
                    new Dictionary<string, string> { { "TargetHost", "8.8.8.8" }, { "PacketCount", "4" }, { "TimeoutMs", "1000" } },
                    new List<RemediationAction>
                    {
                        new(
                            "fix-flush-dns",
                            "net-dns-audit",
                            "Flush DNS Cache & Reset WinSock Sockets",
                            "Flushes local DNS resolver cache and resets network socket catalog to eliminate stale routes.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"ipconfig /flushdns & netsh winsock reset catalog\"")
                    }
                ),

                // 2. Sentinel-SecOps (Security Incident Agent)
                new(
                    "secops-logon-bruteforce",
                    "Sentinel-SecOps (Security Incident Agent)",
                    "Hunts for unauthorized failed logon spikes (Event 4625), brute-force attacks, and account lockouts.",
                    "Security",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "wevtutil-sec-tool",
                        "Windows Security Event Log Sensor",
                        "wevtutil.exe",
                        "qe Security \"/q:*[System[(EventID=4625 or EventID=4624)]]\" /c:{EventCount} /rd:true /f:text",
                        new[] { 0 },
                        TimeoutSeconds: 45,
                        MaxMemoryBytes: 128 * 1024 * 1024,
                        MaxCpuPercent: 60,
                        RequiresRestrictedToken: false),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Sentinel-SecOps, a Principal SOC Threat Hunting AI Agent. Evaluate Windows Security Events 4624/4625 for brute-force surges, spray attacks, and unauthorized lateral movement.",
                    new List<TemplateParameterField>
                    {
                        new("EventCount", "Events To Query", "Number of recent security events to analyze", "25", true),
                        new("UserInstruction", "Threat Focus", "Specific account, IP, or time window to hunt", "", false, true)
                    },
                    new Dictionary<string, string> { { "EventCount", "25" } },
                    new List<RemediationAction>
                    {
                        new(
                            "fix-lock-account-policy",
                            "secops-logon-bruteforce",
                            "Enforce Account Lockout Threshold (5 Attempts)",
                            "Hardens local security policy to automatically lock accounts after 5 consecutive invalid passwords.",
                            RemediationRiskLevel.Moderate,
                            CanRollback: true,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30\"",
                            RollbackExecutable: "cmd.exe",
                            RollbackArguments: "/c \"net accounts /lockoutthreshold:0\"")
                    }
                ),

                // 3. Titan-SysOps (Storage Optimization Agent)
                new(
                    "sysops-disk-space",
                    "Titan-SysOps (Storage Optimization Agent)",
                    "Analyzes disk volumes, free capacity headroom, and identifies large recoverable cache directories.",
                    "SysOps",
                    "gemini-2.5-flash",
                    new SingleToolDefinition(
                        "wmic-disk-tool",
                        "Windows Storage & Volume Sensor",
                        "wmic.exe",
                        "logicaldisk where drivetype=3 get deviceid, freespace, size, volumename /format:csv",
                        new[] { 0 },
                        TimeoutSeconds: 30,
                        MaxMemoryBytes: 64 * 1024 * 1024,
                        MaxCpuPercent: 50,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Titan-SysOps, a Storage Optimization AI Agent. Calculate free disk percentages and identify capacity bottlenecks.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Cleanup Objective", "Specific drive or folder targets for Titan-SysOps", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-purge-temp-cache",
                            "sysops-disk-space",
                            "Purge Temporary User & Windows System Caches",
                            "Safely purges temporary files and build artifacts from %TEMP% and user crash logs.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"del /q /f /s %TEMP%\\* 2>nul\"")
                    }
                ),

                // 4. Aegis-Endpoint (Compliance & Defender Agent)
                new(
                    "sysops-defender-status",
                    "Aegis-Endpoint (Compliance & Defender Agent)",
                    "Verifies Microsoft Defender real-time protection, signature freshness, and kernel security posture.",
                    "Compliance",
                    "gemini-2.5-flash",
                    new SingleToolDefinition(
                        "sc-query-defender",
                        "Service Controller Sensor",
                        "sc.exe",
                        "query WinDefend",
                        new[] { 0 },
                        TimeoutSeconds: 30,
                        MaxMemoryBytes: 64 * 1024 * 1024,
                        MaxCpuPercent: 50,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Aegis-Endpoint, a Corporate Compliance & Endpoint Security AI Agent. Verify Microsoft Defender real-time service state.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Compliance Standard", "Compliance benchmark to check against", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-enable-defender-shield",
                            "sysops-defender-status",
                            "Start & Enable Defender Real-Time Shield",
                            "Ensures the WinDefend antivirus service is set to Automatic startup and running.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"sc config WinDefend start= auto & sc start WinDefend\"")
                    }
                ),

                // 5. Vanguard-AD (Active Directory & Identity Hunter)
                new(
                    "secops-ad-hunter",
                    "Vanguard-AD (Identity & Kerberos Hunter)",
                    "Dispatches Active Directory identity audits, Kerberos ticket checks, and privileged SID enumeration.",
                    "Security",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "whoami-ad-tool",
                        "Active Directory Identity & Privilege Sensor",
                        "cmd.exe",
                        "/c \"whoami /all & net accounts\"",
                        new[] { 0 },
                        TimeoutSeconds: 45,
                        MaxMemoryBytes: 64 * 1024 * 1024,
                        MaxCpuPercent: 50,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Vanguard-AD, an Identity & Access Threat Hunter AI Agent. Analyze domain group memberships, Kerberos tickets, and user privilege delegations. Identify over-privileged accounts and shadow admin tokens.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Identity Focus", "Specific user, SID, or domain controller to investigate", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-purge-kerberos-tickets",
                            "secops-ad-hunter",
                            "Purge Stale Kerberos Tickets & Reset SIDs",
                            "Clears cached Kerberos tickets (klist purge) to force fresh authentication tickets from the KDC.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"klist purge\"")
                    }
                ),

                // 6. Zephyr-Azure (Cloud Health & Hybrid Identity Agent)
                new(
                    "cloud-azure-health",
                    "Zephyr-Azure (Cloud Health & Hybrid Sync Agent)",
                    "Audits Microsoft Entra ID / Azure Arc hybrid connectivity, SSO endpoints, and cloud sync latency.",
                    "Cloud",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "azure-net-tool",
                        "Azure Cloud Endpoint Sensor",
                        "powershell.exe",
                        "-NoProfile -NonInteractive -Command \"Test-NetConnection -ComputerName login.microsoftonline.com -Port 443 | Select-Object ComputerName,TcpTestSucceeded,RoundTripTimeMillis | ConvertTo-Json\"",
                        new[] { 0 },
                        TimeoutSeconds: 45,
                        MaxMemoryBytes: 128 * 1024 * 1024,
                        MaxCpuPercent: 60,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Zephyr-Azure, a Cloud Infrastructure & Hybrid Entra ID AI Agent. Analyze cloud connectivity, TLS roundtrip latency to login.microsoftonline.com, and tenant reachability.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Cloud Service Focus", "Specific Azure endpoint or tenant ID to analyze", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-flush-cloud-dns",
                            "cloud-azure-health",
                            "Flush Cloud SSO Endpoints & DNS Cache",
                            "Refreshes local DNS resolution for Azure Entra ID login and graph endpoints.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"ipconfig /flushdns\"")
                    }
                ),

                // 7. Chronos-Patch (Patch, CVE & Vulnerability Auditor)
                new(
                    "sysops-patch-auditor",
                    "Chronos-Patch (Patch & Vulnerability Auditor)",
                    "Audits installed Windows Quality hotfixes, missing security updates, and OS rollup timelines.",
                    "SysOps",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "hotfix-sensor-tool",
                        "Windows HotFix & Patch Sensor",
                        "powershell.exe",
                        "-NoProfile -NonInteractive -Command \"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID,Description,InstalledOn | ConvertTo-Json\"",
                        new[] { 0 },
                        TimeoutSeconds: 60,
                        MaxMemoryBytes: 128 * 1024 * 1024,
                        MaxCpuPercent: 60,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Chronos-Patch, a Vulnerability Management & Patch Compliance AI Agent. Evaluate installed hotfixes, calculate patch staleness, and assess vulnerability exposure.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Patch / KB Filter", "Specific KB number or vulnerability to cross-reference", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-trigger-wu-scan",
                            "sysops-patch-auditor",
                            "Trigger Windows Update Detection & Scan",
                            "Triggers the Windows Update client (UsoClient StartScan) to check Microsoft Update servers for critical security hotfixes.",
                            RemediationRiskLevel.Safe,
                            CanRollback: false,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"usoclient StartScan\"")
                    }
                ),

                // 8. Cypher-Registry (Registry & Persistence Cleaner)
                new(
                    "secops-registry-persistence",
                    "Cypher-Registry (Registry & Persistence Cleaner)",
                    "Audits Windows Run / RunOnce startup keys, shell extensions, and unauthorized persistence hooks.",
                    "Security",
                    "gemini-2.5-pro",
                    new SingleToolDefinition(
                        "reg-autorun-tool",
                        "Windows Registry Autorun Sensor",
                        "cmd.exe",
                        "/c \"reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run & reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"",
                        new[] { 0, 1 },
                        TimeoutSeconds: 30,
                        MaxMemoryBytes: 64 * 1024 * 1024,
                        MaxCpuPercent: 50,
                        RequiresRestrictedToken: true),
                    new EgressRule("api.anthropic.com", 443, true, "Governed AI Gateway (default: Anthropic Claude; egress pinned by provider client)"),
                    "You are Cypher-Registry, a Windows Forensics & Persistence Hunter AI Agent. Examine startup registry keys and binary paths for suspicious names, unquoted service executables, and malware persistence mechanisms.",
                    new List<TemplateParameterField>
                    {
                        new("UserInstruction", "Forensics Focus", "Specific registry hive or binary name to inspect", "", false, true)
                    },
                    new Dictionary<string, string>(),
                    new List<RemediationAction>
                    {
                        new(
                            "fix-clean-runonce",
                            "secops-registry-persistence",
                            "Clear Stale User RunOnce Registry Keys",
                            "Removes temporary RunOnce registry entries that may have been left behind by uninstalled software.",
                            RemediationRiskLevel.Moderate,
                            CanRollback: true,
                            FixExecutable: "cmd.exe",
                            FixArguments: "/c \"reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /va /f\"",
                            RollbackExecutable: "cmd.exe",
                            RollbackArguments: "/c \"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /f\"")
                    }
                )
            };

            foreach (var template in defaultTemplates)
            {
                await RegisterTemplateAsync(template);
            }
        }
    }

    public async Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "SELECT TemplateJson FROM Templates ORDER BY Category, Name";

        var list = new List<SingleToolTemplate>();
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            var template = JsonSerializer.Deserialize<SingleToolTemplate>(json);
            if (template != null)
                list.Add(template);
        }

        return list;
    }

    public async Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "SELECT TemplateJson FROM Templates WHERE TemplateId = @id";
        command.Parameters.AddWithValue("@id", templateId);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            return JsonSerializer.Deserialize<SingleToolTemplate>(json);
        }

        return null;
    }

    public async Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
    {
        template.ValidateStrictRules();

        using var connection = _context.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO Templates (TemplateId, Name, Category, TemplateJson)
            VALUES (@id, @name, @category, @json)
            ON CONFLICT(TemplateId) DO UPDATE SET
                Name = excluded.Name,
                Category = excluded.Category,
                TemplateJson = excluded.TemplateJson";

        command.Parameters.AddWithValue("@id", template.TemplateId);
        command.Parameters.AddWithValue("@name", template.Name);
        command.Parameters.AddWithValue("@category", template.Category);
        command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(template));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
