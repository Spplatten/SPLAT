using System;
using System.Collections.Generic;
using MissionController.Core.Enums;

namespace MissionController.Core.Models;

/// <summary>
/// Execution environment target for a Copilot tool invocation.
/// </summary>
public enum CopilotExecutionEnvironment
{
    /// <summary>
    /// Native Windows execution using Win32 Job Objects, Restricted Token de-escalation, and NT ACL jails.
    /// </summary>
    WindowsJobSandbox,

    /// <summary>
    /// Linux/WSL2 execution using in-kernel BPF-LSM capability leases, cgroups v2, and OverlayFS.
    /// </summary>
    LinuxBpfLsmLease
}

/// <summary>
/// Security classification and risk severity for Copilot actions and violations.
/// </summary>
public enum CopilotSecuritySeverity
{
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// CISO enterprise policy rules governing Copilot and Semantic Kernel tool execution.
/// </summary>
public record CopilotSafetyPolicy(
    string PolicyId,
    string PolicyName,
    bool EnforceRestrictedToken,
    bool EnforceJobObjectResourceLimits,
    bool StreamToMicrosoftSentinel,
    IReadOnlyList<string> AllowedExecutables,
    IReadOnlyList<string> BlockedPathSubstrings,
    IReadOnlyList<string> BlockedArgumentPatterns,
    long MaxMemoryBytes = 256 * 1024 * 1024, // 256 MB default
    int MaxCpuPercent = 50,                  // 50% CPU clamp
    int TimeoutSeconds = 30,                 // 30s timeout
    bool AllowNetworkEgress = false,
    IReadOnlyList<string>? AllowedEgressIps = null,
    IReadOnlyList<uint>? AllowedEgressPorts = null)
{
    /// <summary>
    /// Default hardened CISO policy for enterprise Windows Copilot deployments.
    /// </summary>
    public static CopilotSafetyPolicy CreateEnterpriseDefault() => new(
        PolicyId: "POL-COPILOT-DEFAULT-CISO",
        PolicyName: "Enterprise Copilot Native Hardening Policy",
        EnforceRestrictedToken: true,
        EnforceJobObjectResourceLimits: true,
        StreamToMicrosoftSentinel: true,
        AllowedExecutables: new[]
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "netstat.exe",
            "ipconfig.exe", "ping.exe", "tracert.exe", "nslookup.exe", "systeminfo.exe",
            "tasklist.exe", "whoami.exe", "python.exe", "python3.exe", "git.exe", "curl.exe"
        },
        BlockedPathSubstrings: new[]
        {
            @"\System32\config\SAM",
            @"\System32\config\SYSTEM",
            @"\System32\config\SECURITY",
            @"\Windows\NTDS",
            @"\.ssh\",
            @"\.aws\",
            @"\.azure\",
            @"\AppData\Local\Microsoft\Credentials",
            @"\AppData\Roaming\Microsoft\Credentials",
            @"\AppData\Roaming\Microsoft\Protect",
            @"/etc/shadow",
            @"/etc/sudoers",
            @"/root/.ssh"
        },
        BlockedArgumentPatterns: new[]
        {
            "Invoke-Expression",
            "iex ",
            "DownloadString",
            "IEX(",
            "mimikatz",
            "sekurlsa",
            "procdump",
            "lsass",
            "Set-ExecutionPolicy Unrestricted",
            "Disable-WindowsOptionalFeature"
        },
        MaxMemoryBytes: 256 * 1024 * 1024,
        MaxCpuPercent: 50,
        TimeoutSeconds: 30,
        AllowNetworkEgress: false,
        AllowedEgressIps: new[] { "127.0.0.1" },
        AllowedEgressPorts: new uint[] { 80, 443 }
    );
}

/// <summary>
/// Telemetry context passed when a Copilot agent invokes a tool or Semantic Kernel function.
/// </summary>
public record CopilotToolCallContext(
    Guid SessionId,
    string AgentId,
    string ToolName,
    string ExecutableOrCommand,
    string Arguments,
    string? WorkingDirectory,
    string OperatorIdentity,
    IReadOnlyDictionary<string, string>? Metadata = null,
    CopilotExecutionEnvironment PreferredEnvironment = CopilotExecutionEnvironment.WindowsJobSandbox);

/// <summary>
/// Security violation detected by SPLAT pre-execution checks or in-kernel hooks.
/// </summary>
public record CopilotSecurityViolation(
    string ViolationType,
    string Description,
    CopilotSecuritySeverity Severity,
    string OffendingValue,
    DateTime TimestampUtc);

/// <summary>
/// Result returned after executing a Copilot tool within the SPLAT safety substrate.
/// </summary>
public record CopilotExecutionResult(
    bool IsSuccess,
    bool PolicyBlocked,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    JobResourceMetrics? ResourceMetrics,
    IReadOnlyList<CopilotSecurityViolation> Violations,
    string? MerkleEntryHash,
    DateTime TimestampUtc)
{
    public static CopilotExecutionResult Blocked(
        string reason,
        IReadOnlyList<CopilotSecurityViolation> violations,
        string? merkleHash = null) =>
        new(
            IsSuccess: false,
            PolicyBlocked: true,
            ExitCode: -1,
            StandardOutput: string.Empty,
            StandardError: $"[SPLAT COPILOT SAFETY SUBSTRATE] Blocked tool execution: {reason}",
            TimedOut: false,
            ResourceMetrics: null,
            Violations: violations,
            MerkleEntryHash: merkleHash,
            TimestampUtc: DateTime.UtcNow);
}
