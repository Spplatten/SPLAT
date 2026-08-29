using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// Compiles a governed SingleToolTemplate into an in-kernel capability LeaseSpec.
/// Translates declared tool contracts (files, egress, exec) into kernel-enforced BPF-LSM policies.
/// </summary>
public class TemplatePolicyCompiler : ITemplatePolicyCompiler
{
    private static readonly IReadOnlyList<string> DefaultProtectedPaths = new[]
    {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/root/.ssh",
        "/root/.gnupg",
        "/var/run/docker.sock",
        "/proc/kcore"
    };

    public LeaseSpec CompileTemplatePolicy(
        SingleToolTemplate template,
        Guid missionId,
        string workingDirectory,
        uint leaseDurationSeconds = 30)
    {
        ArgumentNullException.ThrowIfNull(template);
        if (string.IsNullOrWhiteSpace(workingDirectory))
        {
            workingDirectory = "/tmp/splat_sandboxes/" + missionId;
        }

        // Clamp duration between 5s and 300s (seconds-scoped, single-use lease)
        uint clampedDuration = Math.Clamp(leaseDurationSeconds, 5u, 300u);

        // 1. Resolve Executable Inodes / Allowed Binaries
        var allowedExecList = new List<InodeIdentifierModel>();
        string exeName = System.IO.Path.GetFileName(template.Tool.ExecutablePath).ToLowerInvariant();
        if (exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            exeName = exeName[..^4];
        }

        // Core system exec allowlist based on template tool
        var targetPaths = GetStandardLinuxBinaryPaths(exeName);
        foreach (var path in targetPaths)
        {
            allowedExecList.Add(new InodeIdentifierModel(0, 0, path));
        }

        // Always allow standard shell wrappers if invoked through /bin/sh
        allowedExecList.Add(new InodeIdentifierModel(0, 0, "/bin/sh"));
        allowedExecList.Add(new InodeIdentifierModel(0, 0, "/bin/dash"));
        allowedExecList.Add(new InodeIdentifierModel(0, 0, "/usr/bin/env"));

        // 2. Protected Files / Sensitive Inodes
        var protectedList = new List<InodeIdentifierModel>();
        foreach (var p in DefaultProtectedPaths)
        {
            protectedList.Add(new InodeIdentifierModel(0, 0, p));
        }

        // 3. Egress Rule Formulation
        bool allowNetwork = false;
        var allowedIps = new List<string>();
        var allowedPorts = new List<uint>();

        string targetFqdn = template.EgressRule.AllowedFqdn?.Trim() ?? string.Empty;
        if (!string.IsNullOrEmpty(targetFqdn) &&
            !targetFqdn.Equals("none", StringComparison.OrdinalIgnoreCase) &&
            !targetFqdn.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !targetFqdn.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            allowNetwork = true;
            uint port = template.EgressRule.AllowedPort > 0 ? (uint)template.EgressRule.AllowedPort : 443u;
            allowedPorts.Add(port);

            // Attempt DNS resolution to pin /32 IPv4 destinations
            try
            {
                var hostAddresses = Dns.GetHostAddresses(targetFqdn);
                foreach (var ip in hostAddresses)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        allowedIps.Add(ip.ToString());
                    }
                }
            }
            catch
            {
                // If offline or unresolvable at compile-time, allow localhost loopback only
                allowedIps.Add("127.0.0.1");
            }
        }
        else if (targetFqdn.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                 targetFqdn.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            allowNetwork = true;
            allowedIps.Add("127.0.0.1");
            allowedPorts.Add(template.EgressRule.AllowedPort > 0 ? (uint)template.EgressRule.AllowedPort : 80u);
        }

        // 4. Resource Limits from Tool Definition
        ulong memoryBytes = template.Tool.MaxMemoryBytes > 0
            ? (ulong)template.Tool.MaxMemoryBytes
            : 256UL * 1024 * 1024;

        uint cpuPercent = template.Tool.MaxCpuPercent > 0
            ? (uint)Math.Clamp(template.Tool.MaxCpuPercent, 5, 100)
            : 50u;

        var limits = new LeaseResourceLimits(
            MaxMemoryBytes: memoryBytes,
            MaxCpuPercent: cpuPercent,
            MaxPids: 50);

        // 5. CoW OverlayFS scratch space
        var overlay = new OverlayFsSpec(
            EnableCow: true,
            LowerDir: "/var/splat/baseline",
            ScratchDir: $"/tmp/splat_scratch/{missionId}");

        return new LeaseSpec(
            MissionId: missionId,
            WorkingDirectory: workingDirectory,
            AllowNetwork: allowNetwork,
            AllowedEgressIps: allowedIps.Distinct().ToList(),
            AllowedEgressPorts: allowedPorts.Distinct().ToList(),
            ReadOnlyFs: false,
            ProtectedInodes: protectedList,
            AllowedExecInodes: allowedExecList,
            LeaseDurationSeconds: clampedDuration,
            Limits: limits,
            OverlayFs: overlay);
    }

    private static IReadOnlyList<string> GetStandardLinuxBinaryPaths(string toolName)
    {
        return toolName switch
        {
            "ping" => new[] { "/bin/ping", "/usr/bin/ping" },
            "curl" => new[] { "/bin/curl", "/usr/bin/curl" },
            "wevtutil" or "journalctl" => new[] { "/bin/journalctl", "/usr/bin/journalctl" },
            "wmic" or "df" => new[] { "/bin/df", "/usr/bin/df" },
            "sc" or "systemctl" => new[] { "/bin/systemctl", "/usr/bin/systemctl" },
            "whoami" => new[] { "/bin/whoami", "/usr/bin/whoami", "/usr/bin/id" },
            "net" or "ss" or "ip" => new[] { "/bin/ss", "/usr/bin/ss", "/bin/ip", "/usr/bin/ip" },
            "reg" or "cat" => new[] { "/bin/cat", "/usr/bin/cat", "/usr/bin/find" },
            _ => new[] { $"/bin/{toolName}", $"/usr/bin/{toolName}" }
        };
    }
}