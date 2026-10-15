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
    private readonly IHostAddressResolver _dnsResolver;

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

    /// <summary>
    /// The paths the daemon guards on every lease of its own accord, so naming them can never be
    /// refused for failing to resolve: they are the daemon's precondition, not this compiler's guess.
    /// </summary>
    private static readonly IReadOnlyList<string> DaemonGuardedPaths = new[]
    {
        "/etc/shadow",
        "/etc/sudoers"
    };

    public TemplatePolicyCompiler() : this(new SystemHostAddressResolver())
    {
    }

    public TemplatePolicyCompiler(IHostAddressResolver dnsResolver)
    {
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
    }

    public LeaseSpec CompileTemplatePolicy(
        SingleToolTemplate template,
        Guid missionId,
        string workingDirectory,
        uint leaseDurationSeconds = 30)
    {
        ArgumentNullException.ThrowIfNull(template);
        template.Tool.ExecutionPolicy?.Validate();
        if (template.Tool.ExecutionPolicy is not null && template.Tool.Substrate != ToolSubstrate.LinuxLease)
            throw new PolicyCompilationException("Execution policies require the Linux lease substrate.");
        if (string.IsNullOrWhiteSpace(workingDirectory))
        {
            workingDirectory = "/tmp/splat_sandboxes/" + missionId;
        }

        // Clamp duration between 5s and 300s (seconds-scoped, single-use lease)
        uint clampedDuration = Math.Clamp(leaseDurationSeconds, 5u, 300u);

        // 1. Resolve Executable Inodes / Allowed Binaries
        var allowedExecList = new List<InodeIdentifierModel>();
        if (template.Tool.Substrate == ToolSubstrate.LinuxLease)
        {
            // A template written for the lease names the one executable it runs, by its guest path,
            // and that path is the whole allow-list: no shell, no env, no second candidate under
            // another prefix. The 1:1:1 rule, compiled rather than approximated from a Windows name.
            string guestPath = template.Tool.ExecutablePath.Trim();
            if (!guestPath.StartsWith('/') || guestPath.Contains("/../", StringComparison.Ordinal) || guestPath.EndsWith("/..", StringComparison.Ordinal))
            {
                throw new PolicyCompilationException(
                    $"A Linux-lease template's tool must name an absolute guest path without '..'; '{template.Tool.ExecutablePath}' does not.");
            }

            allowedExecList.Add(new InodeIdentifierModel(0, 0, guestPath));
        }
        else
        {
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
        }

        // 2. Protected Files / Sensitive Inodes
        //
        // The daemon resolves every path named here to an inode in the guest and refuses the whole
        // lease when one does not resolve, because a protected path that silently failed to resolve
        // is a file that is silently not protected. This side of the wire runs on Windows and cannot
        // know what the guest holds - on 2026-09-24 the first leased catalog mission was refused
        // because the guest had no /root/.gnupg, no /var/run/docker.sock and no /proc/kcore. So a
        // template that runs under the lease names exactly the two paths the daemon always guards
        // itself (main.rs unions them in whether or not they are asked for), the way run_command
        // does; the ceiling adds the operator's, and the jail keeps /root, /var and /mnt out of the
        // workload's view altogether, which is what the other six on the default list were for.
        var protectedList = new List<InodeIdentifierModel>();
        foreach (var p in template.Tool.Substrate == ToolSubstrate.LinuxLease ? DaemonGuardedPaths : DefaultProtectedPaths)
        {
            protectedList.Add(new InodeIdentifierModel(0, 0, p));
        }

        // 3. Egress Rule Formulation
        bool allowNetwork = false;
        var allowedIps = new List<string>();
        var allowedPorts = new List<uint>();

        // Only a rule whose destination is opened by the SENSOR earns a network lease. This used to
        // read the FQDN alone, and since every template carries one - defaulting to the AI gateway,
        // which SPLAT's own process calls rather than the tool - the compiler opened the network for
        // the entire catalogue when almost no sensor touches it. Scope is what separates the two.
        string targetFqdn = template.EgressRule.ToolProcessNeedsNetwork
            ? template.EgressRule.AllowedFqdn?.Trim() ?? string.Empty
            : string.Empty;

        if (!string.IsNullOrEmpty(targetFqdn) &&
            !targetFqdn.Equals("none", StringComparison.OrdinalIgnoreCase) &&
            !targetFqdn.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !targetFqdn.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            if (template.EgressRule.AllowedPort is < 0 or > 65535)
            {
                throw new PolicyCompilationException(
                    $"Configured egress port {template.EgressRule.AllowedPort} is out of valid range (1-65535).");
            }

            uint port = template.EgressRule.AllowedPort > 0 ? (uint)template.EgressRule.AllowedPort : 443u;
            allowedPorts.Add(port);

            // Attempt DNS resolution to pin /32 IPv4 destinations
            IPAddress[] hostAddresses;
            try
            {
                hostAddresses = _dnsResolver.GetHostAddresses(targetFqdn);
            }
            catch (Exception ex)
            {
                throw new PolicyCompilationException(
                    $"Failed to resolve egress destination '{targetFqdn}' for tool process network lease: {ex.Message}", ex);
            }

            if (hostAddresses == null || hostAddresses.Length == 0)
            {
                throw new PolicyCompilationException(
                    $"Egress destination '{targetFqdn}' resolved to zero IP addresses. Refusing lease.");
            }

            foreach (var ip in hostAddresses)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    allowedIps.Add(ip.ToString());
                }
            }

            if (allowedIps.Count == 0)
            {
                throw new PolicyCompilationException(
                    $"Egress destination '{targetFqdn}' resolved to no usable IPv4 addresses. Refusing lease rather than fabricating permission.");
            }

            allowNetwork = true;
        }
        else if (targetFqdn.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                 targetFqdn.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            if (template.EgressRule.AllowedPort is < 0 or > 65535)
            {
                throw new PolicyCompilationException(
                    $"Configured loopback egress port {template.EgressRule.AllowedPort} is out of valid range (1-65535).");
            }

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

        // Catalog sensors use their declared executable inodes. Writable overlay execution is a
        // separate explicit grant and must never be enabled merely by compiling a template.
        var overlay = new OverlayFsSpec(
            EnableCow: false,
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
            OverlayFs: overlay,
            // A governed mission's workspace is the daemon's to make and remove; a caller that
            // compiled a Windows template for the guest keeps naming a directory of its own.
            EphemeralWorkspace: template.Tool.Substrate == ToolSubstrate.LinuxLease,
            ExecutionPolicy: template.Tool.ExecutionPolicy);
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

/// <summary>
/// Default host address resolver delegating to <see cref="Dns.GetHostAddresses(string)"/>.
/// </summary>
public sealed class SystemHostAddressResolver : IHostAddressResolver
{
    public IPAddress[] GetHostAddresses(string hostNameOrAddress) =>
        Dns.GetHostAddresses(hostNameOrAddress);
}
