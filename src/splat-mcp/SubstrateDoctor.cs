using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;

namespace SplatMcp;

/// <summary>
/// What this host will and will not enforce, printed before anyone trusts it with an agent.
///
/// Every line is either read from this machine now or copied from the substrate's own policy tables;
/// nothing is claimed because it is true on some other host. The verdict is also the exit status —
/// 0 only when a lease would actually reach the kernel — so a setup script can gate on it, and
/// "the daemon answered" is never mistaken for "the daemon is enforcing".
/// </summary>
public static class SubstrateDoctor
{
    /// <summary>Runs `wsl.exe` with these arguments; the seam exists so the report can be tested.</summary>
    public delegate Task<(int ExitCode, string Output)> WslRunner(IReadOnlyList<string> args, CancellationToken ct);

    public static async Task<int> RunAsync(
        McpServerCommand.Doctor doctor,
        TextWriter output,
        WslRunner? wsl = null,
        WslSubstrateHealthChecker? health = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(doctor);
        ArgumentNullException.ThrowIfNull(output);
        wsl ??= RunWslAsync;
        health ??= new WslSubstrateHealthChecker();

        output.WriteLine("SPLAT doctor - what this host will enforce");
        output.WriteLine();

        string workspace = doctor.WorkspaceRoot ?? McpServerHandler.DefaultWorkspaceRoot;
        output.WriteLine("Windows control plane");
        Line(output, Directory.Exists(workspace), "workspace",
            doctor.WorkspaceRoot is null
                ? $"{workspace} (the default; --workspace names another)"
                : $"{workspace} (from --workspace)");
        Line(output, true, "file tools",
            "fs_read and fs_write are confined to that directory by the handle the kernel opened, not by the path string");
        var census = CapabilityManifest.CensusOf(GovernedTemplateCatalog.All);
        Line(output, census.Unconfined == 0 ? "ok" : "--", "sensor network",
            $"{census.NetworkDenied} of {census.Templates} catalog templates run network-denied; "
            + $"{census.Unconfined} keep a network stack ({census.NeedsNetwork} needs it, "
            + $"{census.LocalSubsystems} would lose WMI, the Event Log, Defender or the SCM inside the container)");
        Line(output, true, "audit ledger",
            $"{LedgerPath()} - hash-chained and UNKEYED, so a rewrite by this user is undetectable");
        output.WriteLine();

        // The kernel and its boot line are readable whether or not the daemon is up, and they are what
        // says whether this host could enforce at all - so they are probed separately from the daemon.
        output.WriteLine("Linux lease substrate - run_command and run_code");
        var (wslExit, wslOutput) = await wsl(
            new[] { "-e", "sh", "-c", "uname -r; echo ---; cat /proc/cmdline" }, ct);
        bool wslPresent = wslExit == 0;
        string kernel = wslPresent ? wslOutput.Split("---")[0].Trim() : "unknown";
        string cmdline = wslPresent && wslOutput.Contains("---") ? wslOutput.Split("---")[1] : string.Empty;
        bool bpfRequested = cmdline
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(token => token.StartsWith("lsm=", StringComparison.Ordinal))
            .SelectMany(token => token["lsm=".Length..].Split(','))
            .Any(lsm => lsm.Trim() == "bpf");

        Line(output, wslPresent, "WSL", wslPresent ? kernel : $"not available: {Short(wslOutput)}");
        Line(output, bpfRequested, "BPF-LSM",
            bpfRequested
                ? "bpf is on the boot command line, so the kernel initialised it"
                : "bpf is NOT on the boot command line - no lease can be enforced until .wslconfig names it");

        var status = await health.CheckHealthAsync(ct);
        Line(output, status.DaemonReachable, "daemon",
            status.DaemonReachable ? "reachable" : "not reachable - run_command and run_code will fail, not fall back");
        if (status.DaemonReachable)
        {
            // Reported from the request that was actually made, not from `test -r` on the file. A
            // present token is not an accepted one - a stale secret, or a daemon restarted with a
            // new one, reads as "this host can authenticate" to a presence check while every
            // request it makes is refused. The health check above is that request.
            Line(output, status.Authenticated, "daemon token",
                status.Authenticated
                    ? $"accepted: a request from this host authenticated against {WslAgentToken.DefaultPath} (root-owned)"
                    : $"REFUSED: {status.Message}");

            Line(output, status.Authenticated && status.Enforcing, "enforcement",
                !status.Authenticated
                    ? "unknown: the daemon would not answer this host, so whether a lease reaches the kernel cannot be read from here"
                    : status.Enforcing
                        ? $"live: a lease reaches the kernel ({status.ActiveLeaseCount} active)"
                        : "the daemon answers but holds no BPF maps: treat anything it runs as UNCONTAINED");
        }

        output.WriteLine();
        output.WriteLine("Network for leases");
        // Not a failure: no network is the safe end of this dial, and the only one that needs no
        // trust in the operator getting a list right.
        Line(output, doctor.Egress.IsEmpty ? "--" : "ok", "lease network",
            doctor.Egress.IsEmpty
                ? "no --egress given, so a lease gets no network at all"
                : $"may connect only to {doctor.Egress}");

        output.WriteLine();
        output.WriteLine("What a lease enforces when one runs (native/splat-agent/SUPPORTED_POLICY.md)");
        foreach (var group in CapabilityManifest.Lease.GroupBy(row => row.Where))
        {
            output.WriteLine($"  {Label(group.Key),-24}{string.Join("; ", group.Select(row => row.What))}");
        }

        bool enforcing = status.Enforcing;
        output.WriteLine();
        output.WriteLine(enforcing
            ? "Verdict: a lease on this host reaches the kernel. run_command and run_code are enforced."
            : "Verdict: NOT enforcing here. Nothing above changes what fs_read and fs_write do, but run_command and run_code cannot be trusted to contain anything on this host.");
        return enforcing ? 0 : 1;
    }

    private static string Label(LeaseEnforcement where) => where switch
    {
        LeaseEnforcement.Kernel => "enforced in the kernel",
        LeaseEnforcement.Daemon => "enforced by the daemon",
        LeaseEnforcement.Refused => "refused by the daemon",
        _ => "not policed",
    };

    private static void Line(TextWriter output, bool ok, string what, string detail) =>
        Line(output, ok ? "ok" : "FAIL", what, detail);

    private static void Line(TextWriter output, string mark, string what, string detail) =>
        output.WriteLine($"  {mark,-6}{what,-18}{detail}");

    private static string LedgerPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT", "audit_ledger.db");

    private static string Short(string text) =>
        text.Length <= 90 ? text.ReplaceLineEndings(" ") : text.ReplaceLineEndings(" ")[..90] + "...";

    /// <summary>The real runner, shared with the provisioner so both reach the guest the same way.</summary>
    internal static async Task<(int, string)> RunWslAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var start = new ProcessStartInfo("wsl.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));
            using var process = Process.Start(start);
            if (process is null)
            {
                return (-1, "wsl.exe did not start");
            }

            string stdout = await process.StandardOutput.ReadToEndAsync(cts.Token);
            string stderr = await process.StandardError.ReadToEndAsync(cts.Token);
            await process.WaitForExitAsync(cts.Token);
            return (process.ExitCode, (stdout + stderr).Trim());
        }
        catch (Exception ex) when (ex is not OperationCanceledException || ct.IsCancellationRequested)
        {
            // A missing wsl.exe, a distro that will not start, or a probe that outlived its patience:
            // all three mean the same thing to a reader - this host cannot answer for the substrate.
            return (-1, ex.Message);
        }
    }
}
