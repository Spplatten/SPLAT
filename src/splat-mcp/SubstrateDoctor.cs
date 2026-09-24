using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
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
        string? defaultWorkspace = null,
        string? ledgerPath = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(doctor);
        ArgumentNullException.ThrowIfNull(output);
        wsl ??= RunWslAsync;
        health ??= new WslSubstrateHealthChecker();

        output.WriteLine("SPLAT doctor - what this host will enforce");
        output.WriteLine();

        string workspace = doctor.WorkspaceRoot ?? defaultWorkspace ?? McpServerHandler.DefaultWorkspaceRoot;
        bool exists = Directory.Exists(workspace);
        output.WriteLine("Windows control plane");
        // The server creates the default folder when it first starts, so a host that has never served
        // has none - which a clean machine reported as FAIL above a verdict of enforcing (2026-09-18).
        // A --workspace is never created, and the parser refused a missing one, so absence there is real.
        Line(output, exists || doctor.WorkspaceRoot is null, "workspace", (doctor.WorkspaceRoot, exists) switch
        {
            (null, true) => $"{workspace} (the default; --workspace names another)",
            (null, false) => $"{workspace} (the default; the server creates it when it first starts, and --workspace names another)",
            (_, true) => $"{workspace} (from --workspace)",
            (_, false) => $"{workspace} (from --workspace) does not exist",
        });
        Line(output, true, "file tools",
            "fs_read and fs_write are confined to that directory by the handle the kernel opened, not by the path string");
        var census = CapabilityManifest.CensusOf(GovernedTemplateCatalog.All);
        Line(output, census.Unconfined == 0 ? "ok" : "--", "sensor network",
            $"{census.NetworkDenied} of {census.Templates} catalog templates run network-denied; "
            + $"{census.Unconfined} keep a network stack ({census.NeedsNetwork} needs it, "
            + $"{census.LocalSubsystems} would lose WMI, the Event Log, Defender or the SCM inside the container)");
        var (ledgerMark, ledgerDetail) = await LedgerLineAsync(ledgerPath ?? LedgerPath(), doctor.LedgerKeyPath, ct);
        Line(output, ledgerMark, "audit ledger", ledgerDetail);
        var (signingMark, signingDetail) = RunRecordKeyLine(doctor.RunRecordKeyPath);
        Line(output, signingMark, "run records", signingDetail);
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

            if (status.Authenticated)
            {
                // Not a failure either: an older daemon answers unwrapped and is believed as before. It
                // is the line that says whether what comes back from a lease is proven or only trusted.
                Line(output, status.FramesProven ? "ok" : "--", "daemon frames",
                    status.FramesProven
                        ? "proven: every frame the daemon sends back is proven for its place on the connection"
                        : "unproven: this daemon predates 2026-09-23 and answers unwrapped; `splat-mcp provision --apply` installs the one this executable carries");
            }

            // Not a failure: a host without one is as it was before ceilings existed. It is the line
            // that says what a stolen token would buy.
            Line(output, status.CeilingPolicy ? "ok" : "--", "lease ceiling",
                !status.Authenticated
                    ? "unknown: the daemon would not answer this host"
                    : status.CeilingPolicy
                        ? "the guest bounds every lease from /etc/splat/policy.json, whoever holds the token"
                        : "none in the guest, so the token alone authorizes what a lease may name. `splat-mcp provision --apply` writes one; add --egress <list> to bound the network from there too");
        }

        output.WriteLine();
        output.WriteLine("Network for leases");
        // Not a failure: no network is the safe end of this dial, and the only one that needs no
        // trust in the operator getting a list right.
        Line(output, doctor.Egress.IsEmpty ? "--" : "ok", "lease network",
            doctor.Egress.IsEmpty
                ? "no --egress given, so a lease gets no network at all"
                : $"may connect only to {doctor.Egress}");

        if (doctor.Egress.NamesNoResolver)
        {
            Line(output, "--", "name lookups",
                "this policy names no resolver on port 53, and the kernel refuses a leased tool's DNS "
                + "datagram like any other destination - so a lease can reach these addresses by IP and "
                + "cannot look a name up. Add your resolver as a.b.c.d:53 if a tool needs one.");
        }

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

    /// <summary>
    /// Keyed or not is a property of the chain already written, so it is read from the file - without
    /// creating it - rather than inferred from the options this run was given.
    /// </summary>
    private static async Task<(string Mark, string Detail)> LedgerLineAsync(string path, string? keyPath, CancellationToken ct)
    {
        byte[]? key;
        SqliteChainedAuditLedger.ChainState chain;
        try
        {
            key = keyPath is null ? null : LedgerKeyFile.Read(keyPath);
            chain = await SqliteChainedAuditLedger.InspectAsync(path, key, ct);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.Data.Common.DbException)
        {
            return ("FAIL", $"{path} - could not be read: {ex.Message}");
        }

        if (chain.Keyed)
        {
            return (key, chain.KeyMatches) switch
            {
                (null, _) => ("FAIL", $"{path} - keyed, and no key file was given, so the server would refuse to start"),
                (_, true) => ("ok", $"{path} - keyed by {keyPath}: no entry can be rewritten unnoticed without that key, and a saved audit anchor catches deleted newest entries"),
                _ => ("FAIL", $"{path} - keyed, but not by {keyPath}, so the server would refuse to start"),
            };
        }

        return key is null
            ? ("--", $"{path} - hash-chained and UNKEYED, so a rewrite by this user is undetectable; --ledger-key keys it")
            : ("ok", $"{path} - {(chain.Exists ? "unkeyed so far; its next entry keys it" : "not created yet; its first entry will be keyed")}, by {keyPath}");
    }

    /// <summary>
    /// Whether exported run record bundles would be signed, read from the key file itself: a bundle
    /// nobody can attribute is the one thing an auditor cannot check, so an unsigned host says so here
    /// rather than at export time.
    /// </summary>
    private static (string Mark, string Detail) RunRecordKeyLine(string? keyPath)
    {
        if (keyPath is null)
        {
            return ("--", "exported bundles are UNSIGNED, so they show only that their own files agree; "
                + $"--run-record-key <file> or {RunRecordKeyFile.EnvironmentVariable} signs them");
        }

        try
        {
            using var signer = RunRecordKeyFile.Load(keyPath);
            return ("ok", $"signed by {signer.KeyId} ({signer.Algorithm}), from {keyPath}; publish that fingerprint to whoever checks a bundle");
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            return ("FAIL", $"{keyPath} - {ex.Message}");
        }
    }

    private static string LedgerPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT", "audit_ledger.db");

    private static string Short(string text) =>
        text.Length <= 90 ? text.ReplaceLineEndings(" ") : text.ReplaceLineEndings(" ")[..90] + "...";

    /// <summary>
    /// How long one wsl.exe probe gets. A budget rather than a limit: exceeding it is an answer -
    /// this host did not say in time - and the report prints that instead of failing.
    /// </summary>
    internal static readonly TimeSpan ProbeBudget = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The real runner, shared with the provisioner so both reach the guest the same way. Two
    /// parameters, not three with a default: this signature is the one <see cref="WslRunner"/>
    /// names, and an optional parameter would stop it converting to that delegate.
    /// </summary>
    internal static Task<(int, string)> RunWslAsync(IReadOnlyList<string> args, CancellationToken ct) =>
        RunWslAsync(args, ct, ProbeBudget);

    /// <summary>
    /// The same probe under an explicit budget, so the suite can reach the timeout path in
    /// milliseconds rather than waiting fifteen seconds for it.
    /// </summary>
    internal static async Task<(int, string)> RunWslAsync(
        IReadOnlyList<string> args, CancellationToken ct, TimeSpan budget)
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
            cts.CancelAfter(budget);
            using var process = Process.Start(start);
            if (process is null)
            {
                return (-1, "wsl.exe did not start");
            }

            // Both streams at once. Reading one to its end before starting the other deadlocks the moment
            // the child fills the second pipe's buffer, and waits out the fifteen seconds for nothing.
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(cts.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(cts.Token);
            await process.WaitForExitAsync(cts.Token);
            return (process.ExitCode, OutputOf(process.ExitCode, await stdout, await stderr));
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // A missing wsl.exe, a distro that will not start, or a probe that outlived its patience:
            // all three mean the same thing to a reader - this host cannot answer for the substrate.
            //
            // The filter turns on the CALLER's token, and it used to turn on the exception type,
            // which excluded the one case the comment above promises: the budget above is this
            // method's own, so when it fired - ct untouched - the OperationCanceledException was
            // rethrown and `doctor` died with it instead of reporting. That is not theoretical.
            // It took down the packaging gate on 2026-09-24, on a loaded machine, on a commit that
            // touched neither WSL nor the doctor. A caller who cancels still gets its cancellation,
            // because then this filter is false and the exception goes on up.
            return (-1, ex is OperationCanceledException
                ? $"wsl.exe did not answer within {budget.TotalSeconds:0.##}s"
                : ex.Message);
        }
    }

    /// <summary>
    /// What a caller gets to parse. On success, stdout alone: wsl.exe writes its own diagnostics to stderr, and
    /// on a guest whose systemd user session will not start it writes "wsl: Failed to start the systemd user
    /// session ..." on every call - measured 2026-09-13, stdout clean and exit 0 beside it. Appended to the
    /// answer, that turns `systemd` from `ps -p 1` into something that is not "systemd", so provision would
    /// report a guest without systemd, and turns a wslpath answer into a path that does not exist. On failure,
    /// both streams, because then stderr is the diagnosis.
    /// </summary>
    public static string OutputOf(int exitCode, string stdout, string stderr) =>
        (exitCode == 0 ? stdout : stdout + stderr).Trim();
}
