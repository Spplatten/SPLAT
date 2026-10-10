using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Host;

namespace SplatMcp;

/// <summary>
/// What the command line asked for, decided before the server builds anything.
///
/// A bad invocation must cost nothing — no ledger database, no catalog seeding, no daemon client —
/// so this is a pure function of the arguments plus a look at the paths they name, and
/// <see cref="Program"/> acts on the verdict before it constructs a single service. The workspace is
/// validated, never created: a typo in a client's config should fail loudly in that client's log,
/// not quietly hand the agent a new, empty directory somewhere nobody meant.
/// </summary>
public abstract record McpServerCommand
{
    /// <summary>The conventional exit status for "invoked wrong".</summary>
    public const int UsageExitCode = 2;

    public static string Usage => $"""
        Usage: splat-mcp [--workspace <dir>] [--egress <a.b.c.d:port,...>] [--ledger-key <file>] [--run-record-key <file>]
               splat-mcp doctor [--workspace <dir>] [--egress <a.b.c.d:port,...>] [--ledger-key <file>] [--run-record-key <file>]
               splat-mcp provision [--apply] [--egress <a.b.c.d:port,...>]
               splat-mcp unmount [--apply] [--manifest <file>]
               splat-mcp new-run-record-key <file>
               splat-mcp managed --configuration <administrator-owned bridge.json>
               splat-mcp provision --managed --rootfs <clean archive> --rootfs-sha256 <publisher hash> --operator-sid <SID[,SID]> [--instance SplatManaged] [--egress <list>] [--apply]
               splat-mcp unmount --managed [--instance SplatManaged] [--apply]

        Serves SPLAT's governed tools to an MCP client: JSON-RPC, one message per line, on stdin
        and stdout. Diagnostics go to stderr, never stdout.

          doctor              Report what this host will and will not enforce - kernel,
                              BPF-LSM, the daemon and its token - and exit. Exits 0 only
                              when a lease would reach the kernel. Serves nothing, and
                              creates nothing.
          provision           Do what doctor reports missing: build and install the lease
                              daemon in the guest and start it under systemd, so it is there
                              after a restart. Reports only, until --apply.
          unmount             Take out what a mount put in, by playing its manifest backwards:
                              the unit, the daemon, the lease ceiling, the token, and only the
                              config lines the mount appended. Reports only, until --apply. It
                              refuses without a manifest rather than deleting whatever looks
                              like SPLAT, and names anything it could not restore.
          retain              Apply the retention policy to the two databases: overwrite mission
                              payload columns past their window, drop semantic index rows whole,
                              and cryptographically erase audit detail while the chain's
                              commitment to it survives. Reports only, until --apply. There is no
                              undo - the counts it reports without --apply come from the sweep's
                              own predicates, not from a second query written to match them.
          --manifest <file>   With unmount, the manifest to play backwards. Without it, the one
                              the mount wrote under the data root.
          --apply             With provision, unmount or retain, make the changes rather than listing them.
                              `wsl --install` and `wsl --shutdown` stay yours: one needs
                              administrator rights, the other ends every WSL session you have.
          --workspace <dir>   The one directory fs_read and fs_write may touch. It must already
                              exist; it is never created. Without it, both are confined to
                              {McpServerHandler.DefaultWorkspaceRoot}
          --egress <list>     The only endpoints run_command and run_code leases may connect
                              to, as IPv4 a.b.c.d:port separated by commas. A caller may ask
                              for some of them and never for others. Without it, neither tool
                              gets any network. With provision, the same list is written into
                              the guest's lease ceiling (/etc/splat/policy.json), which bounds
                              every lease from inside the guest, whoever holds the token.
          --ledger-key <file> The operator's key for the audit ledger: a file of 32 to 4096
                              bytes, read and never written or printed. With it every new
                              entry is HMAC-SHA256 under the key, and a keyed ledger is never
                              extended without it. Without the option, the path in
                              {LedgerKeyFile.EnvironmentVariable} is used; with neither, the ledger is unkeyed.
          new-run-record-key  Make a run record signing key at the path given, readable only
                              by you, and print its fingerprint. It refuses to overwrite a
                              file. Publish the fingerprint: it is how anyone you hand a
                              bundle to tells your bundles from a forgery.
          --run-record-key <file>
                              The operator's key for signing run record bundles: an RSA
                              private key in PEM, read and never written or printed. Without
                              the option, the path in {RunRecordKeyFile.EnvironmentVariable}
                              is used; with neither, bundles are exported unsigned and say so.
          -h, --help          Show this and exit.

        """;

    public static McpServerCommand Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        // Help wins wherever it appears: someone who typed it wants the usage, not a complaint
        // about whatever else is on the line.
        foreach (string arg in args)
        {
            if (arg is "-h" or "--help")
            {
                return new ShowHelp();
            }
        }

        // Each option may be given once: were a second value to win silently, what the server confines
        // would depend on the order a client's config happened to list them.
        // `doctor` is a subcommand, and only as the first argument: the value of an option
        // must never be able to turn into one.
        bool doctor = args.Count > 0 && args[0] == "doctor";
        bool provision = args.Count > 0 && args[0] == "provision";
        bool unmount = args.Count > 0 && args[0] == "unmount";
        bool retain = args.Count > 0 && args[0] == "retain";
        if (args.Count > 0 && args[0] == "new-run-record-key")
        {
            if (args.Count != 2 || args[1].StartsWith('-'))
            {
                return new UsageError("`new-run-record-key` takes one argument: the path of the key file to make.");
            }

            try
            {
                return new NewRunRecordKey(Path.GetFullPath(args[1]));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return new UsageError($"'{args[1]}' is not a usable path: {ex.Message}");
            }
        }

        IReadOnlyList<string> options = doctor || provision || unmount || retain ? args.Skip(1).ToArray() : args;

        var given = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < options.Count; i++)
        {
            string arg = options[i];
            int equals = arg.IndexOf('=');
            string option = equals < 0 ? arg : arg[..equals];
            string? value;

            // The one flag that carries no value. It is refused outside `provision` rather than
            // ignored there: an option that silently does nothing is how a caller comes to believe
            // a machine was changed when nothing was.
            if (option == "--apply")
            {
                if (equals >= 0)
                {
                    return new UsageError("--apply takes no value.");
                }

                if (!provision && !unmount && !retain)
                {
                    return new UsageError(
                        "--apply is only for `splat-mcp provision`, `splat-mcp unmount` and `splat-mcp retain`.");
                }

                if (!given.TryAdd("--apply", string.Empty))
                {
                    return new UsageError("--apply was given more than once.");
                }

                continue;
            }

            if (option == "--manifest" && !unmount)
            {
                return new UsageError("--manifest is only for `splat-mcp unmount`.");
            }

            if (option is not ("--workspace" or "--egress" or "--ledger-key" or "--run-record-key" or "--manifest"))
            {
                return arg.StartsWith('-')
                    ? new UsageError($"unknown option '{arg}'.")
                    : new UsageError($"unexpected argument '{arg}'. Each value follows its option, as in --workspace <dir> or --egress <list>.");
            }

            if (equals >= 0)
            {
                value = arg[(equals + 1)..];
            }
            else
            {
                // `--workspace --egress` is a forgotten value, not a directory named "--egress".
                value = i + 1 < options.Count && !options[i + 1].StartsWith('-') ? options[++i] : null;
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                return new UsageError(option switch
                {
                    "--workspace" => "--workspace needs a directory.",
                    "--ledger-key" => "--ledger-key needs the key file's path.",
                    "--run-record-key" => "--run-record-key needs the key file's path.",
                    _ => "--egress needs a list of a.b.c.d:port endpoints.",
                });
            }

            if (!given.TryAdd(option, value))
            {
                return new UsageError($"{option} was given more than once.");
            }
        }

        var egress = McpEgressPolicy.None;
        if (given.TryGetValue("--egress", out string? list))
        {
            try
            {
                egress = McpEgressPolicy.Parse(list);
            }
            catch (FormatException ex)
            {
                // Refused like a missing workspace, not served on with no network: the agent would meet
                // refusals it cannot explain, and the operator who wrote the list would hear nothing.
                return new UsageError($"--egress: {ex.Message}");
            }
        }

        if (unmount)
        {
            // Nothing else belongs to unmounting: it removes what a manifest records, and no option
            // here can widen or narrow that without making the record and the act disagree.
            string? extra = given.Keys.FirstOrDefault(key => key is "--workspace" or "--egress" or "--ledger-key" or "--run-record-key");
            if (extra is not null)
            {
                return new UsageError($"`unmount` takes only --apply and --manifest; {extra} belongs to the server or to `doctor`.");
            }

            string? manifest = null;
            if (given.TryGetValue("--manifest", out string? manifestPath))
            {
                try
                {
                    manifest = Path.GetFullPath(manifestPath);
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
                {
                    return new UsageError($"--manifest '{manifestPath}' is not a usable path: {ex.Message}");
                }
            }

            return new Unmount(given.ContainsKey("--apply"), manifest);
        }

        if (retain)
        {
            // A sweep reads the retention windows and the two databases, and nothing else. --egress and
            // --workspace confine a served tool; naming them here would suggest the sweep is bounded by
            // them, which it is not. --ledger-key IS taken: the audit chain's redaction runs against the
            // ledger this host would otherwise open with that key.
            string? foreign = given.Keys.FirstOrDefault(key => key is "--workspace" or "--egress" or "--manifest" or "--run-record-key");
            if (foreign is not null)
            {
                return new UsageError($"`retain` takes only --apply and --ledger-key; {foreign} belongs to the server or to another subcommand.");
            }

            return new Retain(given.ContainsKey("--apply"), given.GetValueOrDefault("--ledger-key"));
        }

        if (provision)
        {
            // --egress is provision's too: it is written into the guest's lease ceiling. The other
            // options change nothing about provisioning, and accepting one would say otherwise.
            string? irrelevant = given.Keys.FirstOrDefault(key => key is "--workspace" or "--ledger-key" or "--run-record-key");
            return irrelevant is null
                ? new Provision(given.ContainsKey("--apply"), egress)
                : new UsageError($"`provision` takes only --apply and --egress; {irrelevant} belongs to the server or to `doctor`.");
        }

        string? ledgerKey = null;
        if (given.TryGetValue("--ledger-key", out string? keyPath)
            && CheckKeyFile(keyPath, "--ledger-key", LedgerKeyFile.Problem, out ledgerKey) is UsageError keyError)
        {
            return keyError;
        }

        string? runRecordKey = null;
        if (given.TryGetValue("--run-record-key", out string? signingPath)
            && CheckKeyFile(signingPath, "--run-record-key", RunRecordKeyFile.Problem, out runRecordKey) is UsageError signingError)
        {
            return signingError;
        }

        return given.TryGetValue("--workspace", out string? workspace)
            ? ValidateWorkspace(workspace, egress, doctor, ledgerKey, runRecordKey)
            : Built(doctor, null, egress, ledgerKey, runRecordKey);
    }

    /// <summary>
    /// Fills in the ledger key from <see cref="LedgerKeyFile.EnvironmentVariable"/> when --ledger-key was
    /// not given. Kept out of <see cref="Parse"/>, which stays a function of its arguments, and so of
    /// nothing set on the machine that runs the tests.
    /// </summary>
    public static McpServerCommand WithLedgerKeyFromEnvironment(McpServerCommand command, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(environment);
        if (command is not (Serve { LedgerKeyPath: null } or Doctor { LedgerKeyPath: null }))
        {
            return command;
        }

        string? path = environment(LedgerKeyFile.EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            return command;
        }

        if (CheckKeyFile(path, LedgerKeyFile.EnvironmentVariable, LedgerKeyFile.Problem, out string? full) is UsageError error)
        {
            return error;
        }

        return command is Serve serve ? serve with { LedgerKeyPath = full } : ((Doctor)command) with { LedgerKeyPath = full };
    }

    /// <summary>The same for the run record signing key, from <see cref="RunRecordKeyFile.EnvironmentVariable"/>.</summary>
    public static McpServerCommand WithRunRecordKeyFromEnvironment(McpServerCommand command, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(environment);
        if (command is not (Serve { RunRecordKeyPath: null } or Doctor { RunRecordKeyPath: null }))
        {
            return command;
        }

        string? path = environment(RunRecordKeyFile.EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            return command;
        }

        if (CheckKeyFile(path, RunRecordKeyFile.EnvironmentVariable, RunRecordKeyFile.Problem, out string? full) is UsageError error)
        {
            return error;
        }

        return command is Serve serve ? serve with { RunRecordKeyPath = full } : ((Doctor)command) with { RunRecordKeyPath = full };
    }

    /// <summary>A key file that will not do stops the server before it starts, like a missing workspace.</summary>
    private static UsageError? CheckKeyFile(string path, string source, Func<string, string?> problemWith, out string? fullPath)
    {
        fullPath = null;
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new UsageError($"{source} '{path}' is not a usable path: {ex.Message}");
        }

        if (problemWith(full) is string problem)
        {
            return new UsageError($"{source}: {problem}");
        }

        fullPath = full;
        return null;
    }

    private static McpServerCommand ValidateWorkspace(string workspace, McpEgressPolicy egress, bool doctor, string? ledgerKey, string? runRecordKey)
    {
        string full;
        try
        {
            full = Path.GetFullPath(workspace);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new UsageError($"--workspace '{workspace}' is not a usable path: {ex.Message}");
        }

        if (File.Exists(full))
        {
            return new UsageError($"--workspace '{full}' is a file, not a directory.");
        }

        if (!Directory.Exists(full))
        {
            return new UsageError($"--workspace '{full}' does not exist. It is never created for you.");
        }

        return Built(doctor, full, egress, ledgerKey, runRecordKey);
    }

    /// <summary>
    /// Run the server. <see cref="WorkspaceRoot"/> is null when no --workspace was given,
    /// <see cref="Egress"/> is <see cref="McpEgressPolicy.None"/> when no --egress was, and
    /// <see cref="LedgerKeyPath"/> is null when the ledger is to chain unkeyed.
    /// </summary>
    public sealed record Serve(string? WorkspaceRoot, McpEgressPolicy Egress, string? LedgerKeyPath = null, string? RunRecordKeyPath = null) : McpServerCommand;

    private static McpServerCommand Built(bool doctor, string? workspaceRoot, McpEgressPolicy egress, string? ledgerKey, string? runRecordKey) =>
        doctor
            ? new Doctor(workspaceRoot, egress, ledgerKey, runRecordKey)
            : new Serve(workspaceRoot, egress, ledgerKey, runRecordKey);

    /// <summary>Report what this host will and will not enforce, then exit. Serves nothing.</summary>
    public sealed record Doctor(string? WorkspaceRoot, McpEgressPolicy Egress, string? LedgerKeyPath = null, string? RunRecordKeyPath = null) : McpServerCommand
    {
        public DoctorOptions Options => new(WorkspaceRoot, Egress, LedgerKeyPath, RunRecordKeyPath);
    }

    /// <summary>Make a run record signing key at this path, print its fingerprint, and exit.</summary>
    public sealed record NewRunRecordKey(string Path) : McpServerCommand;

    /// <summary>
    /// Do what `doctor` reports missing. <see cref="Apply"/> is false by default: the steps write to
    /// /etc inside the guest and to the user's .wslconfig, so a dry run is what an unqualified
    /// invocation gets.
    /// </summary>
    /// <summary>
    /// Provision the guest. <see cref="Egress"/> is what the lease ceiling written into the guest
    /// allows a lease to reach; <see cref="McpEgressPolicy.None"/> leaves the ceiling's egress
    /// unbounded, since the server's own --egress is then the only network policy.
    /// </summary>
    public sealed record Provision(bool Apply, McpEgressPolicy? Egress = null) : McpServerCommand
    {
        public McpEgressPolicy CeilingEgress => Egress ?? McpEgressPolicy.None;

        public ProvisionOptions Options => new(Apply, Egress);
    }

    /// <summary>
    /// Undo a mount. <see cref="Apply"/> is false by default, for the same reason provisioning's is:
    /// the steps remove a root daemon and rewrite files in /etc, and an unqualified invocation should
    /// say what it would do. <see cref="ManifestPath"/> is null for the manifest the mount wrote
    /// under the data root.
    /// </summary>
    public sealed record Unmount(bool Apply, string? ManifestPath = null) : McpServerCommand
    {
        public UnmountOptions Options => new(Apply, ManifestPath);
    }

    /// <summary>
    /// Run the retention sweep. <see cref="Apply"/> is false by default for a stronger reason than
    /// provisioning's: this erases. Mission payload columns are overwritten and audit detail is
    /// cryptographically erased, which leaves the chain's commitment and takes the text - so there is
    /// nothing to restore afterwards and no undo to write. An unqualified invocation reports what the
    /// sweep would take, counted by the sweep's own predicates.
    /// </summary>
    public sealed record Retain(bool Apply, string? LedgerKeyPath = null) : McpServerCommand;

    public sealed record ShowHelp : McpServerCommand;

    public sealed record UsageError(string Message) : McpServerCommand;
}
