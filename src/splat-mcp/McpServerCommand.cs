using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SplatMcp;

/// <summary>
/// What the command line asked for, decided before the server builds anything.
///
/// A bad invocation must cost nothing — no ledger database, no catalog seeding, no daemon client —
/// so this is a pure function of the arguments plus one question to the filesystem, and
/// <see cref="Program"/> acts on the verdict before it constructs a single service. The workspace is
/// validated, never created: a typo in a client's config should fail loudly in that client's log,
/// not quietly hand the agent a new, empty directory somewhere nobody meant.
/// </summary>
public abstract record McpServerCommand
{
    /// <summary>The conventional exit status for "invoked wrong".</summary>
    public const int UsageExitCode = 2;

    public static string Usage => $"""
        Usage: splat-mcp [--workspace <dir>] [--egress <a.b.c.d:port,...>]
               splat-mcp doctor [--workspace <dir>] [--egress <a.b.c.d:port,...>]
               splat-mcp provision [--apply]

        Serves SPLAT's governed tools to an MCP client: JSON-RPC, one message per line, on stdin
        and stdout. Diagnostics go to stderr, never stdout.

          doctor              Report what this host will and will not enforce - kernel,
                              BPF-LSM, the daemon and its token - and exit. Exits 0 only
                              when a lease would reach the kernel. Serves nothing, and
                              creates nothing.
          provision           Do what doctor reports missing: build and install the lease
                              daemon in the guest and start it under systemd, so it is there
                              after a restart. Reports only, until --apply.
          --apply             With provision, make the changes rather than listing them.
                              `wsl --install` and `wsl --shutdown` stay yours: one needs
                              administrator rights, the other ends every WSL session you have.
          --workspace <dir>   The one directory fs_read and fs_write may touch. It must already
                              exist; it is never created. Without it, both are confined to
                              {McpServerHandler.DefaultWorkspaceRoot}
          --egress <list>     The only endpoints run_command and run_code leases may connect
                              to, as IPv4 a.b.c.d:port separated by commas. A caller may ask
                              for some of them and never for others. Without it, neither tool
                              gets any network.
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
        IReadOnlyList<string> options = doctor || provision ? args.Skip(1).ToArray() : args;

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

                if (!provision)
                {
                    return new UsageError("--apply is only for `splat-mcp provision`.");
                }

                if (!given.TryAdd("--apply", string.Empty))
                {
                    return new UsageError("--apply was given more than once.");
                }

                continue;
            }

            if (option is not ("--workspace" or "--egress"))
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
                return new UsageError(option == "--workspace"
                    ? "--workspace needs a directory."
                    : "--egress needs a list of a.b.c.d:port endpoints.");
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

        if (provision)
        {
            // Neither option changes what provisioning does, and accepting one would say otherwise.
            string? irrelevant = given.Keys.FirstOrDefault(key => key is "--workspace" or "--egress");
            return irrelevant is null
                ? new Provision(given.ContainsKey("--apply"))
                : new UsageError($"`provision` takes only --apply; {irrelevant} belongs to the server or to `doctor`.");
        }

        return given.TryGetValue("--workspace", out string? workspace)
            ? ValidateWorkspace(workspace, egress, doctor)
            : Built(doctor, null, egress);
    }

    private static McpServerCommand ValidateWorkspace(string workspace, McpEgressPolicy egress, bool doctor)
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

        return Built(doctor, full, egress);
    }

    /// <summary>
    /// Run the server. <see cref="WorkspaceRoot"/> is null when no --workspace was given, and
    /// <see cref="Egress"/> is <see cref="McpEgressPolicy.None"/> when no --egress was.
    /// </summary>
    public sealed record Serve(string? WorkspaceRoot, McpEgressPolicy Egress) : McpServerCommand;

    private static McpServerCommand Built(bool doctor, string? workspaceRoot, McpEgressPolicy egress) =>
        doctor ? new Doctor(workspaceRoot, egress) : new Serve(workspaceRoot, egress);

    /// <summary>Report what this host will and will not enforce, then exit. Serves nothing.</summary>
    public sealed record Doctor(string? WorkspaceRoot, McpEgressPolicy Egress) : McpServerCommand;

    /// <summary>
    /// Do what `doctor` reports missing. <see cref="Apply"/> is false by default: the steps write to
    /// /etc inside the guest and to the user's .wslconfig, so a dry run is what an unqualified
    /// invocation gets.
    /// </summary>
    public sealed record Provision(bool Apply) : McpServerCommand;

    public sealed record ShowHelp : McpServerCommand;

    public sealed record UsageError(string Message) : McpServerCommand;
}
