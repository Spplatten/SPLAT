using System;
using System.Collections.Generic;
using System.IO;

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

        Serves SPLAT's governed tools to an MCP client: JSON-RPC, one message per line, on stdin
        and stdout. Diagnostics go to stderr, never stdout.

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
        var given = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];
            int equals = arg.IndexOf('=');
            string option = equals < 0 ? arg : arg[..equals];
            string? value;

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
                value = i + 1 < args.Count && !args[i + 1].StartsWith('-') ? args[++i] : null;
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

        return given.TryGetValue("--workspace", out string? workspace)
            ? ValidateWorkspace(workspace, egress)
            : new Serve(null, egress);
    }

    private static McpServerCommand ValidateWorkspace(string workspace, McpEgressPolicy egress)
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

        return new Serve(full, egress);
    }

    /// <summary>
    /// Run the server. <see cref="WorkspaceRoot"/> is null when no --workspace was given, and
    /// <see cref="Egress"/> is <see cref="McpEgressPolicy.None"/> when no --egress was.
    /// </summary>
    public sealed record Serve(string? WorkspaceRoot, McpEgressPolicy Egress) : McpServerCommand;

    public sealed record ShowHelp : McpServerCommand;

    public sealed record UsageError(string Message) : McpServerCommand;
}
