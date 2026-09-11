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
        Usage: splat-mcp [--workspace <dir>]

        Serves SPLAT's governed tools to an MCP client: JSON-RPC, one message per line, on stdin
        and stdout. Diagnostics go to stderr, never stdout.

          --workspace <dir>   The one directory fs_read and fs_write may touch. It must already
                              exist; it is never created. Without it, both are confined to
                              {McpServerHandler.DefaultWorkspaceRoot}
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

        string? workspace = null;
        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];
            string? value;

            if (arg == "--workspace")
            {
                // `--workspace --other` is a forgotten path, not a directory named "--other".
                value = i + 1 < args.Count && !args[i + 1].StartsWith('-') ? args[++i] : null;
            }
            else if (arg.StartsWith("--workspace=", StringComparison.Ordinal))
            {
                value = arg["--workspace=".Length..];
            }
            else if (arg.StartsWith('-'))
            {
                return new UsageError($"unknown option '{arg}'.");
            }
            else
            {
                return new UsageError($"unexpected argument '{arg}'. A workspace is given as --workspace <dir>.");
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                return new UsageError("--workspace needs a directory.");
            }

            if (workspace is not null)
            {
                return new UsageError("--workspace was given more than once.");
            }

            workspace = value;
        }

        return workspace is null ? new Serve(null) : ValidateWorkspace(workspace);
    }

    private static McpServerCommand ValidateWorkspace(string workspace)
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

        return new Serve(full);
    }

    /// <summary>Run the server. <see cref="WorkspaceRoot"/> is null when no --workspace was given.</summary>
    public sealed record Serve(string? WorkspaceRoot) : McpServerCommand;

    public sealed record ShowHelp : McpServerCommand;

    public sealed record UsageError(string Message) : McpServerCommand;
}
