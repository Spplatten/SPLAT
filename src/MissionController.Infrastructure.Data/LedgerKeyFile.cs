using System;
using System.IO;

namespace MissionController.Infrastructure.Data.Audit;

/// <summary>
/// The operator's ledger key: the raw bytes of a file they keep, in a folder SPLAT never writes to.
/// SPLAT reads the file and never writes it or prints it. Every message here names the path and a
/// length, never a byte of the key.
/// </summary>
public static class LedgerKeyFile
{
    /// <summary>
    /// How a host with no command line of its own - the console - is given the key file, and what
    /// splat-mcp falls back to without --ledger-key.
    /// </summary>
    public const string EnvironmentVariable = "SPLAT_LEDGER_KEY_FILE";

    /// <summary>32 random bytes is HMAC-SHA256's full strength.</summary>
    public const int MinimumBytes = 32;

    /// <summary>A key file is small; anything larger was named by mistake and would be read on every start.</summary>
    public const int MaximumBytes = 4096;

    /// <summary>Why this path cannot be the key file, or null when it can. Looks only at the file's length.</summary>
    public static string? Problem(string fullPath)
    {
        if (Directory.Exists(fullPath))
        {
            return $"'{fullPath}' is a folder; the ledger key is a file.";
        }

        if (!File.Exists(fullPath))
        {
            return $"'{fullPath}' does not exist. SPLAT never creates the key file.";
        }

        long length = new FileInfo(fullPath).Length;
        if (length < MinimumBytes)
        {
            return $"'{fullPath}' holds {length} bytes; a ledger key needs at least {MinimumBytes}.";
        }

        return length > MaximumBytes
            ? $"'{fullPath}' holds {length} bytes, more than a key file should ({MaximumBytes}), so it is probably not the key."
            : null;
    }

    public static byte[] Read(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (Problem(fullPath) is string problem)
        {
            throw new InvalidOperationException(problem);
        }

        byte[] key = File.ReadAllBytes(fullPath);
        // Checked again on the bytes actually read: the file can change between the two looks.
        if (key.Length is < MinimumBytes or > MaximumBytes)
        {
            throw new InvalidOperationException($"'{fullPath}' changed while it was read, to {key.Length} bytes.");
        }

        return key;
    }
}
