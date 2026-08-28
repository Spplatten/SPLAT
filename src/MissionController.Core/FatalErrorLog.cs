using System;
using System.IO;

namespace MissionController.Core;

/// <summary>
/// Last-resort crash sink for failures that kill the process before any UI exists.
///
/// This lives in Core rather than inside the App class for one reason: a crash logger that cannot be
/// tested is a crash logger you find out about during the crash. Keeping it free of WinUI types lets
/// the suite prove it appends, creates its directory, and - most importantly - stays silent when it
/// cannot write at all.
/// </summary>
public static class FatalErrorLog
{
    /// <summary>Where the app writes startup and unhandled-exception detail by default.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SPLAT",
        "crash.log");

    /// <summary>
    /// Appends one fatal-error record. Returns whether it reached disk, so a caller that cares can
    /// tell - but callers on the crash path should ignore it and carry on.
    ///
    /// Never throws. A logger that raises during crash handling replaces a diagnosable failure with
    /// an undiagnosable one, which is strictly worse than losing the record.
    /// </summary>
    public static bool Write(string source, object? detail, string? path = null)
    {
        try
        {
            string target = path ?? DefaultPath;

            string? directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.AppendAllText(
                target,
                $"[{DateTime.UtcNow:O}] {source}{Environment.NewLine}{detail}{Environment.NewLine}{Environment.NewLine}");

            return true;
        }
        catch
        {
            return false;
        }
    }
}
