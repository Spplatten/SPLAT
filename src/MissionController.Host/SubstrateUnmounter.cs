using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Host;

/// <summary>
/// Plays a mount manifest backwards, and says what it could not restore.
///
/// A mount is honest only if it can be undone. Until this existed `provision` had no inverse: a
/// person who ran it to see what SPLAT does was left with a root daemon, a systemd unit, a token, a
/// lease ceiling and two appended config stanzas, and no way to take them out but by hand, from a
/// list nobody had written down. The manifest is that list, written by the mount itself, so what
/// comes out is what went in rather than what this version of the code remembers to look for.
///
/// It refuses rather than guesses. No manifest means no unmount: removing "the things a mount
/// usually adds" would delete a daemon someone else installed, a unit they wrote, or a wsl.conf
/// stanza that was there first.
/// </summary>
public static class SubstrateUnmounter
{
    public static async Task<int> RunAsync(
        UnmountOptions unmount,
        TextWriter output,
        SubstrateDoctor.WslRunner? wsl = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(unmount);
        ArgumentNullException.ThrowIfNull(output);
        wsl ??= SubstrateDoctor.RunWslAsync;

        string manifestPath = unmount.ManifestPath ?? MissionController.Core.SplatDataRoot.Layout.MountManifest;

        output.WriteLine(unmount.Apply
            ? "SPLAT unmount - taking out what the mount put in"
            : "SPLAT unmount - what would be taken out (nothing is changed; add --apply)");
        output.WriteLine();

        if (!File.Exists(manifestPath))
        {
            output.WriteLine($"No mount manifest at {manifestPath}.");
            output.WriteLine(
                "Nothing is removed without one. A mount records every change it made, and unmounting " +
                "without that record would mean deleting whatever a daemon, a unit or a config stanza " +
                "happens to look like - including one this machine had before SPLAT arrived.");
            return 1;
        }

        MountManifest manifest;
        try
        {
            manifest = MountManifest.Read(manifestPath);
        }
        catch (InvalidOperationException ex)
        {
            output.WriteLine(ex.Message);
            return 1;
        }

        output.WriteLine($"Manifest  {manifestPath}");
        output.WriteLine($"Mounted   {manifest.MountedUtc:u} on {manifest.Host} ({manifest.Distro})");
        output.WriteLine($"Changes   {manifest.Changes.Count}");
        output.WriteLine();

        var unrestored = new List<string>();
        int undone = 0;

        // Backwards: the unit goes before the binary it runs, and a directory after what was in it.
        foreach (var change in manifest.Changes.Reverse())
        {
            var (mark, detail, problem) = await UndoAsync(change, unmount.Apply, wsl, ct);
            Line(output, mark, $"{change.Kind} {change.Path}", detail);
            if (problem is not null)
            {
                unrestored.Add(problem);
            }
            else if (mark == "ok")
            {
                undone++;
            }
        }

        output.WriteLine();
        if (!unmount.Apply)
        {
            output.WriteLine($"Nothing was changed. Re-run with --apply to take out the {manifest.Changes.Count} changes above.");
            return 0;
        }

        if (unrestored.Count == 0)
        {
            // The manifest goes last, and only when everything in it is gone. A manifest removed
            // while some of its changes remain would leave a host with no record of what is still on
            // it, which is the one state worse than not unmounting at all.
            File.Delete(manifestPath);
            output.WriteLine($"Unmounted. {undone} change(s) taken out, and the manifest with them.");
            return 0;
        }

        output.WriteLine($"Unmounted with {unrestored.Count} thing(s) this could not restore:");
        foreach (string note in unrestored)
        {
            output.WriteLine($"  - {note}");
        }

        output.WriteLine();
        output.WriteLine($"{manifestPath} is kept, because it is the only record of what is still on this host.");
        return 1;
    }

    private static async Task<(string Mark, string Detail, string? Problem)> UndoAsync(
        MountChange change, bool apply, SubstrateDoctor.WslRunner wsl, CancellationToken ct) => change.Kind switch
    {
        MountChange.Unit => await UndoUnitAsync(change, apply, wsl, ct),
        MountChange.File => await UndoFileAsync(change, apply, wsl, ct),
        MountChange.Directory => await UndoDirectoryAsync(change, apply, wsl, ct),
        MountChange.Lines => await UndoLinesAsync(change, apply, wsl, ct),
        _ => ("--", $"kind '{change.Kind}' is not one this build knows how to undo",
              $"{change.Path}: the manifest records a '{change.Kind}' change this build cannot reverse"),
    };

    private static async Task<(string, string, string?)> UndoUnitAsync(
        MountChange change, bool apply, SubstrateDoctor.WslRunner wsl, CancellationToken ct)
    {
        if (!apply)
        {
            return ("todo", "would stop and disable splat-agent, remove the unit and reload systemd", null);
        }

        string name = Path.GetFileName(change.Path);
        var (exit, text) = await wsl(Root(
            $"systemctl disable --now {name} >/dev/null 2>&1; rm -f {Quote(change.Path)}; systemctl daemon-reload"), ct);

        return exit == 0
            ? ("ok", "stopped, disabled, removed; systemd reloaded", null)
            : ("FAIL", Short(text), $"{change.Path}: the unit could not be removed ({Short(text)})");
    }

    private static async Task<(string, string, string?)> UndoFileAsync(
        MountChange change, bool apply, SubstrateDoctor.WslRunner wsl, CancellationToken ct)
    {
        string replaced = change.Replaced
            ? $" It replaced a file with sha256 {change.PreviousSha256}, which nothing here kept a copy of."
            : string.Empty;

        if (!apply)
        {
            return ("todo", "would be removed." + replaced, null);
        }

        if (change.Where == MountChange.Host)
        {
            try
            {
                File.Delete(change.Path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return ("FAIL", ex.Message, $"{change.Path}: {ex.Message}");
            }
        }
        else
        {
            var (exit, text) = await wsl(Root($"rm -f {Quote(change.Path)}"), ct);
            if (exit != 0)
            {
                return ("FAIL", Short(text), $"{change.Path}: could not be removed ({Short(text)})");
            }
        }

        return change.Replaced
            ? ("--", "removed, but what it replaced cannot be put back." + replaced,
               $"{change.Path}: removed, but the file it replaced (sha256 {change.PreviousSha256}) is gone for good")
            : ("ok", "removed", null);
    }

    private static async Task<(string, string, string?)> UndoDirectoryAsync(
        MountChange change, bool apply, SubstrateDoctor.WslRunner wsl, CancellationToken ct)
    {
        if (!apply)
        {
            return ("todo", "would be removed if empty", null);
        }

        // rmdir, never rm -r: anything else in there belongs to somebody, and a mount that took a
        // directory over is not entitled to take its contents with it on the way out.
        var (exit, _) = await wsl(Root($"rmdir {Quote(change.Path)} 2>/dev/null"), ct);
        return exit == 0
            ? ("ok", "removed", null)
            : ("--", "left in place: it is not empty, so something else is using it", null);
    }

    /// <summary>
    /// Takes out exactly the text the mount appended, and nothing else. The file is read, the block
    /// removed in one place, and the result written back - rather than a sed that would match the
    /// same stanza wherever it appears, including one the operator wrote themselves.
    /// </summary>
    private static async Task<(string, string, string?)> UndoLinesAsync(
        MountChange change, bool apply, SubstrateDoctor.WslRunner wsl, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(change.Appended))
        {
            return ("--", "the manifest records no text for this append, so nothing can be taken out",
                    $"{change.Path}: the manifest does not say what was appended");
        }

        string current;
        if (change.Where == MountChange.Host)
        {
            current = File.Exists(change.Path) ? File.ReadAllText(change.Path) : string.Empty;
        }
        else
        {
            var (readExit, text) = await wsl(Root($"cat {Quote(change.Path)} 2>/dev/null"), ct);
            current = readExit == 0 ? text : string.Empty;
        }

        string normalised = current.Replace("\r\n", "\n");
        string block = change.Appended.Replace("\r\n", "\n");
        int at = normalised.IndexOf(block, StringComparison.Ordinal);
        if (at < 0)
        {
            return ("--", "the text this mount appended is no longer there; the file was edited since",
                    $"{change.Path}: the appended block is gone or changed, so it was left alone");
        }

        if (!apply)
        {
            return ("todo", $"would take out the {block.Split('\n').Length - 1} line(s) this mount appended", null);
        }

        string updated = normalised.Remove(at, block.Length);
        if (change.Where == MountChange.Host)
        {
            try
            {
                File.WriteAllText(change.Path, updated);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return ("FAIL", ex.Message, $"{change.Path}: {ex.Message}");
            }
        }
        else
        {
            var (writeExit, writeOut) = await wsl(
                Root($"printf '%s' \"$SPLAT_FILE\" > {Quote(change.Path)}", ("SPLAT_FILE", updated)), ct);
            if (writeExit != 0)
            {
                return ("FAIL", Short(writeOut), $"{change.Path}: could not be rewritten ({Short(writeOut)})");
            }
        }

        return ("ok", "the appended lines are out; the rest of the file is untouched", null);
    }

    /// <summary>Single-quoted for sh, with an embedded quote closed and reopened the only way sh allows.</summary>
    private static string Quote(string path) => "'" + path.Replace("'", "'\\''") + "'";

    private static string[] Root(string script, params (string Name, string Value)[] environment)
    {
        var args = new List<string> { "-u", "root", "-e", "env" };
        foreach (var (name, value) in environment)
        {
            args.Add($"{name}={value}");
        }

        args.Add("sh");
        args.Add("-c");
        args.Add(script);
        return args.ToArray();
    }

    private static void Line(TextWriter output, string mark, string what, string detail) =>
        output.WriteLine($"  [{mark,-4}] {what,-46} {detail}");

    private static string Short(string text) =>
        text.Length <= 90 ? text.ReplaceLineEndings(" ") : text.ReplaceLineEndings(" ")[..90] + "...";
}
