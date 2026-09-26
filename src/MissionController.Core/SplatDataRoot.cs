using System;
using System.Collections.Generic;
using System.IO;

namespace MissionController.Core;

/// <summary>How the data root was chosen. Printed by <c>doctor</c>, so an operator can see it.</summary>
public enum SplatDataRootKind
{
    /// <summary>Under the user's local application data. What an installed copy does.</summary>
    Host,

    /// <summary>Beside the executable, because a portable marker said so. What the drive does.</summary>
    Portable,

    /// <summary>Wherever <c>SPLAT_DATA_DIR</c> named. What a launcher or a test does.</summary>
    Environment,
}

/// <summary>Where the data is, and the one-line answer to "why there".</summary>
public sealed record SplatDataLocation(string Root, SplatDataRootKind Kind, string Reason)
{
    public override string ToString() => $"{Root} ({Kind.ToString().ToLowerInvariant()}: {Reason})";
}

/// <summary>
/// Every file SPLAT owns on the host, named once, under one root.
///
/// Before this existed the two hosts computed their own paths: eleven expressions of
/// <c>SpecialFolder.LocalApplicationData</c> across Core, Data, Windows, the console and
/// <c>splat-mcp</c>, splitting the product's own data over two sibling roots with two different brand
/// names - <c>SPLAT\</c> for the ledger and the workspace, <c>MissionController\</c> for the database,
/// the vault and the jails - and computing the jail root twice, in the manager that makes jails and
/// again in the view model that lists them. Two copies of one path is a bug with a delay on it.
///
/// It also makes the data movable, which is what roadmap 4.1 is for: a kit that mounts onto a machine
/// keeps its ledger, workspace and evidence on the drive, so the drive is the record of every machine
/// it was mounted on. Nothing here is a preference - the layout under the root is fixed - so moving
/// the data is a matter of naming a root, and every path follows.
/// </summary>
public static class SplatDataRoot
{
    /// <summary>Names the root outright. Absolute only; see <see cref="Resolve"/>.</summary>
    public const string EnvironmentVariable = "SPLAT_DATA_DIR";

    /// <summary>
    /// The file that says "this copy keeps its data beside itself". A marker rather than an inferred
    /// layout: a stray folder named <c>data</c> must never be able to flip a host copy into portable
    /// mode, and a person who copies the kit off the drive onto their desktop must get the same
    /// behaviour as the drive, not a different one.
    /// </summary>
    public const string PortableMarkerFileName = "splat.portable";

    /// <summary>The directory the portable marker means when it names none.</summary>
    public const string PortableDefaultDirectoryName = "data";

    private static readonly Lazy<SplatDataLocation> Resolved = new(() =>
        Resolve(AppContext.BaseDirectory, Environment.GetEnvironmentVariable(EnvironmentVariable)));

    /// <summary>Where this process keeps its data. Resolved once: a root that moved mid-run would
    /// leave half a mission in one place and half in another.</summary>
    public static SplatDataLocation Current => Resolved.Value;

    /// <summary>The paths under <see cref="Current"/>.</summary>
    public static SplatDataLayout Layout { get; } = new(Current.Root);

    /// <summary>
    /// Chooses the root from the two things that can say where it goes, in order: the environment
    /// variable, then a portable marker beside the executable or one directory above it (the kit puts
    /// <c>splat-mcp.exe</c> in <c>splat\</c> and the console in <c>splat\app\</c>, so both find the
    /// same marker). Otherwise the host's local application data.
    ///
    /// A relative <c>SPLAT_DATA_DIR</c> throws rather than being resolved against the working
    /// directory. The console is started from its own folder and an MCP host starts
    /// <c>splat-mcp</c> from wherever it pleases, so one relative value means two different roots -
    /// which is the exact failure this type exists to end, arriving through its own front door.
    /// </summary>
    public static SplatDataLocation Resolve(string executableDirectory, string? configuredRoot)
    {
        if (!string.IsNullOrWhiteSpace(configuredRoot))
        {
            if (!Path.IsPathRooted(configuredRoot))
            {
                throw new InvalidOperationException(
                    $"{EnvironmentVariable} is '{configuredRoot}', which is relative. It must be an absolute " +
                    "path: the console and splat-mcp run with different working directories, so a relative " +
                    "value names a different folder in each and the two would keep separate ledgers.");
            }

            return new SplatDataLocation(
                Path.GetFullPath(configuredRoot),
                SplatDataRootKind.Environment,
                $"{EnvironmentVariable} names it");
        }

        string? marker = FindPortableMarker(executableDirectory);
        if (marker is not null)
        {
            string markerDirectory = Path.GetDirectoryName(marker) ?? executableDirectory;
            return new SplatDataLocation(
                Path.GetFullPath(Path.Combine(markerDirectory, ReadPortableDirectoryName(marker))),
                SplatDataRootKind.Portable,
                $"{PortableMarkerFileName} beside {markerDirectory}");
        }

        string localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(localApplicationData))
        {
            // An account with no profile directory - a service account, or a stripped container. Falling
            // back to a relative "SPLAT" would put the ledger wherever the process happened to start.
            return new SplatDataLocation(
                Path.GetFullPath(Path.Combine(executableDirectory, PortableDefaultDirectoryName)),
                SplatDataRootKind.Portable,
                "this account has no local application data, so the data goes beside the executable");
        }

        return new SplatDataLocation(
            Path.Combine(localApplicationData, "SPLAT"),
            SplatDataRootKind.Host,
            "installed copy, no marker and no environment variable");
    }

    /// <summary>
    /// Moves an older installation's data under the new root, once, and only for an installed copy.
    ///
    /// Until 2026-09-25 the database, the vault and the jails lived under
    /// <c>%LOCALAPPDATA%\MissionController</c> while the ledger and the MCP workspace lived under
    /// <c>%LOCALAPPDATA%\SPLAT</c>. Unifying the root without moving those would hand an existing
    /// operator an empty history and a vault with no key in it, and they would have to be told why.
    /// Silence is the failure mode here, so this returns what it moved and the hosts print it.
    ///
    /// Jails are deliberately not moved: they are scratch directories for missions that have already
    /// ended, and the new root simply starts making them in the new place.
    ///
    /// Portable copies adopt nothing. A drive that silently swallowed the host's ledger the first time
    /// it was plugged in would be a data-exfiltration tool with a friendly icon.
    /// </summary>
    public static IReadOnlyList<string> AdoptLegacyHostLayout(SplatDataLocation location, string? legacyRoot = null)
    {
        ArgumentNullException.ThrowIfNull(location);

        var moved = new List<string>();
        if (location.Kind != SplatDataRootKind.Host)
        {
            return moved;
        }

        legacyRoot ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MissionController");

        foreach (string directory in new[] { "Data", "Vault" })
        {
            string source = Path.Combine(legacyRoot, directory);
            string destination = Path.Combine(location.Root, directory);

            // An existing destination wins. The operator may have already run a newer build, and a
            // half-adopted state must never overwrite the live chain with the abandoned one.
            if (!Directory.Exists(source) || Directory.Exists(destination))
            {
                continue;
            }

            try
            {
                Directory.CreateDirectory(location.Root);
                Directory.Move(source, destination);
                moved.Add($"{source} -> {destination}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Adoption is a convenience, not a precondition. A locked file means the operator keeps
                // their old data where it is and starts a new chain, which they should be told about
                // rather than have the process die at startup over.
                moved.Add($"{source} could not be moved ({ex.Message}); it is still there");
            }
        }

        return moved;
    }

    private static string? FindPortableMarker(string executableDirectory)
    {
        string? directory = executableDirectory;

        // Two levels, never a walk to the volume root: an unbounded search would let a marker left in
        // C:\ decide where every copy on the machine keeps its data.
        for (int depth = 0; depth < 2 && !string.IsNullOrEmpty(directory); depth++)
        {
            string candidate = Path.Combine(directory, PortableMarkerFileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar));
        }

        return null;
    }

    private static string ReadPortableDirectoryName(string markerPath)
    {
        try
        {
            foreach (string line in File.ReadAllLines(markerPath))
            {
                string trimmed = line.Trim();
                if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
                {
                    return trimmed;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The marker exists, so this copy is portable; only its one optional line is unreadable.
        }

        return PortableDefaultDirectoryName;
    }
}

/// <summary>
/// The fixed layout under a root. Constructed against an arbitrary root so the suite can prove the
/// shape without touching the machine's real one.
///
/// The two databases are not a mistake being preserved: the console's <c>missioncontroller.db</c> and
/// <c>splat-mcp</c>'s <c>audit_ledger.db</c> are two real chains with different histories, and merging
/// them is a migration with its own decision to make, not a rename. Putting them under one root at
/// least makes the split visible in one folder instead of two roots apart.
/// </summary>
public sealed class SplatDataLayout
{
    public SplatDataLayout(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);

        Root = root;
        Database = Path.Combine(root, "Data", "missioncontroller.db");
        LedgerDatabase = Path.Combine(root, "audit_ledger.db");
        Vault = Path.Combine(root, "Vault");
        Jails = Path.Combine(root, "Jails");
        CrashLog = Path.Combine(root, "crash.log");
        SelfTestReport = Path.Combine(root, "self-test.json");
        McpWorkspace = Path.Combine(root, "mcp-workspace");
        CopilotWorkspace = Path.Combine(root, "copilot-workspace");
        ComplianceExports = Path.Combine(root, "ComplianceExports");
        MissionRunRecords = Path.Combine(root, "MissionRunRecords");
        MountManifest = Path.Combine(root, "mount-manifest.json");
    }

    public string Root { get; }

    /// <summary>The console's database: missions, findings, memory and its ledger.</summary>
    public string Database { get; }

    /// <summary>The ledger <c>splat-mcp</c> writes when no <c>SPLAT_DB_PATH</c> points it elsewhere.</summary>
    public string LedgerDatabase { get; }

    public string Vault { get; }

    public string Jails { get; }

    public string CrashLog { get; }

    public string SelfTestReport { get; }

    public string McpWorkspace { get; }

    public string CopilotWorkspace { get; }

    public string ComplianceExports { get; }

    public string MissionRunRecords { get; }

    /// <summary>
    /// Every change a mount made to this host, written by `splat-mcp provision --apply` and played
    /// backwards by `splat-mcp unmount`. It lives under the data root rather than in the guest
    /// because the guest is most of what unmounting takes apart - and in portable mode that root is
    /// the drive, which is where the design wants it: the drive becomes the record of every machine
    /// it was mounted on.
    /// </summary>
    public string MountManifest { get; }
}
