using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SplatMcp;

/// <summary>
/// One change a mount made to a host, and what was there before it.
///
/// <see cref="PreviousSha256"/> is the honest half. A mount that replaced something cannot always put
/// it back - nothing keeps a copy of a binary it overwrote - so the manifest records what was there
/// and unmount says it could not restore it, rather than removing the replacement and leaving the
/// operator to discover the hole themselves.
/// </summary>
/// <param name="Kind">One of <see cref="File"/>, <see cref="Lines"/>, <see cref="Unit"/>, <see cref="Directory"/>.</param>
/// <param name="Where">"guest" for inside WSL, "host" for Windows.</param>
public sealed record MountChange(
    string Kind,
    string Where,
    string Path,
    string? Appended = null,
    string? PreviousSha256 = null,
    string? Note = null)
{
    /// <summary>A file the mount wrote. Unmount removes it.</summary>
    public const string File = "file";

    /// <summary>Text the mount appended to a file that already existed. Unmount takes out exactly that text.</summary>
    public const string Lines = "lines";

    /// <summary>A systemd unit. Unmount stops it, disables it, removes it and reloads the daemon.</summary>
    public const string Unit = "unit";

    /// <summary>A directory the mount created. Unmount removes it only if it is empty.</summary>
    public const string Directory = "directory";

    public const string Guest = "guest";
    public const string Host = "host";

    /// <summary>Was something already there that this change wrote over?</summary>
    [JsonIgnore]
    public bool Replaced => PreviousSha256 is { Length: > 0 };
}

/// <summary>
/// Everything a mount changed, in the order it changed it, written where it survives the guest.
///
/// A mount is honest only if it can be undone, and "undone" cannot mean "remove the things this
/// version of the code happens to know about" - that is a second list of changes, maintained by
/// hand, that drifts from the first one. Unmount plays this file backwards instead, so a step added
/// to provisioning is removed by an unmount written before it existed.
///
/// It lives in the data root rather than in the guest, because the guest is most of what unmounting
/// takes apart. In portable mode that root is the drive, which is where the design puts it: the
/// drive becomes the record of every machine it was mounted on.
/// </summary>
public sealed record MountManifest(
    int Version,
    DateTime MountedUtc,
    string Host,
    string Distro,
    IReadOnlyList<MountChange> Changes)
{
    public const int CurrentVersion = 1;

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static MountManifest Create(string distro, IReadOnlyList<MountChange> changes) =>
        new(CurrentVersion, DateTime.UtcNow, Environment.MachineName, distro, changes);

    public void Write(string path)
    {
        string? directory = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            System.IO.Directory.CreateDirectory(directory);
        }

        System.IO.File.WriteAllText(path, JsonSerializer.Serialize(this, Options));
    }

    /// <summary>
    /// Reads a manifest, or says why it cannot. Never returns a half-read one: an unmount driven by a
    /// manifest it only partly understood would remove some of what a mount added and leave the rest,
    /// which is worse than refusing, because the operator would believe the host was restored.
    /// </summary>
    public static MountManifest Read(string path)
    {
        MountManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<MountManifest>(System.IO.File.ReadAllText(path), Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"{path} is not a mount manifest this build can read: {ex.Message}");
        }

        if (manifest is null)
        {
            throw new InvalidOperationException($"{path} is empty.");
        }

        if (manifest.Version != CurrentVersion)
        {
            throw new InvalidOperationException(
                $"{path} is a version {manifest.Version} manifest and this build writes version {CurrentVersion}. " +
                "Unmount with the build that mounted, or take the steps out by hand from the list it names.");
        }

        if (manifest.Changes is null)
        {
            throw new InvalidOperationException($"{path} records no changes, so there is nothing it can undo.");
        }

        return manifest;
    }
}
