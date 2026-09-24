using System;
using System.IO;

namespace MissionController.Core;

/// <summary>
/// Finds the copy of the Field Guide that shipped with this build.
///
/// The onboarding wizard used to link the guide as a URL in the source repository. That repository
/// is private, so the one reader the link exists for - someone who has just installed the console
/// and wants the plain-English explanation - got a GitHub 404 behind a sign-in wall. A governed
/// appliance that has to reach a code host to explain itself is also the wrong shape: the console
/// runs on machines with no egress at all.
///
/// Resolution is a search rather than a constant because the guide sits in two places by design:
/// beside the executable in a normal build (packaging\build-client-dist.ps1 also stages a copy one
/// level up, beside App\, which is where a client package's reader is pointed). Both are checked,
/// nearest first. WinUI types are deliberately absent so the search itself is testable.
/// </summary>
public static class ShippedFieldGuide
{
    /// <summary>The file name every copy of the guide carries, in the repository and in a package.</summary>
    public const string FileName = "SPLAT-Field-Guide.html";

    /// <summary>
    /// Returns the full path of the guide that shipped beside <paramref name="baseDirectory"/>, or
    /// null when this build did not ship one. Never throws: a malformed path returns null like any
    /// other miss, because the caller is a button click and not a diagnostic.
    /// </summary>
    public static string? Locate(string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(baseDirectory))
        {
            return null;
        }

        try
        {
            foreach (string relative in new[]
                     {
                         Path.Combine("docs", FileName),         // beside the executable
                         Path.Combine("..", "docs", FileName),   // client package: App\ beside docs\
                     })
            {
                string candidate = Path.GetFullPath(Path.Combine(baseDirectory, relative));
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        catch (Exception)
        {
            // An unreadable or malformed base directory is a miss, not a crash.
        }

        return null;
    }

    /// <summary>The guide shipped with the running application, or null if it did not ship.</summary>
    public static string? Locate() => Locate(AppContext.BaseDirectory);
}
