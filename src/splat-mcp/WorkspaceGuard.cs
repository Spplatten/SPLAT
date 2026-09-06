using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SplatMcp;

/// <summary>
/// Confines <c>fs_read</c> and <c>fs_write</c> to the governed workspace, judged on the object the
/// filesystem actually resolves to rather than on the string the caller sent.
///
/// The check this replaces was <c>Path.GetFullPath</c> plus a prefix comparison. That much defeats
/// <c>..</c> traversal, a sibling directory that is merely a string prefix of the root
/// (<c>…\mcp-workspace-evil</c>) and the several spellings Windows accepts for one file — but it is
/// a statement about a NAME, and a name is not a location. A junction or symlink sitting inside the
/// workspace normalises to a path under the root and then redirects the ordinary file API somewhere
/// else entirely. `C:\…\mcp-workspace\notes` can be a link to `C:\Windows\System32`, and every
/// lexical test in the world will call that in-bounds.
///
/// So containment is decided from a HANDLE: open the object, ask the kernel where that handle
/// actually landed via GetFinalPathNameByHandle, and refuse if the answer is outside the root. The
/// verified handle is then the one the read or write uses, which is what makes it resistant to a
/// swap between the check and the use — a path re-opened after checking is a different question
/// asked twice.
/// </summary>
public sealed class WorkspaceGuard
{
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x0200_0000;   // required to open a directory
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x0020_0000; // open the LINK, not its target
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x0000_0400;
    private const uint GENERIC_READ = 0x8000_0000;
    private const uint GENERIC_WRITE = 0x4000_0000;
    private const uint FILE_SHARE_READ_WRITE_DELETE = 0x0000_0007;
    private const uint OPEN_EXISTING = 3;
    private const uint CREATE_ALWAYS = 2;
    private const uint VOLUME_NAME_DOS = 0x0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    /// <summary>The root's own final path: if the ROOT is itself a link, everything beneath it is judged against where it really points.</summary>
    private readonly string _root;

    public string Root { get; }

    public WorkspaceGuard(string root)
    {
        Root = Path.GetFullPath(root);
        Directory.CreateDirectory(Root);
        _root = FinalPathOfDirectory(Root) ?? Root;
    }

    /// <summary>The path the kernel says a handle actually refers to, with the \\?\ prefix removed.</summary>
    private static string? FinalPathOf(SafeFileHandle handle)
    {
        if (handle.IsInvalid)
        {
            return null;
        }

        var buffer = new StringBuilder(short.MaxValue);
        uint len = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, VOLUME_NAME_DOS);
        if (len == 0 || len > buffer.Capacity)
        {
            return null;
        }

        string p = buffer.ToString();
        // GetFinalPathNameByHandle always answers in \\?\ form. Strip it so the comparison is
        // against paths of the same shape; \\?\UNC\server\share is the network spelling.
        if (p.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
        {
            return @"\\" + p.Substring(8);
        }
        return p.StartsWith(@"\\?\", StringComparison.Ordinal) ? p.Substring(4) : p;
    }

    private static string? FinalPathOfDirectory(string path)
    {
        using var handle = CreateFile(
            path, GENERIC_READ, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        return handle.IsInvalid ? null : FinalPathOf(handle);
    }

    private bool IsInside(string? finalPath)
    {
        if (string.IsNullOrEmpty(finalPath))
        {
            return false;
        }

        string rootWithSeparator = _root.EndsWith(Path.DirectorySeparatorChar)
            ? _root
            : _root + Path.DirectorySeparatorChar;

        // The root itself is in bounds; anything else must sit strictly beneath it. The trailing
        // separator is what makes this containment rather than a prefix match.
        return string.Equals(finalPath.TrimEnd(Path.DirectorySeparatorChar), _root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
            || finalPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The cheap first pass: canonicalise and reject anything that is not lexically inside. It
    /// cannot be the only check, but it turns the common case into a refusal without touching disk.
    /// </summary>
    private string? LexicallyInside(string requestedPath)
    {
        try
        {
            string candidate = Path.GetFullPath(Path.IsPathRooted(requestedPath)
                ? requestedPath
                : Path.Combine(Root, requestedPath));

            string rootWithSeparator = Root.EndsWith(Path.DirectorySeparatorChar)
                ? Root
                : Root + Path.DirectorySeparatorChar;

            return candidate.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase)
                ? candidate
                : null;
        }
        catch (Exception)
        {
            // Malformed input - invalid characters, over-long, a device name - is out of bounds by
            // definition. There is no path here to authorise.
            return null;
        }
    }

    /// <summary>
    /// Opens a file for reading, or returns null if it is not really inside the workspace.
    ///
    /// The returned handle IS the verified object. Callers must read from it rather than re-opening
    /// by path, because the second open is a different question.
    /// </summary>
    public SafeFileHandle? OpenForRead(string requestedPath, out string? finalPath)
    {
        finalPath = null;
        if (LexicallyInside(requestedPath) is not { } candidate)
        {
            return null;
        }

        var handle = CreateFile(
            candidate, GENERIC_READ, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        finalPath = FinalPathOf(handle);
        if (!IsInside(finalPath))
        {
            // Lexically in bounds, actually somewhere else: a link redirected the open.
            handle.Dispose();
            finalPath = null;
            return null;
        }

        return handle;
    }

    /// <summary>
    /// Opens a file for writing, creating it if absent, or returns null if it escapes.
    ///
    /// Three separate ways out of the workspace, so three checks:
    ///   1. the PARENT directory must really be inside — catches `workspace\link-to-elsewhere\x.txt`,
    ///      where the leaf is innocent and the directory is not;
    ///   2. an existing leaf must not itself be a reparse point — opening one with CREATE_ALWAYS
    ///      follows it and truncates the target, so this is checked before anything is opened for
    ///      writing rather than after;
    ///   3. the handle that results must still land inside.
    /// </summary>
    public SafeFileHandle? OpenForWrite(string requestedPath, out string? finalPath)
    {
        finalPath = null;
        if (LexicallyInside(requestedPath) is not { } candidate)
        {
            return null;
        }

        string? parent = Path.GetDirectoryName(candidate);
        if (string.IsNullOrEmpty(parent))
        {
            return null;
        }

        try
        {
            // Only ever create directories that are lexically inside; the handle check below is
            // what confirms where they actually landed.
            Directory.CreateDirectory(parent);
        }
        catch (Exception)
        {
            return null;
        }

        if (!IsInside(FinalPathOfDirectory(parent)))
        {
            return null;
        }

        if (File.Exists(candidate) && IsReparsePoint(candidate))
        {
            // A link at the LEAF is refused for a mechanical reason, not a policy one: CREATE_ALWAYS
            // follows the link and truncates its target, so by the time the handle exists and its
            // final path can be checked, an out-of-bounds file has already been emptied. There is no
            // check-then-truncate order that is safe here, so the link itself is refused.
            //
            // A link in a PARENT directory is different and is allowed when it resolves inside: the
            // parent is verified before anything is opened, and nothing is destroyed by looking.
            return null;
        }

        var handle = CreateFile(
            candidate, GENERIC_WRITE, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            CREATE_ALWAYS, 0, IntPtr.Zero);

        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        finalPath = FinalPathOf(handle);
        if (!IsInside(finalPath))
        {
            handle.Dispose();
            finalPath = null;
            return null;
        }

        return handle;
    }

    /// <summary>Whether the leaf is a link, asked of the link itself rather than of its target.</summary>
    private static bool IsReparsePoint(string path)
    {
        using var handle = CreateFile(
            path, GENERIC_READ, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);

        if (handle.IsInvalid)
        {
            // Cannot inspect it, so cannot clear it.
            return true;
        }

        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
