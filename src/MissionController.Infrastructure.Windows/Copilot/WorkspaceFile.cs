using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace MissionController.Infrastructure.Windows.Copilot;

// Resolve each child relative to a held directory handle. Rechecking a path and then
// reopening it by name would let a junction swap redirect a read, creation or truncation.
internal static partial class WorkspaceFile
{
    internal static FileStream Open(string workspace, string path, bool write)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(workspace));
        string relative = Path.GetRelativePath(root, Path.GetFullPath(path));
        string[] parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Path.IsPathFullyQualified(root) || root.StartsWith(@"\\", StringComparison.Ordinal) ||
            Path.IsPathRooted(relative) || parts.Any(p => string.IsNullOrWhiteSpace(p) || p is "." or ".." ||
                p.EndsWith('.') || p.EndsWith(' ') || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new UnauthorizedAccessException("[SPLAT POLICY] Invalid workspace file path.");

        var directories = new List<SafeFileHandle>();
        SafeFileHandle? file = null;
        try
        {
            var directory = CreateFile(root, 0x00100080, 1, IntPtr.Zero, 3,
                0x02200000, IntPtr.Zero); // SYNCHRONIZE | READ_ATTRIBUTES, share read; no-follow directory
            directories.Add(directory);
            if (directory.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            Validate(directory, directoryExpected: true);

            var finalRoot = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(directory, finalRoot, (uint)finalRoot.Capacity, 0);
            if (length == 0 || length >= finalRoot.Capacity ||
                !string.Equals(Path.TrimEndingDirectorySeparator(finalRoot.ToString()), @"\\?\" + root,
                    StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("[SPLAT POLICY] Workspace aliases and reparse points are refused.");

            for (int i = 0; i < parts.Length - 1; i++)
            {
                directory = OpenChild(directory, parts[i], directory: true, create: write, write: false);
                directories.Add(directory);
                Validate(directory, directoryExpected: true);
            }

            file = OpenChild(directory, parts[^1], directory: false, create: write, write: write);
            Validate(file, directoryExpected: false);
            var stream = new FileStream(file, write ? FileAccess.Write : FileAccess.Read);
            file = null; // The stream owns the validated object; no path is reopened after validation.
            return stream;
        }
        finally
        {
            file?.Dispose();
            for (int i = directories.Count - 1; i >= 0; i--) directories[i].Dispose();
        }
    }

    private static void Validate(SafeFileHandle handle, bool directoryExpected)
    {
        if (!GetFileInformationByHandle(handle, out var info))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directoryExpected ||
            (!directoryExpected && info.Links != 1))
            throw new UnauthorizedAccessException("[SPLAT POLICY] Reparse points, hard-linked files and unexpected file types are refused.");
    }

    private static unsafe SafeFileHandle OpenChild(SafeFileHandle parent, string name, bool directory, bool create, bool write)
    {
        fixed (char* buffer = name)
        {
            var unicode = new UnicodeString
            {
                Length = checked((ushort)(name.Length * 2)),
                MaximumLength = checked((ushort)(name.Length * 2)),
                Buffer = (IntPtr)buffer
            };
            var attributes = new ObjectAttributes
            {
                Length = (uint)sizeof(ObjectAttributes),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = (IntPtr)(&unicode),
                Attributes = 0x40 // OBJ_CASE_INSENSITIVE; name is exactly one validated component.
            };
            // OPEN_IF never truncates existing data. Validate the opened object before any write.
            int status = NtCreateFile(out var child, directory ? 0x00100080u : write ? 0x40100080u : 0x80100080u,
                ref attributes, out _, IntPtr.Zero, 0, 1, create ? 3u : 1u,
                0x00200020u | (directory ? 1u : 0x40u), IntPtr.Zero, 0);
            GC.KeepAlive(parent);
            if (status < 0)
            {
                child?.Dispose();
                throw new Win32Exception((int)RtlNtStatusToDosError(status));
            }
            return child;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public IntPtr Status, Information; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    [LibraryImport("ntdll.dll")]
    private static partial int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
        out IoStatusBlock status, IntPtr allocation, uint fileAttributes, uint share, uint disposition,
        uint options, IntPtr eaBuffer, uint eaLength);
    [LibraryImport("ntdll.dll")]
    private static partial uint RtlNtStatusToDosError(int status);
}
