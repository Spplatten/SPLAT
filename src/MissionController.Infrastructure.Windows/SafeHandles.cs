using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace MissionController.Infrastructure.Windows.Native;

/// <summary>
/// A kernel job-object handle.
/// </summary>
/// <remarks>
/// This one is not a tidiness exercise. The containment job is armed with
/// <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c>, which means the last handle closing is what kills
/// everything still running inside it. A raw <see cref="IntPtr"/> field released only from
/// <c>Dispose</c> has no finalizer behind it, so a sandbox that is dropped without being disposed -
/// an exception on a path that skipped its <c>using</c>, a caller that simply forgot - leaks the
/// handle for the life of the process and the kill never fires. The contained tools keep running.
/// SafeHandle supplies the finalizer, so the worst case degrades from "containment silently did not
/// happen" to "containment happened a garbage collection later than it should have".
/// </remarks>
internal sealed class SafeJobObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>
    /// Public and parameterless because the source-generated marshaller constructs it: returning a
    /// SafeHandle from a <c>[LibraryImport]</c> requires a <c>new()</c>-able type, and a private
    /// constructor fails the build with SYSLIB1051 rather than falling back to anything.
    /// </summary>
    public SafeJobObjectHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle() => Win32Interop.CloseHandle(handle);
}

/// <summary>
/// A thread handle, as returned in <c>PROCESS_INFORMATION.hThread</c>.
/// </summary>
/// <remarks>
/// The BCL exposes <see cref="SafeProcessHandle"/> publicly but keeps its thread equivalent
/// internal, so this fills the gap. Marshalled in rather than returned: the handle arrives inside a
/// blittable struct, which cannot itself carry a SafeHandle field, so the launcher adopts both
/// handles immediately after <c>CreateProcess</c> returns.
/// </remarks>
internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeThreadHandle(IntPtr existingHandle) : base(ownsHandle: true) => SetHandle(existingHandle);

    protected override bool ReleaseHandle() => Win32Interop.CloseHandle(handle);
}
