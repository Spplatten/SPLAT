using System;
using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Security;

/// <summary>
/// Lets SPLAT's AppContainer open the window station and desktop its parent is on.
///
/// This is the whole of the headless failure recorded on 2026-09-18: over a non-interactive logon a
/// PowerShell sensor launched into the container died at 0xC0000142 before running a line, while
/// cmd.exe started fine, and the same tests passed in a desktop session. user32 joins the process to
/// a window station and a desktop during DLL_PROCESS_ATTACH; a process that may not open them fails
/// that initialisation, which is STATUS_DLL_INIT_FAILED. PowerShell loads user32 at startup and
/// cmd.exe does not, which is why one died and the other did not.
///
/// An interactive WinSta0 and its Default desktop carry ACEs for ALL APPLICATION PACKAGES, put there
/// by Windows - so on a desktop session an AppContainer child gets in for reasons that have nothing
/// to do with SPLAT. A station created by LSA for a service, batch or SSH logon carries no such ACE,
/// and SPLAT never added one. The interactive case worked by inheritance from someone else's
/// decision, so nothing in the product noticed.
///
/// Reproduced under one variable on 2026-09-29: a desktop created with a DACL naming only the
/// current user, with the same container and the same two programs. Before the ACE, PowerShell
/// 0xC0000142 and cmd.exe exit 7; after it, both exit 7.
///
/// <para>
/// What this deliberately does NOT do is widen anything already open. It looks first, grants only
/// where the container has no access, and grants only to SPLAT's own container SID - never to ALL
/// APPLICATION PACKAGES, which would let every AppContainer on the machine onto the station. On an
/// interactive session it therefore does nothing at all. A window station's ACL lives only as long
/// as its logon session, so nothing written here outlives the logon that needed it.
/// </para>
/// </summary>
public static class WindowStationAccess
{
    /// <summary>
    /// The masks Windows itself grants ALL APPLICATION PACKAGES on an interactive WinSta0 and its
    /// Default desktop, read off a live machine rather than composed from the header. Copying what
    /// the platform grants is the point: a hand-picked subset that happens to work on one build is a
    /// guess about which of user32's startup calls matter.
    /// </summary>
    private const int WindowStationMask = 0x00020327;

    private const int DesktopMask = 0x000F00FF;

    /// <summary>
    /// The inheritable half of what Windows puts on WinSta0, so a desktop created under the station
    /// later inherits the grant rather than needing its own pass.
    /// </summary>
    private const int InheritableMask = unchecked((int)(0x80000000 | 0x20000000)); // GENERIC_READ | GENERIC_EXECUTE

    /// <summary>ALL APPLICATION PACKAGES. Its presence already covers every AppContainer, SPLAT's included.</summary>
    private static readonly SecurityIdentifier AllApplicationPackages = new("S-1-15-2-1");

    /// <summary>
    /// What the launcher should record about this call. <paramref name="Granted"/> is false both when
    /// nothing was needed and when nothing could be done, which is why the description is the part
    /// worth writing down.
    /// </summary>
    public readonly record struct Outcome(bool ContainerCanAttach, bool Granted, string Description);

    /// <summary>
    /// Ensures a child in <paramref name="containerSid"/> can open this process's window station and
    /// desktop, granting access only where it is missing.
    ///
    /// Never throws. A host that cannot rewrite its own station's ACL is a real situation - the
    /// station may belong to another logon session - and the caller's job is then to launch anyway
    /// and report the truth if the child dies in DLL initialisation, not to refuse a mission over a
    /// pre-flight check that might have been unnecessary.
    /// </summary>
    public static Outcome EnsureAppContainerMayAttach(SecurityIdentifier containerSid)
    {
        ArgumentNullException.ThrowIfNull(containerSid);

        if (!OperatingSystem.IsWindows())
        {
            return new Outcome(false, false, "winsta: not Windows");
        }

        IntPtr station = Win32Interop.GetProcessWindowStation();
        IntPtr desktop = Win32Interop.GetThreadDesktop(Win32Interop.GetCurrentThreadId());
        if (station == IntPtr.Zero || desktop == IntPtr.Zero)
        {
            return new Outcome(false, false, "winsta: this process is attached to no window station or desktop");
        }

        var stationResult = EnsureOn(station, containerSid, WindowStationMask, InheritableMask, "window station");
        var desktopResult = EnsureOn(desktop, containerSid, DesktopMask, inheritableMask: null, "desktop");

        string name = NameOf(station) + "\\" + NameOf(desktop);
        bool canAttach = stationResult.CanAttach && desktopResult.CanAttach;
        bool granted = stationResult.Granted || desktopResult.Granted;

        string description = (canAttach, granted) switch
        {
            (true, false) => $"winsta:{name} (the container could already attach)",
            (true, true) => $"winsta:{name} (granted to the container by SPLAT)",
            (false, _) => $"winsta:{name} NOT ACCESSIBLE to the container - {stationResult.Detail}; {desktopResult.Detail}",
        };

        return new Outcome(canAttach, granted, description);
    }

    private static (bool CanAttach, bool Granted, string Detail) EnsureOn(
        IntPtr handle,
        SecurityIdentifier containerSid,
        int mask,
        int? inheritableMask,
        string what)
    {
        RawSecurityDescriptor? descriptor;
        try
        {
            descriptor = ReadDacl(handle);
        }
        catch (Exception ex) when (ex is Win32Exception or ArgumentException)
        {
            return (false, false, $"{what}: its DACL could not be read ({ex.Message})");
        }

        if (descriptor?.DiscretionaryAcl is not { } dacl)
        {
            // No DACL at all means no access check, so everyone gets in. Unusual, and not something
            // to "fix" by adding an ACE - that would REMOVE the access it currently has.
            return (true, false, $"{what}: has no DACL, so nothing restricts it");
        }

        if (AlreadyAllows(dacl, containerSid, mask) || AlreadyAllows(dacl, AllApplicationPackages, mask))
        {
            return (true, false, $"{what}: already open to the container");
        }

        try
        {
            dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, mask, containerSid, false, null));
            if (inheritableMask is { } inheritable)
            {
                dacl.InsertAce(0, new CommonAce(
                    AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly,
                    AceQualifier.AccessAllowed, inheritable, containerSid, false, null));
            }

            descriptor.DiscretionaryAcl = dacl;
            WriteDacl(handle, descriptor);
            return (true, true, $"{what}: granted to the container");
        }
        catch (Exception ex) when (ex is Win32Exception or ArgumentException or InvalidOperationException)
        {
            // WRITE_DAC on a station this process does not own is the expected way to land here.
            return (false, false, $"{what}: could not be granted to the container ({ex.Message})");
        }
    }

    private static bool AlreadyAllows(RawAcl dacl, SecurityIdentifier sid, int requiredMask)
    {
        foreach (var ace in dacl)
        {
            // An InheritOnly ACE grants nothing on the object carrying it, so it is not access.
            if (ace is CommonAce common
                && common.AceType == AceType.AccessAllowed
                && common.SecurityIdentifier == sid
                && (common.AceFlags & AceFlags.InheritOnly) == 0
                && (common.AccessMask & requiredMask) == requiredMask)
            {
                return true;
            }
        }

        return false;
    }

    private static RawSecurityDescriptor? ReadDacl(IntPtr handle)
    {
        int information = Win32Interop.DACL_SECURITY_INFORMATION;
        Win32Interop.GetUserObjectSecurity(handle, ref information, null, 0, out uint needed);
        if (needed == 0)
        {
            return null;
        }

        var buffer = new byte[needed];
        if (!Win32Interop.GetUserObjectSecurity(handle, ref information, buffer, needed, out _))
        {
            throw new Win32Exception();
        }

        return new RawSecurityDescriptor(buffer, 0);
    }

    private static void WriteDacl(IntPtr handle, RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        int information = Win32Interop.DACL_SECURITY_INFORMATION;
        if (!Win32Interop.SetUserObjectSecurity(handle, ref information, bytes))
        {
            throw new Win32Exception();
        }
    }

    private static string NameOf(IntPtr handle)
    {
        var buffer = new byte[512];
        if (!Win32Interop.GetUserObjectInformation(handle, Win32Interop.UOI_NAME, buffer, (uint)buffer.Length, out uint written)
            || written < sizeof(char))
        {
            return "<unnamed>";
        }

        // written counts the trailing NUL that GetUserObjectInformationW includes.
        return System.Text.Encoding.Unicode.GetString(buffer, 0, (int)written - sizeof(char));
    }
}
