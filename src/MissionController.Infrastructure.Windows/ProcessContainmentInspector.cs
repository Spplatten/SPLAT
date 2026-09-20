using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Process;

/// <summary>
/// Reads what confines a launched process from the process itself, while it is still suspended: the
/// job the kernel holds it in and the token it will run with. A run record reports this rather than
/// the flags the launcher was called with, because a flag says what was asked for and the token says
/// what the kernel will enforce.
/// </summary>
internal static class ProcessContainmentInspector
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static IReadOnlyList<string> Describe(SafeProcessHandle process, IJobSandbox job)
    {
        var controls = new List<string>();
        try
        {
            bool? inJob = job.ContainsProcess(process);
            if (inJob is not null)
            {
                controls.Add(inJob.Value ? $"job:{job.JobName}" : $"job:{job.JobName}:not-a-member");
            }

            if (!Win32Interop.OpenProcessToken(process.DangerousGetHandle(), Win32Interop.TOKEN_QUERY, out SafeAccessTokenHandle token))
            {
                int error = Marshal.GetLastWin32Error();
                token.Dispose();
                controls.Add($"token:unreadable (Win32 error {error})");
                return controls;
            }

            using (token)
            {
                controls.Add($"token:integrity={IntegrityOf(token)}");
                controls.Add($"token:administrators={AdministratorsIn(token)}");
                controls.Add($"token:privileges={Read(token, Win32Interop.TokenPrivileges, CountAt)}");
                controls.Add($"token:appcontainer={AppContainerOf(token)}");
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Evidence gathering must not turn into a launch failure: the process is already confined
            // or CreateProcess would have failed. What could not be read is reported as such.
            controls.Add($"readback:failed ({ex.GetType().Name})");
        }

        return controls;
    }

    private static string IntegrityOf(SafeAccessTokenHandle token) => Read(token, Win32Interop.TokenIntegrityLevel, buffer =>
    {
        var label = Marshal.PtrToStructure<Win32Interop.TOKEN_MANDATORY_LABEL>(buffer);
        string sid = new SecurityIdentifier(label.Label.Sid).Value;
        return sid switch
        {
            "S-1-16-0" => "Untrusted",
            "S-1-16-4096" => "Low",
            "S-1-16-8192" => "Medium",
            "S-1-16-8448" => "MediumPlus",
            "S-1-16-12288" => "High",
            "S-1-16-16384" => "System",
            _ => sid
        };
    });

    // TOKEN_GROUPS: a DWORD count, then SID_AND_ATTRIBUTES entries aligned to a pointer.
    private static string AdministratorsIn(SafeAccessTokenHandle token) => Read(token, Win32Interop.TokenGroups, buffer =>
    {
        int count = Marshal.ReadInt32(buffer);
        int size = Marshal.SizeOf<Win32Interop.SID_AND_ATTRIBUTES>();
        for (int i = 0; i < count; i++)
        {
            var group = Marshal.PtrToStructure<Win32Interop.SID_AND_ATTRIBUTES>(buffer + IntPtr.Size + i * size);
            if (new SecurityIdentifier(group.Sid) == Administrators)
            {
                return (group.Attributes & Win32Interop.SE_GROUP_USE_FOR_DENY_ONLY) != 0 ? "deny-only"
                    : (group.Attributes & Win32Interop.SE_GROUP_ENABLED) != 0 ? "enabled"
                    : "present-disabled";
            }
        }

        return "absent";
    });

    private static string AppContainerOf(SafeAccessTokenHandle token) => Read(token, Win32Interop.TokenIsAppContainer, buffer =>
        Marshal.ReadInt32(buffer) == 0
            ? "none"
            : $"{Read(token, Win32Interop.TokenCapabilities, CountAt)}-capabilities");

    private static string CountAt(IntPtr buffer) => Marshal.ReadInt32(buffer).ToString(CultureInfo.InvariantCulture);

    // GetTokenInformation reports the size it needs when handed none, then fills a buffer of that size.
    private static string Read(SafeAccessTokenHandle token, int infoClass, Func<IntPtr, string> interpret)
    {
        Win32Interop.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out uint needed);
        if (needed == 0)
        {
            return $"unreadable (Win32 error {Marshal.GetLastWin32Error()})";
        }

        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            return Win32Interop.GetTokenInformation(token, infoClass, buffer, needed, out _)
                ? interpret(buffer)
                : $"unreadable (Win32 error {Marshal.GetLastWin32Error()})";
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
