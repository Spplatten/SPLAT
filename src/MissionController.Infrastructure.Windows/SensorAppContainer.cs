using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Security;

/// <summary>
/// SPLAT's single AppContainer identity, and the reason a sensor tool can be told "no network" as a
/// fact rather than as a promise.
///
/// A Win32 job object clamps CPU, memory, PIDs and (with the restricted token) privilege, but it has
/// no concept of a socket - so before this existed, a template that declared it only reads the local
/// machine was free to open any connection it liked, and the Field Guide's "one phone line" claim
/// held only for SPLAT's own model call. An AppContainer closes exactly that gap: a process launched
/// into one reaches the network ONLY through capability SIDs granted at creation, so granting the
/// empty set removes the network stack instead of filtering it. Measured on Windows 11 26200: a
/// tool inside this container fails DNS resolution AND fails a raw-IP TCP connect, while the same
/// command outside it succeeds.
///
/// What this deliberately does NOT do is choose a destination. An AppContainer is binary - network
/// or no network - so a template whose sensor genuinely needs one host (<see cref="MissionController
/// .Core.Enums.EgressScope.ToolProcess"/>) is launched WITHOUT this containment and its declared FQDN
/// stays a governance claim on Windows until a broker or WFP filter lands. Being explicit about that
/// boundary is the point: the containment is real for the ~40 templates that need nothing, and
/// absent for the one that does, and nothing in the product should say otherwise.
///
/// The profile is created once per machine and reused. Creation is not privileged, survives reboots,
/// and returns ERROR_ALREADY_EXISTS on every later run - which is a success, not a fault.
/// </summary>
public static class SensorAppContainer
{
    /// <summary>
    /// Stable, SPLAT-specific container name. It also appears in the jail directory's ACL, so
    /// renaming it strands the ACE granted to the previous name.
    /// </summary>
    public const string ProfileName = "SPLAT.Sensor.Contained";

    private const int S_OK = 0;
    private const int HRESULT_ERROR_ALREADY_EXISTS = unchecked((int)0x800700B7);

    private static readonly object Gate = new();
    private static SecurityIdentifier? _sid;
    private static string? _failureReason;
    private static bool _attempted;

    /// <summary>
    /// Resolves the container SID, creating the profile on first use. Cached for the process
    /// lifetime because the answer cannot change while SPLAT is running.
    /// </summary>
    /// <returns>False when this machine cannot provide an AppContainer; callers must then REFUSE to
    /// launch rather than fall back to an unconfined process.</returns>
    public static bool TryGetSid(out SecurityIdentifier? sid, out string? failureReason)
    {
        lock (Gate)
        {
            if (!_attempted)
            {
                _attempted = true;
                Resolve();
            }

            sid = _sid;
            failureReason = _failureReason;
            return _sid is not null;
        }
    }

    private static void Resolve()
    {
        IntPtr rawSid = IntPtr.Zero;
        try
        {
            int hr = Win32Interop.CreateAppContainerProfile(
                ProfileName,
                "SPLAT Contained Sensor",
                "Network-denied container for SPLAT governed sensor tools.",
                IntPtr.Zero,
                0,
                out rawSid);

            // Second and every subsequent run on this machine: the profile is already registered,
            // which is the normal steady state rather than an error path.
            if (hr == HRESULT_ERROR_ALREADY_EXISTS)
            {
                hr = Win32Interop.DeriveAppContainerSidFromAppContainerName(ProfileName, out rawSid);
            }

            if (hr != S_OK)
            {
                _failureReason = $"AppContainer profile '{ProfileName}' could not be resolved (HRESULT 0x{hr:X8}).";
                return;
            }

            // Copies the SID into managed memory, so the native buffer can be released immediately
            // and no unmanaged SID is held for the life of the process.
            _sid = new SecurityIdentifier(rawSid);
        }
        catch (Exception ex)
        {
            _failureReason = $"AppContainer profile '{ProfileName}' could not be resolved: {ex.Message}";
        }
        finally
        {
            if (rawSid != IntPtr.Zero)
            {
                Win32Interop.FreeSid(rawSid);
            }
        }
    }

    /// <summary>
    /// Copies a managed SID into unmanaged memory for SECURITY_CAPABILITIES. The caller owns the
    /// result and must <see cref="Marshal.FreeHGlobal"/> it once CreateProcess has returned.
    /// </summary>
    public static IntPtr AllocateNativeSid(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }
}
