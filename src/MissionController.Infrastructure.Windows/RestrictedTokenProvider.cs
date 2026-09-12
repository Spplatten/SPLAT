using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Security;

public sealed class RestrictedTokenProvider : IRestrictedTokenProvider
{
    public IntPtr CreateLowPrivilegeToken()
    {
        using var self = global::System.Diagnostics.Process.GetCurrentProcess();
        IntPtr currentProcess = self.Handle;
        if (!Win32Interop.OpenProcessToken(
            currentProcess,
            Win32Interop.TOKEN_DUPLICATE | Win32Interop.TOKEN_ASSIGN_PRIMARY | Win32Interop.TOKEN_QUERY | Win32Interop.TOKEN_ADJUST_DEFAULT,
            out IntPtr currentToken))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open current process token.");
        }

        // CreateRestrictedToken with DISABLE_MAX_PRIVILEGE strips every privilege except
        // SeChangeNotifyPrivilege, but it does NOT touch group SIDs or the integrity level. Two
        // further steps are therefore required to actually reduce authority, and both were missing
        // before: (1) mark the Administrators group deny-only via SidsToDisable, so an elevated
        // operator's admin membership cannot authorize the sensor tool; (2) lower the token's
        // integrity to Medium. Without these the "stripped Admin SIDs (S-1-5-32-544)" property the
        // catalog advertises is not real - the tool would keep admin group authority and High
        // integrity while only its privileges were dropped.
        IntPtr adminSid = IntPtr.Zero;
        IntPtr sidsToDisable = IntPtr.Zero;
        try
        {
            adminSid = MarshalSid(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            sidsToDisable = Marshal.AllocHGlobal(Marshal.SizeOf<Win32Interop.SID_AND_ATTRIBUTES>());
            Marshal.StructureToPtr(
                new Win32Interop.SID_AND_ATTRIBUTES { Sid = adminSid, Attributes = 0 },
                sidsToDisable, false);

            if (!Win32Interop.CreateRestrictedToken(
                currentToken,
                Win32Interop.DISABLE_MAX_PRIVILEGE,
                1, sidsToDisable,   // Administrators -> USE_FOR_DENY_ONLY
                0, IntPtr.Zero,
                0, IntPtr.Zero,
                out IntPtr restrictedToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create restricted token.");
            }

            try
            {
                // Drop integrity on the restricted token before duplicating it, so the primary
                // token (and the process launched from it) inherits Medium integrity.
                LowerIntegrityToMedium(restrictedToken);

                // bInheritHandle = 0, deliberately. CreateProcessAsUserW consumes this handle in the
                // PARENT, so nothing needs it to be inheritable - and the launcher passes
                // bInheritHandles: true, which means an inheritable token handle would be handed to
                // the sandboxed child itself. Giving a confined process a TOKEN_ALL_ACCESS handle to
                // its own token is authority the sandbox never intended to grant.
                var sa = new Win32Interop.SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf<Win32Interop.SECURITY_ATTRIBUTES>(),
                    bInheritHandle = 0
                };

                // Duplicate as a primary token for CreateProcessAsUser
                if (!Win32Interop.DuplicateTokenEx(
                    restrictedToken,
                    Win32Interop.TOKEN_ALL_ACCESS,
                    ref sa,
                    2, // SecurityImpersonation
                    1, // TokenPrimary
                    out IntPtr primaryToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to duplicate restricted primary token.");
                }

                return primaryToken;
            }
            finally
            {
                Win32Interop.CloseHandle(restrictedToken);
            }
        }
        finally
        {
            // adminSid backs the SID_AND_ATTRIBUTES read by CreateRestrictedToken above, so it is
            // only safe to free here, after that call has returned.
            if (sidsToDisable != IntPtr.Zero) Marshal.FreeHGlobal(sidsToDisable);
            if (adminSid != IntPtr.Zero) Marshal.FreeHGlobal(adminSid);
            Win32Interop.CloseHandle(currentToken);
        }
    }

    // Medium is the standard-user integrity level (S-1-16-8192). You can lower integrity but never
    // raise it, so on an already-standard host this is a no-op rather than an error; on an elevated
    // host it removes the High integrity the operator would otherwise hand to the tool.
    private static void LowerIntegrityToMedium(IntPtr token)
    {
        IntPtr integritySid = IntPtr.Zero;
        IntPtr labelPtr = IntPtr.Zero;
        try
        {
            integritySid = MarshalSid(new SecurityIdentifier("S-1-16-8192"));
            var label = new Win32Interop.TOKEN_MANDATORY_LABEL
            {
                Label = new Win32Interop.SID_AND_ATTRIBUTES
                {
                    Sid = integritySid,
                    Attributes = Win32Interop.SE_GROUP_INTEGRITY
                }
            };
            labelPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Win32Interop.TOKEN_MANDATORY_LABEL>());
            Marshal.StructureToPtr(label, labelPtr, false);

            if (!Win32Interop.SetTokenInformation(
                token,
                Win32Interop.TokenIntegrityLevel,
                labelPtr,
                (uint)Marshal.SizeOf<Win32Interop.TOKEN_MANDATORY_LABEL>()))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to lower restricted token integrity to Medium.");
            }
        }
        finally
        {
            if (labelPtr != IntPtr.Zero) Marshal.FreeHGlobal(labelPtr);
            if (integritySid != IntPtr.Zero) Marshal.FreeHGlobal(integritySid);
        }
    }

    private static IntPtr MarshalSid(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }
}
