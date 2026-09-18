using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Security;

public sealed class RestrictedTokenProvider : IRestrictedTokenProvider
{
    public SafeAccessTokenHandle CreateLowPrivilegeToken()
    {
        using var self = global::System.Diagnostics.Process.GetCurrentProcess();
        IntPtr currentProcess = self.Handle;

        // Every token below is owned by a SafeHandle from the moment the kernel returns it, so the
        // several throw sites in this method can no longer strand one. Only the primary token
        // escapes - deliberately, to the caller, which the interface now says in the type.
        if (!Win32Interop.OpenProcessToken(
            currentProcess,
            Win32Interop.TOKEN_DUPLICATE | Win32Interop.TOKEN_ASSIGN_PRIMARY | Win32Interop.TOKEN_QUERY | Win32Interop.TOKEN_ADJUST_DEFAULT,
            out SafeAccessTokenHandle currentToken))
        {
            currentToken.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open current process token.");
        }

        using var ownedCurrentToken = currentToken;

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
                out SafeAccessTokenHandle restrictedToken))
            {
                restrictedToken.Dispose();
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create restricted token.");
            }

            try
            {
                // Drop integrity on the restricted token before duplicating it, so the primary
                // token (and the process launched from it) inherits Medium integrity.
                LowerIntegrityToMedium(restrictedToken);

                // And let the child open what it creates - its own process first. From an elevated
                // console it could not, and never started: see GiveTheUserWhatItCreates.
                GiveTheUserWhatItCreates(restrictedToken);

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
                    out SafeAccessTokenHandle primaryToken))
                {
                    primaryToken.Dispose();
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to duplicate restricted primary token.");
                }

                return primaryToken;
            }
            finally
            {
                restrictedToken.Dispose();
            }
        }
        finally
        {
            // adminSid backs the SID_AND_ATTRIBUTES read by CreateRestrictedToken above, so it is
            // only safe to free here, after that call has returned.
            if (sidsToDisable != IntPtr.Zero) Marshal.FreeHGlobal(sidsToDisable);
            if (adminSid != IntPtr.Zero) Marshal.FreeHGlobal(adminSid);
        }
    }

    // Medium is the standard-user integrity level (S-1-16-8192). You can lower integrity but never
    // raise it, so on an already-standard host this is a no-op rather than an error; on an elevated
    // host it removes the High integrity the operator would otherwise hand to the tool.
    private static void LowerIntegrityToMedium(SafeAccessTokenHandle token)
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

    /// <summary>
    /// The default DACL and owner a non-elevated token already hands out: the user in full, and SYSTEM.
    ///
    /// An elevated administrator's token gives everything it creates a DACL naming Administrators and
    /// SYSTEM, not the user, and makes Administrators the owner. The restricted token kept both while
    /// marking Administrators deny-only above, so a child launched from an elevated console could not
    /// open its own process and died in DLL initialisation (0xC0000142). Seven tests failed exactly that
    /// way from an elevated PowerShell on 2026-09-18 - in the configuration this privilege drop exists for.
    /// </summary>
    private static void GiveTheUserWhatItCreates(SafeAccessTokenHandle token)
    {
        SecurityIdentifier user = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("This process's token names no user to grant.");

        var dacl = new DiscretionaryAcl(isContainer: false, isDS: false, capacity: 2);
        dacl.AddAccess(AccessControlType.Allow, user, GenericAll, InheritanceFlags.None, PropagationFlags.None);
        dacl.AddAccess(AccessControlType.Allow, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            GenericAll, InheritanceFlags.None, PropagationFlags.None);
        byte[] acl = new byte[dacl.BinaryLength];
        dacl.GetBinaryForm(acl, 0);

        IntPtr aclBuffer = Marshal.AllocHGlobal(acl.Length);
        IntPtr owner = MarshalSid(user);
        // TOKEN_DEFAULT_DACL and TOKEN_OWNER are each a structure holding one pointer.
        IntPtr pointer = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.Copy(acl, 0, aclBuffer, acl.Length);
            Marshal.WriteIntPtr(pointer, aclBuffer);
            if (!Win32Interop.SetTokenInformation(token, Win32Interop.TokenDefaultDacl, pointer, (uint)IntPtr.Size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to give the restricted token a default DACL naming its user.");
            }

            Marshal.WriteIntPtr(pointer, owner);
            if (!Win32Interop.SetTokenInformation(token, Win32Interop.TokenOwner, pointer, (uint)IntPtr.Size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to make the restricted token's user the owner of what it creates.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
            Marshal.FreeHGlobal(owner);
            Marshal.FreeHGlobal(aclBuffer);
        }
    }

    private const int GenericAll = 0x10000000;

    private static IntPtr MarshalSid(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }
}
