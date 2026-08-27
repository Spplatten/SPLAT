using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.Security;

public sealed class RestrictedTokenProvider : IRestrictedTokenProvider
{
    public IntPtr CreateLowPrivilegeToken()
    {
        IntPtr currentProcess = global::System.Diagnostics.Process.GetCurrentProcess().Handle;
        if (!Win32Interop.OpenProcessToken(
            currentProcess,
            Win32Interop.TOKEN_DUPLICATE | Win32Interop.TOKEN_ASSIGN_PRIMARY | Win32Interop.TOKEN_QUERY | Win32Interop.TOKEN_ADJUST_DEFAULT,
            out IntPtr currentToken))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open current process token.");
        }

        try
        {
            // LUA_TOKEN / DISABLE_MAX_PRIVILEGE strips administrator SID and privileges
            if (!Win32Interop.CreateRestrictedToken(
                currentToken,
                Win32Interop.DISABLE_MAX_PRIVILEGE | Win32Interop.LUA_TOKEN,
                0, IntPtr.Zero,
                0, IntPtr.Zero,
                0, IntPtr.Zero,
                out IntPtr restrictedToken))
            {
                // If already non-elevated or LUA_TOKEN cannot be created, fallback to standard restricted token
                if (!Win32Interop.CreateRestrictedToken(
                    currentToken,
                    Win32Interop.DISABLE_MAX_PRIVILEGE,
                    0, IntPtr.Zero,
                    0, IntPtr.Zero,
                    0, IntPtr.Zero,
                    out restrictedToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create restricted token.");
                }
            }

            var sa = new Win32Interop.SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(Win32Interop.SECURITY_ATTRIBUTES)),
                bInheritHandle = 1
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
                Win32Interop.CloseHandle(restrictedToken);
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to duplicate restricted primary token.");
            }

            Win32Interop.CloseHandle(restrictedToken);
            return primaryToken;
        }
        finally
        {
            Win32Interop.CloseHandle(currentToken);
        }
    }
}
