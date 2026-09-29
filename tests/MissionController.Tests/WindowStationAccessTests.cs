using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The headless 0xC0000142, reproduced under one variable and then fixed.
///
/// The field observation (ROADMAP, 2026-09-18) was that over a non-interactive logon a PowerShell
/// sensor launched into SPLAT's AppContainer died at 0xC0000142 before running a line, while
/// cmd.exe started, and that the same tests passed in a desktop session. It sat as "cause unknown"
/// because reproducing it needed a service or SSH logon, which no test could arrange.
///
/// It does not need one. The variable is not the logon - it is whether the AppContainer may open the
/// window station and desktop, and a desktop created with a DACL naming only the current user has
/// exactly the shape LSA gives a service's. That is what these tests build. cmd.exe is the control
/// throughout: it does not load user32 at startup, so if the theory is right it survives the
/// condition that kills PowerShell, and a run where both die proves nothing about window stations.
/// </summary>
public class WindowStationAccessTests
{
    private const uint DESKTOP_ALL = 0x1FF;
    private const uint READ_CONTROL = 0x00020000;
    private const uint WRITE_DAC = 0x00040000;
    private const uint DllInitFailed = 0xC0000142;
    private const uint Ran = 7;

    [Fact]
    public void OnAnInteractiveDesktop_TheContainerAlreadyAttaches_AndSplatWidensNothing()
    {
        Assert.True(SensorAppContainer.TryGetSid(out var sid, out string? why), why);

        var outcome = WindowStationAccess.EnsureAppContainerMayAttach(sid!);

        Assert.True(outcome.ContainerCanAttach, outcome.Description);

        // The guarantee that matters on an operator's own machine: Windows already put an
        // ALL APPLICATION PACKAGES ACE on WinSta0 and its Default desktop, so SPLAT changes nothing.
        // A version of this that granted unconditionally would rewrite the DACL of the desktop the
        // operator is sitting at, every time a sensor ran.
        Assert.False(outcome.Granted, outcome.Description);
        Assert.Contains("could already attach", outcome.Description);
    }

    [Fact]
    public void OnADesktopTheContainerCannotOpen_PowerShellDiesInDllInit_AndTheGrantRevivesIt()
    {
        Assert.True(SensorAppContainer.TryGetSid(out var containerSid, out string? why), why);

        string deskName = "SplatTest" + Environment.ProcessId + "_" + Environment.CurrentManagedThreadId;
        var self = WindowsIdentity.GetCurrent().User!;
        IntPtr desktop = CreateDesktopNaming(deskName, self);
        Assert.True(desktop != IntPtr.Zero, $"CreateDesktopW failed: {new Win32Exception().Message}");

        try
        {
            string target = CurrentStationName() + "\\" + deskName;

            // 1. The reported failure, with its control beside it.
            Assert.Equal(DllInitFailed, RunContained("powershell.exe -NoProfile -Command exit 7", target, containerSid!));
            Assert.Equal(Ran, RunContained("cmd.exe /c exit 7", target, containerSid!));

            // 2. The production path, pointed at this desktop by putting a thread on it. Nothing else
            //    about the call changes: it reads the same handle GetThreadDesktop would return over
            //    a non-interactive logon.
            var outcome = GrantOnDesktop(desktop, containerSid!);
            Assert.True(outcome.Granted, outcome.Description);
            Assert.True(outcome.ContainerCanAttach, outcome.Description);

            // 3. One ACE later, on the same desktop, with the same command.
            Assert.Equal(Ran, RunContained("powershell.exe -NoProfile -Command exit 7", target, containerSid!));
            Assert.Equal(Ran, RunContained("cmd.exe /c exit 7", target, containerSid!));
        }
        finally
        {
            CloseDesktop(desktop);
        }
    }

    /// <summary>
    /// Runs <see cref="WindowStationAccess.EnsureAppContainerMayAttach"/> with the thread standing on
    /// <paramref name="desktop"/>, on a thread of its own so a failure cannot leave an xunit worker
    /// attached to a desktop that is about to be closed.
    /// </summary>
    private static WindowStationAccess.Outcome GrantOnDesktop(IntPtr desktop, SecurityIdentifier containerSid)
    {
        WindowStationAccess.Outcome outcome = default;
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            IntPtr original = GetThreadDesktop(GetCurrentThreadId());
            if (!SetThreadDesktop(desktop))
            {
                failure = new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadDesktop failed.");
                return;
            }

            try
            {
                outcome = WindowStationAccess.EnsureAppContainerMayAttach(containerSid);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                SetThreadDesktop(original);
            }
        });

        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The grant thread did not finish.");
        if (failure is not null)
        {
            throw failure;
        }

        return outcome;
    }

    /// <summary>
    /// A desktop whose DACL names one SID and nothing else - the shape LSA gives a service logon's,
    /// and the one thing these tests change.
    /// </summary>
    private static IntPtr CreateDesktopNaming(string name, SecurityIdentifier only)
    {
        var dacl = new RawAcl(GenericAcl.AclRevision, 1);
        dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
            unchecked((int)(DESKTOP_ALL | READ_CONTROL | WRITE_DAC)), only, false, null));
        var descriptor = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative, only, only, null, dacl);

        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        IntPtr raw = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, raw, bytes.Length);

        var attributes = new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = raw,
            bInheritHandle = 0
        };

        return CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0, DESKTOP_ALL | READ_CONTROL | WRITE_DAC, ref attributes);
    }

    /// <summary>
    /// Launches a command in SPLAT's AppContainer on a named station and desktop and returns its exit
    /// code. Deliberately not through SuspendedProcessLauncher: that one grants access as part of its
    /// job, which is the behaviour under test, and it offers no way to name a desktop.
    /// </summary>
    private static uint RunContained(string commandLine, string stationAndDesktop, SecurityIdentifier containerSid)
    {
        IntPtr attributeList = IntPtr.Zero, capabilityBlock = IntPtr.Zero, sidBuffer = IntPtr.Zero, desktopName = IntPtr.Zero;
        try
        {
            byte[] sidBytes = new byte[containerSid.BinaryLength];
            containerSid.GetBinaryForm(sidBytes, 0);
            sidBuffer = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, sidBuffer, sidBytes.Length);

            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attributeList = Marshal.AllocHGlobal(size);
            Assert.True(InitializeProcThreadAttributeList(attributeList, 1, 0, ref size), "InitializeProcThreadAttributeList failed.");

            var capabilities = new SECURITY_CAPABILITIES
            {
                AppContainerSid = sidBuffer,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0
            };
            capabilityBlock = Marshal.AllocHGlobal(Marshal.SizeOf<SECURITY_CAPABILITIES>());
            Marshal.StructureToPtr(capabilities, capabilityBlock, false);
            Assert.True(
                UpdateProcThreadAttribute(attributeList, 0, new IntPtr(0x00020009), capabilityBlock,
                    new IntPtr(Marshal.SizeOf<SECURITY_CAPABILITIES>()), IntPtr.Zero, IntPtr.Zero),
                "UpdateProcThreadAttribute failed.");

            desktopName = Marshal.StringToHGlobalUni(stationAndDesktop);
            var startup = new STARTUPINFOEX
            {
                StartupInfo = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFOEX>(), lpDesktop = desktopName },
                lpAttributeList = attributeList
            };

            var command = new StringBuilder(commandLine);
            Assert.True(
                CreateProcessW(null, command, IntPtr.Zero, IntPtr.Zero, false,
                    0x00080000 | 0x08000000, IntPtr.Zero, null, ref startup, out var info),
                $"CreateProcessW failed for '{commandLine}': {new Win32Exception().Message}");

            Assert.Equal(0u, WaitForSingleObject(info.hProcess, 30000));
            Assert.True(GetExitCodeProcess(info.hProcess, out uint exitCode), "GetExitCodeProcess failed.");
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            return exitCode;
        }
        finally
        {
            if (desktopName != IntPtr.Zero) Marshal.FreeHGlobal(desktopName);
            if (capabilityBlock != IntPtr.Zero) Marshal.FreeHGlobal(capabilityBlock);
            if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
            if (sidBuffer != IntPtr.Zero) Marshal.FreeHGlobal(sidBuffer);
        }
    }

    private static string CurrentStationName()
    {
        var buffer = new StringBuilder(256);
        return GetUserObjectInformationW(GetProcessWindowStation(), 2, buffer, 256, out _) ? buffer.ToString() : "WinSta0";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid, Capabilities; public uint CapabilityCount, Reserved; }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateDesktopW(string desktop, IntPtr device, IntPtr devmode, uint flags, uint access, ref SECURITY_ATTRIBUTES sa);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr handle);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetThreadDesktop(IntPtr desktop);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint threadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetUserObjectInformationW(IntPtr obj, int index, StringBuilder info, uint length, out uint needed);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string? app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
        uint flags, IntPtr env, string? dir, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
