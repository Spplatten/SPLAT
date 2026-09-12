using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Windows.Native;
using MissionController.Infrastructure.Windows.Security;

namespace MissionController.Infrastructure.Windows.Process;

public sealed class SuspendedProcessLauncher : IProcessLauncher
{
    private readonly IRestrictedTokenProvider _restrictedTokenProvider;

    public SuspendedProcessLauncher(IRestrictedTokenProvider restrictedTokenProvider)
    {
        _restrictedTokenProvider = restrictedTokenProvider;
    }

    public async Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
        string executable,
        string arguments,
        string workingDirectory,
        IJobSandbox jobSandbox,
        bool dropAdminPrivileges,
        int timeoutSeconds,
        IProgress<string>? stdoutProgress = null,
        IProgress<string>? stderrProgress = null,
        CancellationToken cancellationToken = default,
        bool denyNetworkAccess = false)
    {
        var sa = new Win32Interop.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<Win32Interop.SECURITY_ATTRIBUTES>(),
            bInheritHandle = 1,
            lpSecurityDescriptor = IntPtr.Zero
        };

        IntPtr hStdOutRead = IntPtr.Zero;
        IntPtr hStdOutWrite = IntPtr.Zero;
        IntPtr hStdErrRead = IntPtr.Zero;
        IntPtr hStdErrWrite = IntPtr.Zero;
        SafeAccessTokenHandle? restrictedToken = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr capabilitiesBlock = IntPtr.Zero;
        IntPtr appContainerSidBuffer = IntPtr.Zero;
        var pi = new Win32Interop.PROCESS_INFORMATION();

        try
        {
            // Create anonymous pipes for STDOUT and STDERR redirection
            if (!Win32Interop.CreatePipe(out hStdOutRead, out hStdOutWrite, ref sa, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create stdout pipe.");
            }
            Win32Interop.SetHandleInformation(hStdOutRead, Win32Interop.HANDLE_FLAG_INHERIT, 0); // Read handle non-inheritable

            if (!Win32Interop.CreatePipe(out hStdErrRead, out hStdErrWrite, ref sa, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create stderr pipe.");
            }
            Win32Interop.SetHandleInformation(hStdErrRead, Win32Interop.HANDLE_FLAG_INHERIT, 0);

            var si = new Win32Interop.STARTUPINFO
            {
                cb = Marshal.SizeOf<Win32Interop.STARTUPINFO>(),
                dwFlags = (int)Win32Interop.STARTF_USESTDHANDLES,
                hStdOutput = hStdOutWrite,
                hStdError = hStdErrWrite,
                hStdInput = IntPtr.Zero
            };

            string resolvedExecutable = ResolveExecutablePath(executable);
            string fullCommandLine = string.IsNullOrWhiteSpace(arguments)
                ? $"\"{resolvedExecutable}\""
                : $"\"{resolvedExecutable}\" {arguments}";

            uint creationFlags = Win32Interop.CREATE_SUSPENDED | Win32Interop.CREATE_NO_WINDOW;
            bool success = false;

            // Network denial is applied by launching into an AppContainer holding ZERO capability
            // SIDs. Capabilities are what grant an AppContainer its reach, so an empty set leaves the
            // process with no network stack at all - DNS and a raw-IP TCP connect both fail inside it.
            // Built before the token so a machine that cannot furnish a container costs nothing.
            var siex = new Win32Interop.STARTUPINFOEX { StartupInfo = si };
            if (denyNetworkAccess)
            {
                // FAIL CLOSED, exactly as the privilege drop does below. A template that declares its
                // sensor needs no network must never be run WITH a network because containment was
                // unavailable - that would turn an enforced boundary back into a hopeful comment.
                if (!SensorAppContainer.TryGetSid(out var containerSid, out var isolationFailure) || containerSid is null)
                {
                    throw new SecurityException(
                        "Network isolation required by this template could not be applied, so the sensor tool was NOT launched. " +
                        isolationFailure);
                }

                appContainerSidBuffer = SensorAppContainer.AllocateNativeSid(containerSid);

                // Called twice by contract: the first call fails with ERROR_INSUFFICIENT_BUFFER and
                // reports the size through listSize, which is why its return value is not checked.
                IntPtr listSize = IntPtr.Zero;
                Win32Interop.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
                attributeList = Marshal.AllocHGlobal(listSize);

                if (!Win32Interop.InitializeProcThreadAttributeList(attributeList, 1, 0, ref listSize))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to initialize process attribute list for network isolation.");
                }

                var capabilities = new Win32Interop.SECURITY_CAPABILITIES
                {
                    AppContainerSid = appContainerSidBuffer,
                    Capabilities = IntPtr.Zero,
                    CapabilityCount = 0,
                    Reserved = 0
                };

                capabilitiesBlock = Marshal.AllocHGlobal(Marshal.SizeOf<Win32Interop.SECURITY_CAPABILITIES>());
                Marshal.StructureToPtr(capabilities, capabilitiesBlock, false);

                if (!Win32Interop.UpdateProcThreadAttribute(
                        attributeList,
                        0,
                        Win32Interop.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        capabilitiesBlock,
                        new IntPtr(Marshal.SizeOf<Win32Interop.SECURITY_CAPABILITIES>()),
                        IntPtr.Zero,
                        IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to attach AppContainer capabilities to the sensor launch.");
                }

                // cb must describe the EXTENDED struct and the flag must be set, or the kernel reads
                // only the STARTUPINFO prefix and launches the tool with full network access.
                siex.lpAttributeList = attributeList;
                siex.StartupInfo.cb = Marshal.SizeOf<Win32Interop.STARTUPINFOEX>();
                creationFlags |= Win32Interop.EXTENDED_STARTUPINFO_PRESENT;
            }

            if (dropAdminPrivileges)
            {
                try
                {
                    restrictedToken = _restrictedTokenProvider.CreateLowPrivilegeToken();
                    success = denyNetworkAccess
                        ? Win32Interop.CreateProcessAsUserExtendedW(
                            restrictedToken,
                            null,
                            fullCommandLine,
                            ref sa,
                            ref sa,
                            true,
                            creationFlags,
                            IntPtr.Zero,
                            workingDirectory,
                            ref siex,
                            out pi)
                        : Win32Interop.CreateProcessAsUserW(
                            restrictedToken,
                            null,
                            fullCommandLine,
                            ref sa,
                            ref sa,
                            true,
                            creationFlags,
                            IntPtr.Zero,
                            workingDirectory,
                            ref si,
                            out pi);
                }
                catch (Exception ex)
                {
                    // FAIL CLOSED - see below. Token creation blowing up is not a reason to run
                    // the tool with more privilege than the template asked for.
                    throw new SecurityException(
                        "Privilege drop required by this template could not be applied, so the sensor tool was NOT launched. " +
                        $"Restricted token creation failed: {ex.Message}", ex);
                }

                if (!success)
                {
                    // Refuse the launch instead: the engine catches this and seals an honest MISSION_FAILED row.
                    throw new SecurityException(
                        "Privilege drop required by this template could not be applied, so the sensor tool was NOT launched. " +
                        $"CreateProcessAsUserW failed with Win32 error {Marshal.GetLastWin32Error()}.");
                }
            }
            else
            {
                success = denyNetworkAccess
                    ? Win32Interop.CreateProcessExtendedW(
                        null,
                        fullCommandLine,
                        ref sa,
                        ref sa,
                        true,
                        creationFlags,
                        IntPtr.Zero,
                        workingDirectory,
                        ref siex,
                        out pi)
                    : Win32Interop.CreateProcessW(
                        null,
                        fullCommandLine,
                        ref sa,
                        ref sa,
                        true,
                        creationFlags,
                        IntPtr.Zero,
                        workingDirectory,
                        ref si,
                        out pi);
            }

            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to create suspended process '{resolvedExecutable}'.");
            }

            using var safeProcess = new SafeProcessHandle(pi.hProcess, ownsHandle: true);
            pi.hProcess = IntPtr.Zero;
            using var safeThread = new SafeThreadHandle(pi.hThread);
            pi.hThread = IntPtr.Zero;

            // Assign process to Job Object BEFORE resuming thread
            jobSandbox.AssignProcess(safeProcess);

            // Close write ends in parent process so EOF can be detected on read
            Win32Interop.CloseHandle(hStdOutWrite);
            hStdOutWrite = IntPtr.Zero;
            Win32Interop.CloseHandle(hStdErrWrite);
            hStdErrWrite = IntPtr.Zero;

            // Resume the primary thread now that the process is bound to the Job Object
            uint resumeResult = Win32Interop.ResumeThread(safeThread);
            if (resumeResult == unchecked((uint)-1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to resume process thread.");
            }

            // Transfer handle ownership to SafeFileHandle
            using var safeStdOut = new SafeFileHandle(hStdOutRead, ownsHandle: true);
            hStdOutRead = IntPtr.Zero;
            using var safeStdErr = new SafeFileHandle(hStdErrRead, ownsHandle: true);
            hStdErrRead = IntPtr.Zero;

            // Setup stream readers for synchronous pipes
            using var stdoutStream = new FileStream(safeStdOut, FileAccess.Read, 4096, isAsync: false);
            using var stderrStream = new FileStream(safeStdErr, FileAccess.Read, 4096, isAsync: false);

            var stdoutTask = ReadStreamAsync(stdoutStream, stdoutProgress, cancellationToken);
            var stderrTask = ReadStreamAsync(stderrStream, stderrProgress, cancellationToken);

            // Wait for process with timeout and cancellation
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            bool timedOut = false;
            try
            {
                await Task.Run(() =>
                {
                    while (true)
                    {
                        cts.Token.ThrowIfCancellationRequested();
                        uint wait = Win32Interop.WaitForSingleObject(safeProcess, 100);
                        if (wait == 0) // WAIT_OBJECT_0
                            break;
                    }
                }, cts.Token);
            }
            catch (OperationCanceledException)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    timedOut = true;
                    jobSandbox.TerminateAllProcesses(99);
                }
                else
                {
                    jobSandbox.TerminateAllProcesses(130);
                    throw;
                }
            }

            string stdout = await stdoutTask;
            string stderr = await stderrTask;

            Win32Interop.GetExitCodeProcess(safeProcess, out uint exitCode);
            var metrics = jobSandbox.GetResourceMetrics();

            return new ProcessExecutionResult((int)exitCode, stdout, stderr, timedOut, metrics);
        }
        finally
        {
            if (hStdOutRead != IntPtr.Zero) Win32Interop.CloseHandle(hStdOutRead);
            if (hStdOutWrite != IntPtr.Zero) Win32Interop.CloseHandle(hStdOutWrite);
            if (hStdErrRead != IntPtr.Zero) Win32Interop.CloseHandle(hStdErrRead);
            if (hStdErrWrite != IntPtr.Zero) Win32Interop.CloseHandle(hStdErrWrite);
            // Non-zero only when CreateProcess succeeded but something between it and the adoption
            // above threw; past that point the two using declarations own them.
            if (pi.hThread != IntPtr.Zero) Win32Interop.CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) Win32Interop.CloseHandle(pi.hProcess);
            restrictedToken?.Dispose();

            // The attribute list holds a pointer INTO capabilitiesBlock, which in turn points at
            // appContainerSidBuffer, so the list is deleted before either block is released.
            if (attributeList != IntPtr.Zero)
            {
                Win32Interop.DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (capabilitiesBlock != IntPtr.Zero) Marshal.FreeHGlobal(capabilitiesBlock);
            if (appContainerSidBuffer != IntPtr.Zero) Marshal.FreeHGlobal(appContainerSidBuffer);
        }
    }

    private static async Task<string> ReadStreamAsync(
        Stream stream,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var sb = new StringBuilder();
        char[] buffer = new char[1024];
        int read;

        while ((read = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            string chunk = new string(buffer, 0, read);
            sb.Append(chunk);
            progress?.Report(chunk);
            if (cancellationToken.IsCancellationRequested)
                break;
        }

        return sb.ToString();
    }

    private static string ResolveExecutablePath(string executable)
    {
        if (Path.IsPathRooted(executable) && File.Exists(executable))
            return executable;

        string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string systemCandidate = Path.Combine(systemDir, executable);
        if (File.Exists(systemCandidate))
            return systemCandidate;

        string wbemCandidate = Path.Combine(systemDir, "wbem", executable);
        if (File.Exists(wbemCandidate))
            return wbemCandidate;

        string psCandidate = Path.Combine(systemDir, "WindowsPowerShell", "v1.0", executable);
        if (File.Exists(psCandidate))
            return psCandidate;

        return executable;
    }
}
