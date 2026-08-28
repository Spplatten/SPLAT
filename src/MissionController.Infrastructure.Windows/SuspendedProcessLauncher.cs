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
        CancellationToken cancellationToken = default)
    {
        var sa = new Win32Interop.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf(typeof(Win32Interop.SECURITY_ATTRIBUTES)),
            bInheritHandle = 1,
            lpSecurityDescriptor = IntPtr.Zero
        };

        // Create anonymous pipes for STDOUT and STDERR redirection
        if (!Win32Interop.CreatePipe(out IntPtr hStdOutRead, out IntPtr hStdOutWrite, ref sa, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create stdout pipe.");
        }
        Win32Interop.SetHandleInformation(hStdOutRead, Win32Interop.HANDLE_FLAG_INHERIT, 0); // Read handle non-inheritable

        if (!Win32Interop.CreatePipe(out IntPtr hStdErrRead, out IntPtr hStdErrWrite, ref sa, 0))
        {
            Win32Interop.CloseHandle(hStdOutRead);
            Win32Interop.CloseHandle(hStdOutWrite);
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to create stderr pipe.");
        }
        Win32Interop.SetHandleInformation(hStdErrRead, Win32Interop.HANDLE_FLAG_INHERIT, 0);

        var si = new Win32Interop.STARTUPINFO
        {
            cb = Marshal.SizeOf(typeof(Win32Interop.STARTUPINFO)),
            dwFlags = (int)Win32Interop.STARTF_USESTDHANDLES,
            hStdOutput = hStdOutWrite,
            hStdError = hStdErrWrite,
            hStdInput = IntPtr.Zero
        };

        var pi = new Win32Interop.PROCESS_INFORMATION();

        string resolvedExecutable = ResolveExecutablePath(executable);
        string fullCommandLine = string.IsNullOrWhiteSpace(arguments)
            ? $"\"{resolvedExecutable}\""
            : $"\"{resolvedExecutable}\" {arguments}";

        uint creationFlags = Win32Interop.CREATE_SUSPENDED | Win32Interop.CREATE_NO_WINDOW;

        IntPtr restrictedToken = IntPtr.Zero;
        bool success = false;

        try
        {
            if (dropAdminPrivileges)
            {
                try
                {
                    restrictedToken = _restrictedTokenProvider.CreateLowPrivilegeToken();
                    success = Win32Interop.CreateProcessAsUserW(
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
                    // This previously fell back to CreateProcessW - a FULL-token launch - whenever the
                    // restricted-token path failed. A template declaring RequiresRestrictedToken could
                    // therefore run its tool with the operator's full (often administrative) privileges
                    // while the mission still reported success and the ledger still recorded it as
                    // governed. A sandbox that silently turns itself off is worse than no sandbox,
                    // because everything downstream keeps trusting it. Refuse the launch instead: the
                    // engine catches this and seals an honest MISSION_FAILED row.
                    throw new SecurityException(
                        "Privilege drop required by this template could not be applied, so the sensor tool was NOT launched. " +
                        $"CreateProcessAsUserW failed with Win32 error {Marshal.GetLastWin32Error()}.");
                }
            }
            else
            {
                success = Win32Interop.CreateProcessW(
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

            // CRITICAL HARDENING FIX 1: Assign process to Job Object BEFORE resuming thread
            jobSandbox.AssignProcess(pi.hProcess);

            // Close write ends in parent process so EOF can be detected on read
            Win32Interop.CloseHandle(hStdOutWrite);
            hStdOutWrite = IntPtr.Zero;
            Win32Interop.CloseHandle(hStdErrWrite);
            hStdErrWrite = IntPtr.Zero;

            // Resume the primary thread now that the process is bound to the Job Object
            uint resumeResult = Win32Interop.ResumeThread(pi.hThread);
            if (resumeResult == unchecked((uint)-1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to resume process thread.");
            }

            // Setup stream readers for synchronous pipes
            using var stdoutStream = new FileStream(new SafeFileHandle(hStdOutRead, true), FileAccess.Read, 4096, isAsync: false);
            using var stderrStream = new FileStream(new SafeFileHandle(hStdErrRead, true), FileAccess.Read, 4096, isAsync: false);

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
                        uint wait = Win32Interop.WaitForSingleObject(pi.hProcess, 100);
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

            Win32Interop.GetExitCodeProcess(pi.hProcess, out uint exitCode);
            var metrics = jobSandbox.GetResourceMetrics();

            return new ProcessExecutionResult((int)exitCode, stdout, stderr, timedOut, metrics);
        }
        finally
        {
            if (hStdOutWrite != IntPtr.Zero) Win32Interop.CloseHandle(hStdOutWrite);
            if (hStdErrWrite != IntPtr.Zero) Win32Interop.CloseHandle(hStdErrWrite);
            if (pi.hThread != IntPtr.Zero) Win32Interop.CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) Win32Interop.CloseHandle(pi.hProcess);
            if (restrictedToken != IntPtr.Zero) Win32Interop.CloseHandle(restrictedToken);
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
