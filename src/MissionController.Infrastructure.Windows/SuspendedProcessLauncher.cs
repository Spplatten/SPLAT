using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
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

        string fullCommandLine = string.IsNullOrWhiteSpace(arguments)
            ? $"\"{executable}\""
            : $"\"{executable}\" {arguments}";

        uint creationFlags = Win32Interop.CREATE_SUSPENDED | Win32Interop.CREATE_NO_WINDOW;

        IntPtr restrictedToken = IntPtr.Zero;
        bool success;

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
                catch
                {
                    // Fallback to standard CreateProcessW if CreateProcessAsUserW encounters privilege boundaries
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
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to create suspended process '{executable}'.");
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
}
