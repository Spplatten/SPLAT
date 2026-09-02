using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.JobObjects;

public sealed class Win32JobSandbox : IJobSandbox
{
    /// <summary>
    /// The containment flag set applied to every job, with or without explicit resource limits.
    ///
    /// BREAKAWAY_OK and SILENT_BREAKAWAY_OK were previously included here and are deliberately
    /// absent: SILENT_BREAKAWAY_OK detaches a job member's children from the job automatically, with
    /// no opt-in from the child, so `powershell.exe -c "Start-Process x"` left the sandbox entirely -
    /// unclamped, and surviving TerminateJobObject. A job a process can walk out of is not a
    /// boundary. DIE_ON_UNHANDLED_EXCEPTION suppresses the hard-error dialog that would otherwise
    /// leave a crashed sensor tool parked forever waiting for a click nobody is there to give.
    /// </summary>
    private const uint ContainmentLimitFlags =
        Win32Interop.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        Win32Interop.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        Win32Interop.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

    /// <summary>
    /// Ceiling on live processes inside one mission's job. Governed sensor templates are shell
    /// pipelines (cmd → ping → netstat, powershell → helpers), which sit comfortably under this;
    /// the cap exists so a fork bomb inside the sandbox is refused by the kernel at CreateProcess
    /// rather than absorbed by the host.
    /// </summary>
    private const uint MaxActiveProcesses = 32;

    private IntPtr _jobHandle;
    private bool _disposed;
    public string JobName { get; }

    public Win32JobSandbox(string? jobName = null)
    {
        JobName = jobName ?? $"MissionJob_{Guid.NewGuid():N}";
        _jobHandle = Win32Interop.CreateJobObject(IntPtr.Zero, JobName);
        if (_jobHandle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to create Win32 Job Object '{JobName}'");
        }

        // Containment is armed at construction so a job is never briefly escapable between
        // CreateJobObject and the caller's first ConfigureExtendedLimits.
        ConfigureDefaultHardenedLimits();
    }

    private void ConfigureDefaultHardenedLimits()
    {
        var extendedLimits = new Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        extendedLimits.BasicLimitInformation.LimitFlags = ContainmentLimitFlags;
        extendedLimits.BasicLimitInformation.ActiveProcessLimit = MaxActiveProcesses;

        int length = Marshal.SizeOf(typeof(Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr pLimits = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(extendedLimits, pLimits, false);
            if (!Win32Interop.SetInformationJobObject(
                _jobHandle,
                Win32Interop.JobObjectInfoClass.JobObjectExtendedLimitInformation,
                pLimits,
                (uint)length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to configure default Job Object limits.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pLimits);
        }
    }

    public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent)
    {
        ThrowIfDisposed();

        // SetInformationJobObject REPLACES LimitFlags rather than merging, so the containment set
        // must be re-stated here or applying a memory cap would silently disarm the boundary.
        var extendedLimits = new Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        extendedLimits.BasicLimitInformation.LimitFlags = ContainmentLimitFlags;
        extendedLimits.BasicLimitInformation.ActiveProcessLimit = MaxActiveProcesses;

        if (maxMemoryBytes > 0)
        {
            extendedLimits.BasicLimitInformation.LimitFlags |=
                Win32Interop.JOB_OBJECT_LIMIT_JOB_MEMORY |
                Win32Interop.JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            extendedLimits.JobMemoryLimit = new UIntPtr((ulong)maxMemoryBytes);
            extendedLimits.ProcessMemoryLimit = new UIntPtr((ulong)maxMemoryBytes);
        }

        int length = Marshal.SizeOf(typeof(Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr pLimits = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(extendedLimits, pLimits, false);
            if (!Win32Interop.SetInformationJobObject(
                _jobHandle,
                Win32Interop.JobObjectInfoClass.JobObjectExtendedLimitInformation,
                pLimits,
                (uint)length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to apply extended Job Object limits.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pLimits);
        }

        // Apply CPU Rate Control if requested
        if (maxCpuPercent is > 0 and <= 100)
        {
            var cpuLimits = new Win32Interop.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
            {
                ControlFlags = Win32Interop.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | Win32Interop.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                CpuRate = (uint)(maxCpuPercent * 100) // 100 = 1% in Win32
            };

            int cpuLength = Marshal.SizeOf(typeof(Win32Interop.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION));
            IntPtr pCpu = Marshal.AllocHGlobal(cpuLength);
            try
            {
                Marshal.StructureToPtr(cpuLimits, pCpu, false);
                Win32Interop.SetInformationJobObject(
                    _jobHandle,
                    Win32Interop.JobObjectInfoClass.JobObjectCpuRateControlInformation,
                    pCpu,
                    (uint)cpuLength);
            }
            finally
            {
                Marshal.FreeHGlobal(pCpu);
            }
        }
    }

    public void AssignProcess(IntPtr processHandle)
    {
        ThrowIfDisposed();
        if (!Win32Interop.AssignProcessToJobObject(_jobHandle, processHandle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to assign process to Job Object '{JobName}'.");
        }
    }

    public JobResourceMetrics GetResourceMetrics()
    {
        ThrowIfDisposed();

        int length = Marshal.SizeOf(typeof(Win32Interop.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION));
        IntPtr pInfo = Marshal.AllocHGlobal(length);
        try
        {
            if (Win32Interop.QueryInformationJobObject(
                _jobHandle,
                Win32Interop.JobObjectInfoClass.JobObjectBasicAndIoAccountingInformation,
                pInfo,
                (uint)length,
                out _))
            {
                var accounting = Marshal.PtrToStructure<Win32Interop.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>(pInfo);

                // Named arguments are mandatory here. The previous positional call was misaligned
                // against the record: ActiveProcesses was landing in PeakMemoryBytes, kernel time in
                // CurrentMemoryBytes, user time in TotalCpuKernelTimeMs, and the two real tail fields
                // were hardcoded 0 - so every Windows mission reported a process count as its peak
                // memory figure. Memory is left null because BasicAndIoAccounting does not carry it;
                // reading it needs a separate JobObjectExtendedLimitInformation query.
                return new JobResourceMetrics(
                    PeakMemoryBytes: null,
                    CurrentMemoryBytes: null,
                    TotalCpuKernelTimeMs: accounting.BasicInfo.TotalKernelTime / 10000, // 100-ns ticks to ms
                    TotalCpuUserTimeMs: accounting.BasicInfo.TotalUserTime / 10000,
                    ActiveProcessCount: accounting.BasicInfo.ActiveProcesses);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pInfo);
        }

        // The query failed. Reporting zeros here would claim the job burned no CPU and ran no
        // processes, which is a measurement the caller never made.
        return JobResourceMetrics.Unavailable;
    }

    public void TerminateAllProcesses(uint exitCode = 1)
    {
        if (_jobHandle != IntPtr.Zero)
        {
            Win32Interop.TerminateJobObject(_jobHandle, exitCode);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed || _jobHandle == IntPtr.Zero)
        {
            throw new ObjectDisposedException(nameof(Win32JobSandbox));
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            if (_jobHandle != IntPtr.Zero)
            {
                Win32Interop.CloseHandle(_jobHandle);
                _jobHandle = IntPtr.Zero;
            }
        }
    }
}
