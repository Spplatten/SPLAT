using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Windows.Native;

namespace MissionController.Infrastructure.Windows.JobObjects;

public sealed class Win32JobSandbox : IJobSandbox
{
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

        // Configure default hardened limits: Kill on Close, Silent Breakaway OK, Breakaway OK
        ConfigureDefaultHardenedLimits();
    }

    private void ConfigureDefaultHardenedLimits()
    {
        var extendedLimits = new Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        extendedLimits.BasicLimitInformation.LimitFlags =
            Win32Interop.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            Win32Interop.JOB_OBJECT_LIMIT_BREAKAWAY_OK |
            Win32Interop.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

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

        var extendedLimits = new Win32Interop.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        extendedLimits.BasicLimitInformation.LimitFlags =
            Win32Interop.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            Win32Interop.JOB_OBJECT_LIMIT_BREAKAWAY_OK |
            Win32Interop.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

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
                return new JobResourceMetrics(
                    accounting.BasicInfo.ActiveProcesses,
                    accounting.BasicInfo.TotalKernelTime / 10000, // 100-ns ticks to ms
                    accounting.BasicInfo.TotalUserTime / 10000,
                    0,
                    0);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pInfo);
        }

        return new JobResourceMetrics(0, 0, 0, 0, 0);
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
