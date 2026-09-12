using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using MissionController.Infrastructure.Windows.JobObjects;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Guards the two failure modes the compiler cannot see after the [DllImport] -> [LibraryImport]
/// migration. Everything else in that migration fails loudly at build time; these two do not.
/// </summary>
public sealed class Win32InteropMigrationTests
{
    private static Type Interop =>
        typeof(Win32JobSandbox).Assembly.GetType("MissionController.Infrastructure.Windows.Native.Win32Interop", throwOnError: true)!;

    private static Type NestedStruct(string name) =>
        Interop.GetNestedType(name, BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException($"{name} is gone from Win32Interop.");

    /// <summary>
    /// LibraryImport is always exact-spelling - it never probes for the W-suffixed export the way
    /// DllImport did under CharSet.Unicode. kernel32 exports CreateJobObjectW, not CreateJobObject,
    /// so an EntryPoint attribute left off that declaration compiles clean and then throws here.
    /// Constructing the sandbox also walks SetInformationJobObject and, on dispose, CloseHandle.
    /// </summary>
    [Fact]
    public void EveryJobObjectEntryPointStillResolvesAtRuntime()
    {
        using var sandbox = new Win32JobSandbox();
        Assert.False(string.IsNullOrWhiteSpace(sandbox.JobName));
    }

    /// <summary>
    /// cb is what tells the kernel to read the EXTENDED form of the struct and honour the attribute
    /// list carrying the AppContainer SID. A short cb does not fail - it silently launches a sensor
    /// that was supposed to have no network stack with full network access. Making STARTUPINFO
    /// blittable had to leave the native size untouched, so that equality is asserted rather than
    /// assumed: three pointer-sized reserved LPWSTRs became three pointer-sized nints.
    /// </summary>
    [Fact]
    public void StartupInfoLayoutStillMatchesTheKernelContract()
    {
        Assert.Equal(8, IntPtr.Size); // the expected sizes below are the x64 contract
        Assert.Equal(104, Marshal.SizeOf(NestedStruct("STARTUPINFO")));
        Assert.Equal(112, Marshal.SizeOf(NestedStruct("STARTUPINFOEX")));

        // Offsets of every field the launcher actually writes.
        foreach (var (field, offset) in new[]
                 {
                     ("cb", 0), ("dwFlags", 60), ("hStdInput", 80), ("hStdOutput", 88), ("hStdError", 96)
                 })
        {
            Assert.Equal(offset, Marshal.OffsetOf(NestedStruct("STARTUPINFO"), field).ToInt64());
        }
    }

    /// <summary>
    /// The structural precondition behind the test above. A managed reference anywhere in these
    /// structs is rejected by the source generator (SYSLIB1051), so re-adding a `string` field would
    /// break the build - but re-adding one alongside a hand-written marshaller would not, and would
    /// move every subsequent field. Asserting "no managed references" keeps that door shut.
    /// </summary>
    [Fact]
    public void ProcessStartupStructsCarryNoManagedReferences()
    {
        foreach (var name in new[] { "STARTUPINFO", "STARTUPINFOEX", "SECURITY_ATTRIBUTES", "SECURITY_CAPABILITIES" })
        {
            var type = NestedStruct(name);
            var managed = type
                .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .Where(f => !f.FieldType.IsValueType)
                .Select(f => $"{name}.{f.Name} ({f.FieldType.Name})")
                .ToArray();

            Assert.True(managed.Length == 0, $"Managed reference fields break source-generated marshalling: {string.Join(", ", managed)}");
        }
    }
}
