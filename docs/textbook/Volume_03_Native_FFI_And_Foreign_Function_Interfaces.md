# Volume 03: Native FFI & Foreign Function Interfaces

## Master Table of Contents
1. [The Native Interoperability Layer: Crossing User/Kernel & Managed Boundaries](#1-the-native-interoperability-layer-crossing-userkernel--managed-boundaries)
2. [ABI Calling Conventions: Windows x64 vs. System V AMD64](#2-abi-calling-conventions-windows-x64-vs-system-v-amd64)
3. [.NET P/Invoke Mechanics & Marshaling Discipline](#3-net-pinvoke-mechanics--marshaling-discipline)
4. [Pointer Lifecycles, Memory Pinning & Premature Deallocation Hazards](#4-pointer-lifecycles-memory-pinning--premature-deallocation-hazards)
5. [The Win32 Process Hardening Sequence](#5-the-win32-process-hardening-sequence)
6. [Linux Guest FFI: Async-Signal Safety in Rust `pre_exec`](#6-linux-guest-ffi-async-signal-safety-in-rust-pre_exec)
7. [Line-by-Line Code Breakdown: Containment FFI](#7-line-by-line-code-breakdown-containment-ffi)
8. [Step-by-Step Numerical Walkthrough: Register States During Syscall Invocations](#8-step-by-step-numerical-walkthrough-register-states-during-syscall-invocations)
9. [Interactive University Checkpoints & Debugging Puzzles](#9-interactive-university-checkpoints--debugging-puzzles)

---

## 1. The Native Interoperability Layer: Crossing User/Kernel & Managed Boundaries

In high-level languages like C# (.NET 10), execution occurs within a managed virtual machine governing memory allocation, garbage collection, and type safety. However, operating system containment primitives—such as Win32 Job Objects, Restricted Tokens, AppContainer profiles, and Linux cgroup/eBPF controllers—are exposed exclusively through unmanaged C Application Binary Interfaces (ABIs).

To construct an impermeable execution sandbox, SPLAT must cross the managed/unmanaged boundary hundreds of times per second. This Foreign Function Interface (FFI) boundary introduces strict architectural responsibilities:
- **Calling convention adherence**: Mismatches corrupt the CPU stack pointer (`RSP`).
- **Memory pinning**: Managed GC sweeps can relocate byte arrays while unmanaged Win32 APIs hold raw memory pointers.
- **Handle lifecycle discipline**: Leaking an unmanaged handle keeps kernel objects alive indefinitely, while premature handle closure closes resources actively in use.
- **Fail-closed security contracts**: Every FFI call that fails must abort execution rather than continuing with degraded security.

---

## 2. ABI Calling Conventions: Windows x64 vs. System V AMD64

The SPLAT multi-tier runtime bridges both Windows x64 and Linux x86-64 operating systems. Despite running on identical CPU hardware, their calling conventions differ significantly:

```
+─────────────────────────────────────────────────────────────────────────────+
| WINDOWS x64 CALLING CONVENTION (MS FASTCALL)                                 |
+─────────────────────────────────────────────────────────────────────────────+
| Integer/Pointer Register Arguments:                                         |
|   1. RCX                                                                    |
|   2. RDX                                                                    |
|   3. R8                                                                     |
|   4. R9                                                                     |
| Additional Arguments: Passed on Stack (RSP + 0x28, RSP + 0x30, ...)         |
| Shadow Space Requirement: Caller MUST allocate 32 bytes (0x20) on stack      |
| immediately before the call instruction, even for 0-argument functions.     |
| Volatile Registers: RAX, RCX, RDX, R8, R9, R10, R11                         |
| Non-Volatile (Preserved): RBX, RBP, RDI, RSI, R12, R13, R14, R15            |
+─────────────────────────────────────────────────────────────────────────────+

+─────────────────────────────────────────────────────────────────────────────+
| LINUX SYSTEM V AMD64 ABI CALLING CONVENTION                                 |
+─────────────────────────────────────────────────────────────────────────────+
| Integer/Pointer Register Arguments:                                         |
|   1. RDI                                                                    |
|   2. RSI                                                                    |
|   3. RDX                                                                    |
|   4. RCX                                                                    |
|   5. R8                                                                     |
|   6. R9                                                                     |
| Additional Arguments: Passed on Stack                                       |
| Red Zone: 128 bytes below RSP guaranteed not to be modified by signal       |
| handlers (leaf functions may use without adjusting RSP).                    |
| Volatile Registers: RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11               |
| Non-Volatile (Preserved): RBX, RSP, RBP, R12, R13, R14, R15                 |
+─────────────────────────────────────────────────────────────────────────────+
```

When C# invokes a Win32 API via `[DllImport("kernel32.dll")]`, the CLR JIT compiler synthesizes an unmanaged transition stub (P/Invoke thunk). This stub preserves non-volatile registers, allocates the required 32-byte shadow stack space, moves arguments from CLR internal evaluation stacks into `RCX`, `RDX`, `R8`, and `R9`, executes the `call` instruction, captures `GetLastError()`, and unmarshals return structures back into managed heap objects. That is the legacy path; SPLAT no longer takes it. `[LibraryImport]` moves the same work to compile time, which is why the signatures below read differently from the ones in most Win32 tutorials.

---

## 3. .NET P/Invoke Mechanics & Marshaling Discipline

In `src/MissionController.Infrastructure.Windows/Win32Interop.cs`, SPLAT defines explicit P/Invoke
signatures. All 25 use `[LibraryImport]` rather than `[DllImport]`: the marshalling code is emitted
by a Roslyn source generator at compile time, so there is no runtime IL stub to synthesize and the
whole surface stays NativeAOT-compatible. Automatic marshaling is strictly governed to prevent
performance overhead and memory corruption:

```csharp
[LibraryImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", SetLastError = true,
               StringMarshalling = StringMarshalling.Utf16)]
[return: MarshalAs(UnmanagedType.Bool)]
public static partial bool CreateProcessAsUserExtendedW(
    IntPtr hToken,
    string? lpApplicationName,
    string? lpCommandLine,
    ref SECURITY_ATTRIBUTES lpProcessAttributes,
    ref SECURITY_ATTRIBUTES lpThreadAttributes,
    [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string? lpCurrentDirectory,
    ref STARTUPINFOEX lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation);
```

Three differences from the `[DllImport]` form are worth reading closely, because each is a trap the
generator enforces rather than infers:

- `partial`, not `extern` — there is no body to import; the generator writes one.
- `bInheritHandles` carries an explicit `[MarshalAs]`. `[DllImport]` silently assumed 4-byte Win32
  `BOOL` for a bare `bool`; `[LibraryImport]` refuses to guess and fails the build (`SYSLIB1051`).
- `EntryPoint` is spelled out. `CharSet.Unicode` used to make the runtime probe for a `W` suffix at
  load time. The generator is always exact-spelling, so a name that does not match an exported
  symbol compiles cleanly and throws `EntryPointNotFoundException` on first call.

### Critical Marshaling Directives
1. **`SetLastError = true`**: Instructs the CLR to immediately invoke `GetLastError()` following the native call before any other internal runtime call can overwrite the thread's last error code.
2. **`CharSet = CharSet.Unicode`**: Directs string marshaling to pass 16-bit UTF-16 pointers (`LPCWSTR`) directly without converting to ANSI (`CP_ACP`), eliminating string translation latency and null-terminator vulnerabilities.
3. **`[return: MarshalAs(UnmanagedType.Bool)]`**: Win32 `BOOL` is a 4-byte `int` (`0` = FALSE, non-zero = TRUE). By default, .NET interop marshals `bool` as a 4-byte integer. Explicitly declaring `UnmanagedType.Bool` ensures accurate condition evaluation.

---

## 4. Pointer Lifecycles, Memory Pinning & Premature Deallocation Hazards

A classic pitfall in native systems engineering is the **premature deallocation hazard**: allocating an unmanaged memory buffer via `Marshal.AllocHGlobal`, passing its address to a native function, and freeing the memory before the operating system kernel has finished reading it.

Consider the initialization of a restricted token in `RestrictedTokenProvider.cs`:

```
+─────────────────────────────────────────────────────────────────────────────+
| PREMATURE DEALLOCATION HAZARD (CORRECTED IN SPLAT)                          |
+─────────────────────────────────────────────────────────────────────────────+
| Managed Heap               Unmanaged Native Memory (HGlobal)                |
|                                                                             |
|  [ adminSid ] ───────────> Address: 0x000001D400501000                      |
|                                   │                                         |
|  [ sidsToDisable ] ──────> Address: 0x000001D400502000                      |
|                            Contains: { Sid = 0x000001D400501000, Attr = 0 } |
|                                   │                                         |
|                                   ▼                                         |
|                     [ CreateRestrictedToken(...) ]                          |
|                                   │                                         |
|  CORRECT TIMING:                  │ Kernel reads both memory blocks         |
|  Marshal.FreeHGlobal(sidsToDisable);                                        |
|  Marshal.FreeHGlobal(adminSid);   │ Safe only in finally block              |
+─────────────────────────────────────────────────────────────────────────────+
```

In `RestrictedTokenProvider.cs`, `adminSid` backs the pointer embedded inside `sidsToDisable`. If `adminSid` were freed immediately after calling `Marshal.StructureToPtr`, the pointer stored inside `sidsToDisable` would point to deallocated memory. When `CreateRestrictedToken` executes in kernel mode, it would encounter an invalid pointer or read corrupt data, failing with `ERROR_INVALID_PARAMETER` (`0x57`) or generating a memory fault. SPLAT wraps all native pointer lifetimes in deterministic `try ... finally` blocks.

---

## 5. The Win32 Process Hardening Sequence

To execute a sensor tool on Windows with zero trust, SPLAT orchestrates an eight-step atomic sequence inside `SuspendedProcessLauncher.cs`:

```
+─────────────────────────────────────────────────────────────────────────────+
| THE WIN32 SUSPENDED SPAWN HARDENING SEQUENCE                                |
+─────────────────────────────────────────────────────────────────────────────+
| 1. CreatePipe(hStdOutRead, hStdOutWrite)                                    |
|    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0)                |
|                                                                             |
| 2. RestrictedTokenProvider:                                                 |
|    - OpenProcessToken(CurrentProcess)                                       |
|    - CreateRestrictedToken(DISABLE_MAX_PRIVILEGE, SidsToDisable=AdminSID)   |
|    - SetTokenInformation(TokenIntegrityLevel = Medium S-1-16-8192)          |
|    - DuplicateTokenEx(SecurityImpersonation, TokenPrimary, bInherit=0)      |
|                                                                             |
| 3. SensorAppContainer (if tool requires no network):                        |
|    - DeriveAppContainerSidFromAppContainerName("SPLAT.Sensor.Container")   |
|    - InitializeProcThreadAttributeList(1 attribute)                         |
|    - UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) |
|      (Capabilities count = 0 -> Complete network severance)                |
|                                                                             |
| 4. CreateProcessAsUserExtendedW:                                            |
|    - dwCreationFlags = CREATE_SUSPENDED (0x04) | CREATE_NO_WINDOW (0x08000000)|
|    - Process created in suspended state; EIP/RIP held at entry point        |
|                                                                             |
| 5. Win32JobSandbox:                                                         |
|    - AssignProcessToJobObject(hJob, pi.hProcess)                            |
|    - Process bound to Job Object clamps BEFORE first instruction runs       |
|                                                                             |
| 6. Close Write Ends of Pipes in Parent:                                     |
|    - CloseHandle(hStdOutWrite), CloseHandle(hStdErrWrite)                   |
|    - Ensures parent reader receives EOF when child process terminates       |
|                                                                             |
| 7. ResumeThread(pi.hThread):                                                |
|    - Kernel schedules thread for execution inside clamps                    |
|                                                                             |
| 8. Asynchronous Stream Drain & WaitForSingleObject                          |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 6. Linux Guest FFI: Async-Signal Safety in Rust `pre_exec`

On the Linux substrate, `splat-agent` must spawn untrusted tool processes under an ephemeral cgroup and drop privileges to `nobody (UID 65534)`.

In Unix systems, spawning a process involves `fork()` followed by `execve()`. In a multithreaded runtime like tokio, calling `fork()` creates an exact duplicate of the calling process, **but only the calling thread survives in the child**. Any mutexes or locks held by other threads at the moment of `fork()` remain permanently locked in the child process.

### The Async-Signal Safety Rule
Between `fork()` and `execve()`, the child process executes within an asynchronous signal context. Calling functions that allocate heap memory (`malloc`), acquire mutexes, or format strings (`println!`) can result in an **immediate deadlock**.

Rust exposes the `pre_exec` hook to run code between `fork` and `execve`. SPLAT's implementation in `native/splat-agent/src/main.rs` strictly utilizes raw, non-allocating, lock-free `libc` syscalls:

```rust
// Pre-computed in the parent process before fork:
let procs = cg.path.join("cgroup.procs");
let procs_c = std::ffi::CString::new(procs.as_os_str().as_bytes())?;

unsafe {
    cmd.pre_exec(move || {
        // 1. Join cgroup v2 subtree by writing "0\n" to cgroup.procs
        let fd = libc::open(procs_c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let joined = libc::write(fd, b"0\n".as_ptr().cast(), 2);
        libc::close(fd);
        if joined != 2 {
            return Err(std::io::Error::last_os_error());
        }

        // 2. Drop privileges to unprivileged UID/GID (nobody: 65534)
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setresgid(wl_gid, wl_gid, wl_gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setresuid(wl_uid, wl_uid, wl_uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    });
}
```

### Why Ordering in `pre_exec` is Mandatory
1. **Writing `cgroup.procs` requires root privilege (`CAP_SYS_ADMIN`)**.
2. **The workload must execute as `nobody`**.
3. If `setresuid` were called *before* opening `cgroup.procs`, the `libc::open` call would fail with `-EACCES` (Permission Denied), because `nobody` cannot modify the root cgroup hierarchy.
4. If `Command::uid()` were used instead, the Rust standard library would apply the UID drop *before* executing `pre_exec`. Therefore, both operations must be performed explicitly inside `pre_exec` in exact chronological sequence.

---

## 7. Line-by-Line Code Breakdown: Containment FFI

### 7.1 Low-Privilege Token Creation (`RestrictedTokenProvider.cs`)

```csharp
// Lines 36-50: Administrative SID Neutralization
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
```
*Architectural Rationale:* `DISABLE_MAX_PRIVILEGE` removes privileges from the token, but does not alter group memberships. If an elevated administrator runs SPLAT, the tool process would retain the Administrators group SID (`S-1-5-32-544`). Marking the SID in `SidsToDisable` sets the `SE_GROUP_USE_FOR_DENY_ONLY` attribute. The operating system Object Manager will use this SID solely to *deny* access to ACLs that explicitly forbid administrators, but will never use it to *grant* access.

```csharp
// Lines 59-68: Non-Inheritable Primary Token Duplication
var sa = new Win32Interop.SECURITY_ATTRIBUTES
{
    nLength = Marshal.SizeOf(typeof(Win32Interop.SECURITY_ATTRIBUTES)),
    bInheritHandle = 0 // DELIBERATELY NON-INHERITABLE
};

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
```
*Architectural Rationale:* When creating a process with redirected pipes, `bInheritHandles` must be set to `true` so the child can inherit standard input/output pipes. If the restricted primary token handle were also inheritable (`bInheritHandle = 1`), the sandboxed child would inherit an open `TOKEN_ALL_ACCESS` handle to its own process token, allowing a sophisticated adversary to manipulate token defaults. Setting `bInheritHandle = 0` prevents token handle leakage into the child.

---

## 8. Step-by-Step Numerical Walkthrough: Register States During Syscall Invocations

The table below illustrates the x64 register contents immediately prior to executing the `syscall` instruction for `NtSetInformationJobObject` on Windows 11:

| Register | Value (Hex) | Semantic Role |
| :---: | :--- | :--- |
| **`RAX`** | `0x0000000000000028` | System Call Index (SSN: System Service Number for `NtSetInformationJobObject`) |
| **`RCX`** | `0x00000000000001B0` | Argument 1: `JobHandle` (`0x1B0`) |
| **`RDX`** | `0x0000000000000009` | Argument 2: `JobObjectInformationClass` (`JobObjectExtendedLimitInformation = 9`) |
| **`R8`** | `0x000001D4A0108000` | Argument 3: Pointer to `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` buffer |
| **`R9`** | `0x0000000000000070` | Argument 4: Buffer Length (`sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) = 112 bytes = 0x70`) |
| **`RSP`** | `0x000000E0801FEF88` | Stack Pointer (Allocated shadow space present at `[RSP+0x00]` to `[RSP+0x20]`) |

---

## 9. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 3.1: The Breakaway Sandbox Escape
**Scenario:** A developer notices that a command containing `powershell.exe -Command "Start-Process calc.exe"` fails because child processes are clamped by the Job Object's active process limit. To make child process creation smoother, the developer adds `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` (`0x00001000`) to `LimitFlags`.
- **Question:** What catastrophic security vulnerability was introduced by enabling silent breakaway?
- **Solution:** `SILENT_BREAKAWAY_OK` instructs the Windows kernel object manager that any process created by a member of the Job Object will be automatically spawned *outside* the Job Object. A compromised agent can escape the sandbox entirely simply by executing `Start-Process payload.exe`. The spawned process executes completely unconfined, unaffected by CPU clamps, RAM limits, or `TerminateJobObject`. Containment job objects must never set breakaway flags.

### Checkpoint 3.2: The Inherited Standard Input Deadlock
**Scenario:** A developer modifies `WslLeasedExecutor` to bootstrap `splat-agent` in the background by calling `wsl.exe -u root ...` but sets `RedirectStandardInput = false`. When `splat-mcp` handles multiple requests from an agent client, the connection freezes after the 5th request.
- **Question:** How did setting `RedirectStandardInput = false` on a background `wsl.exe` process corrupt an stdio JSON-RPC stream running on the host?
- **Solution:** When `RedirectStandardInput` is `false`, the child `wsl.exe` process inherits the standard input handle of `splat-mcp`. In an MCP server, `splat-mcp`'s standard input *is the JSON-RPC channel from the client*. As the client transmits subsequent JSON-RPC requests, the background `wsl.exe` process concurrently reads bytes from the shared pipe buffer, consuming fragments of the client's messages. This truncates the JSON payloads received by `splat-mcp`, causing deserialization failures and deadlocks. Background bridge helpers must always redirect or close standard input.
