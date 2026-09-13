# Volume 06: Memory Management & Ownership Universes

## Master Table of Contents
1. [The Tri-Language Memory Model](#1-the-tri-language-memory-model)
2. [C & eBPF Kernel Memory: Stack Ceilings & Direct Memory Mapping](#2-c--ebpf-kernel-memory-stack-ceilings--direct-memory-mapping)
3. [Rust Ownership & Lifecycles: The Affine Type System in Resident Daemons](#3-rust-ownership--lifecycles-the-affine-type-system-in-resident-daemons)
4. [.NET 10 Generational GC: Tracing, Pinning & Large Object Heaps](#4-net-10-generational-gc-tracing-pinning--large-object-heaps)
5. [Kernel-Enforced Memory Clamps: Win32 Job Objects vs. Linux Cgroup v2](#5-kernel-enforced-memory-clamps-win32-job-objects-vs-linux-cgroup-v2)
6. [SQLite Storage Memory & Secure Cryptographic Erasure](#6-sqlite-storage-memory--secure-cryptographic-erasure)
7. [Line-by-Line Code Breakdown: Memory Lifecycles](#7-line-by-line-code-breakdown-memory-lifecycles)
8. [Step-by-Step Numerical Walkthrough: Virtual Memory Allocations & Page Boundaries](#8-step-by-step-numerical-walkthrough-virtual-memory-allocations--page-boundaries)
9. [Interactive University Checkpoints & Debugging Puzzles](#9-interactive-university-checkpoints--debugging-puzzles)

---

## 1. The Tri-Language Memory Model

Building a high-assurance agent containment runtime requires harmonizing three radically distinct memory management universes:

```
+─────────────────────────────────────────────────────────────────────────────+
| THREE CO-EXISTING MEMORY UNIVERSES IN SPLAT                                 |
+─────────────────────────────────────────────────────────────────────────────+
|                                                                             |
|  1. C & eBPF (Kernel Space)                                                 |
|     - Manual stack/heap management.                                         |
|     - HARD 512-BYTE BPF STACK CEILING.                                      |
|     - Direct pointer dereferencing prohibited; all kernel memory reads      |
|       must pass through BPF_CORE_READ() / bpf_probe_read_kernel().          |
|                                                                             |
|  2. Rust (Linux Resident Daemon)                                            |
|     - Compile-time affine ownership system (Borrow Checker).                |
|     - Zero-cost abstractions, RAII (Resource Acquisition Is Initialization).|
|     - Thread-safe reference counting via Arc<T> & interior mutability.      |
|     - Explicit unsafe blocks for raw libc calls and Box::leak static pins.  |
|                                                                             |
|  3. C# (.NET 10 CLR - Windows Host & MCP Server)                            |
|     - Automatic tracing garbage collection across generational heaps.       |
|     - Non-deterministic object finalization.                                |
|     - Memory compaction requiring explicit pointer pinning (GCHandle/fixed) |
|       during unmanaged Win32 P/Invoke transitions.                          |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. C & eBPF Kernel Memory: Stack Ceilings & Direct Memory Mapping

In standard C application development, functions allocate stack frames with arbitrary local arrays. In eBPF, however, the kernel verifier enforces a **strict 512-byte stack limit per program**:

```
Max Stack Frame Size <= 512 Bytes
```

If a BPF program declares local variables exceeding 512 bytes, the kernel verifier rejects the program during `bpf_prog_load()` with `BpfVerifierError: lookahead stack overflow`.

### SPLAT Stack Optimization in `lease_lsm.bpf.c`
To operate safely within this limit, `lease_lsm.bpf.c` never allocates buffers on the stack. Large structures are allocated either directly in kernel BPF maps or reserved in-place inside the ring buffer:

```c
// Struct size: 24 bytes (Fits comfortably within 512-byte stack)
struct lease_inode_key k = lease_inode_key_of(cgid, inode);

// In-place reservation: returns pointer to pre-allocated ring buffer page
// ZERO stack memory consumed for the 36-byte event payload!
struct violation_event *e = bpf_ringbuf_reserve(&violations, sizeof(*e), 0);
```

### Relocatable Memory Reads via CO-RE
In traditional Linux kernel modules, dereferencing `inode->i_sb->s_dev` reads an offset defined at kernel compile time. If kernel struct layouts shift across minor releases, module offsets break.

SPLAT uses BPF CO-RE (Compile Once – Run Everywhere) powered by BTF (BPF Type Format). The macro `BPF_CORE_READ()` emits relocation records evaluated by `libbpf` at load time against the host kernel's `/sys/kernel/btf/vmlinux`:

```c
// Emits BTF relocation: automatically computes dynamic offset of s_dev
k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
```

---

## 3. Rust Ownership & Lifecycles: The Affine Type System in Resident Daemons

In `native/splat-agent/src/main.rs`, the resident daemon must manage concurrent leases without leaking memory or triggering race conditions.

### Thread-Safe Shared State via `Arc<T>` and Mutex
The daemon maintains a collection of active leases across multiple tokio tasks (TCP listener, client handlers, and the 1-second reaper):

```rust
// Arc (Atomic Reference Counter) provides shared heap ownership across threads
let mgr = lease_manager.clone();
let viol_tx_clone = viol_tx.clone();

tokio::spawn(async move {
    // Ownership transferred into async task
    handle_client(socket, mgr, viol_tx_clone, auth, workload_ids).await
});
```

### The `Box::leak` Pattern for Static BPF Skeletons
In `libbpf-rs`, attached BPF skeletons require a `'static` lifetime to ensure that event listeners and background ring buffer pollers can access skeleton maps for the entire lifetime of the process. SPLAT uses `Box::leak`:

```rust
let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
let skel = Box::leak(Box::new(skel));
```
`Box::leak` intentionally bypasses Rust's automatic deallocation, converting a heap allocation into a `'static` raw pointer reference. This is mathematically correct because the daemon's kernel hooks must remain resident until the daemon process terminates.

---

## 4. .NET 10 Generational GC: Tracing, Pinning & Large Object Heaps

On the Windows host, `MissionController` runs on the .NET 10 Common Language Runtime (CLR). The CLR manages memory across four primary heap regions:

```
+─────────────────────────────────────────────────────────────────────────────+
| .NET 10 MANAGED HEAP ARCHITECTURE                                          |
+─────────────────────────────────────────────────────────────────────────────+
|                                                                             |
|  Generation 0 (Gen 0): Ephemeral short-lived allocations (Strings, Task DTOs)|
|  Generation 1 (Gen 1): Buffer zone surviving Gen 0 collections              |
|  Generation 2 (Gen 2): Long-lived objects (Singletons, Storage Context)      |
|  Large Object Heap (LOH): Objects >= 85,000 bytes (Large buffers, images)   |
|  Pinned Object Heap (POH): Memory pinned at fixed physical virtual addresses|
+─────────────────────────────────────────────────────────────────────────────+
```

### The Compaction & Pinning Challenge
During a Gen 2 garbage collection cycle, the CLR performs **memory compaction**: it moves live objects together to eliminate fragmentation, updating internal object references.

If unmanaged code (such as a Win32 API) is holding a pointer to a managed byte array when compaction occurs, the pointer becomes an invalid **dangling pointer**:

```
BEFORE GC COMPACTION:
  Native Pointer points to: [ Object Data at Address 0x1000 ]
  
GC COMPACTION OCCURS:
  CLR moves Object Data to Address 0x2000!
  
AFTER GC COMPACTION:
  Native Pointer STILL points to Address 0x1000 (NOW CORRUPT MEMORY)!
```

### SPLAT Mitigation: Unmanaged Allocation via `Marshal.AllocHGlobal`
Rather than pinning managed objects with `GCHandle.Alloc(..., GCHandleType.Pinned)`, SPLAT allocates memory for unmanaged Win32 structures outside the CLR heap entirely using unmanaged virtual memory allocations:

```csharp
IntPtr pLimits = Marshal.AllocHGlobal(length);
try
{
    Marshal.StructureToPtr(extendedLimits, pLimits, false);
    Win32Interop.SetInformationJobObject(_jobHandle, ..., pLimits, ...);
}
finally
{
    Marshal.FreeHGlobal(pLimits); // Deterministic deallocation
}
```

---

## 5. Kernel-Enforced Memory Clamps: Win32 Job Objects vs. Linux Cgroup v2

A primary directive of SPLAT is that **memory containment must be enforced by the kernel**, not by application-level metrics monitoring.

```
+─────────────────────────────────────────────────────────────────────────────+
| COMPARATIVE KERNEL MEMORY CONTAINMENT                                       |
+─────────────────────────────────────────────────────────────────────────────+
|                                                                             |
|  Property               Windows Win32 Job Object    Linux Cgroup v2         |
|  ───────────────────    ────────────────────────    ─────────────────────── |
|  Enforcement Layer      NT Object Manager / MM      VFS / Cgroup Controller |
|  Configuration Node     SetInformationJobObject     /sys/fs/cgroup/...      |
|  Limit Metric           JobMemoryLimit (Bytes)      memory.max (Bytes)      |
|  Action on Limit        Process allocation fails    Out-Of-Memory (OOM)     |
|                         (STATUS_QUOTA_EXCEEDED)     Killer terminates PID   |
|  Hierarchical Control   Nested Job Objects (Win 8+) Unified Cgroup v2 Tree  |
|  Default Clamp          256 MB (268,435,456 B)      256 MB                  |
+─────────────────────────────────────────────────────────────────────────────+
```

### Read-Back Validation Invariant
In `cgroup.rs`, SPLAT introduces an essential systems invariant: **limits must be read back from the kernel controller after writing**.

If a host kernel has disabled swap or memory accounting, writing to `memory.max` might be ignored. SPLAT reads back the effective limit from `/sys/fs/cgroup/.../memory.max`. If the read-back value does not match the requested limit, the mission launch is refused.

---

## 6. SQLite Storage Memory & Secure Cryptographic Erasure

The audit ledger database (`SqliteStorageContext.cs`) manages disk and memory caching through SQLite's Write-Ahead Logging (WAL) engine.

### GDPR & Cryptographic Erasure Architecture
In enterprise operations, data retention policies mandate that sensitive payload parameters be erased after 90 days. However, in a standard SHA-256 hash chain:

```
H_n = SHA-256(H_{n-1} || Timestamp || Payload)
```

Erasing `Payload` breaks the hash chain, causing every subsequent verification check to fail!

SPLAT resolves this in `SqliteChainedAuditLedger.cs` using **Version 2 Salted Commitments**:

```
ENTRY HASH GENERATION (VERSION 2):
  1. Generate 256-bit cryptographically secure random salt:
     detailsSalt = RandomNumberGenerator.GetBytes(32);

  2. Compute deterministic commitment:
     detailsCommitment = SHA-256(detailsSalt || RawDetails);

  3. Commit entry hash over the COMMITMENT, not the plaintext:
     entryHash = SHA-256(prevHash || timestamp || missionId || detailsCommitment);
```

### Secure Purging
When data retention expires:
1. SPLAT overwrites `Details` and `DetailsSalt` with zeroes.
2. `detailsCommitment` is preserved.
3. When `VerifyLedgerIntegrityAsync()` recalculates `entryHash`, it hashes `detailsCommitment`. The verification passes with zero errors, while the underlying plaintext payload is permanently and non-invertibly erased!

---

## 7. Line-by-Line Code Breakdown: Memory Lifecycles

### 7.1 Ephemeral Cgroup Limit Configuration (`native/splat-agent/src/cgroup.rs`)

```rust
// Lines 80-92: Atomic Limit Writing & Read-Back Verification
pub fn apply_limits(&self, limits: &LeaseLimits) -> Result<()> {
    // 1. Write memory ceiling (e.g., 268435456 bytes = 256 MB)
    let mem_file = self.path.join("memory.max");
    std::fs::write(&mem_file, format!("{}\n", limits.max_memory_bytes))
        .with_context(|| format!("write {}", mem_file.display()))?;

    // 2. Read back effective limit from kernel object manager
    let read_back = std::fs::read_to_string(&mem_file)?;
    let effective_bytes: u64 = read_back.trim().parse()
        .context("parse memory.max")?;

    if effective_bytes != limits.max_memory_bytes {
        bail!("Kernel refused memory limit: requested {}, got {}",
              limits.max_memory_bytes, effective_bytes);
    }
    Ok(())
}
```
*Architectural Rationale:* The code does not trust that writing to `/sys/fs/cgroup` succeeded simply because `write()` returned. It immediately reads back the value from the kernel controller. If the operating system failed to enforce the boundary, the function throws an error, causing the daemon to fail closed.

---

## 8. Step-by-Step Numerical Walkthrough: Virtual Memory Allocations & Page Boundaries

Consider a 256 MB memory allocation for a tool executing inside a Win32 Job Object on an x86-64 CPU (4 KiB physical page size = `4,096` bytes):

- **Memory Cap:** $256 \times 1024 \times 1024 = 268,435,456 \ \text{Bytes}$
- **Total Virtual Pages:** $\frac{268,435,456}{4,096} = 65,536 \ \text{Pages}$ (`0x10000` Pages)

| Page Index | Virtual Address Range | Page State | Hardware MMU Translation |
| :---: | :--- | :--- | :--- |
| `0x0000` | `0x00007FFF00000000 - 0x00007FFF00000FFF` | Committed (R/W) | Page Table Entry (PTE) points to Physical Frame `0x3A12` |
| `0x0001` | `0x00007FFF00001000 - 0x00007FFF00001FFF` | Committed (R/W) | PTE points to Physical Frame `0x4B21` |
| ... | ... | ... | ... |
| `0xFFFF` | `0x00007FFFFFFF0000 - 0x00007FFFFFFFFFFF` | Committed (R/W) | 65,536th Page: Working Set Limit Reached! |
| `0x10000`| `0x0000800000000000` | Allocation Fault | **Hard Fault:** `STATUS_QUOTA_EXCEEDED` (`0xC0000044`). Kernel terminates process! |

---

## 9. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 6.1: The SQLite WAL File Space Leak
**Scenario:** An administrator runs `DELETE FROM AuditLedger WHERE Timestamp < '2025-01-01';` to purge old data. However, the `audit_ledger.db` and `audit_ledger.db-wal` files on disk do not decrease in size by even a single byte. Furthermore, opening the `.db` file in a hex editor reveals that deleted parameter strings are still readable in plaintext.
- **Question:** Why did running `DELETE` fail to reclaim disk space or erase plaintext bytes, and how does SPLAT guarantee true cryptographic deletion?
- **Solution:** SQLite does not return deleted pages to the operating system; it marks them as free pages in an internal freelist for reuse. Moreover, in WAL mode, transactions are appended to the `-wal` sidecar file without modifying the main database pages. To ensure true erasure, SPLAT executes:
  1. `PRAGMA secure_delete = ON;` (Forces SQLite to overwrite deleted payload bytes with zeroes).
  2. `PRAGMA wal_checkpoint(TRUNCATE);` (Flushes WAL pages to the main DB and truncates the WAL file).
  3. `VACUUM;` (Rebuilds the database file, releasing empty pages back to the host filesystem).

### Checkpoint 6.2: The Dangling Pointer GC Race
**Scenario:** A developer attempts to pass a managed `byte[]` buffer directly to a native C function:
```csharp
byte[] buffer = new byte[1024];
IntPtr ptr = (IntPtr)(&buffer[0]); // Unsafe pointer dereference without pinning!
NativeMethod(ptr);
```
Under light test loads, the code works. Under heavy production loads with multiple parallel missions, the program crashes with access violations or data corruption.
- **Question:** What occurred in the CLR during heavy production loads that broke the pointer?
- **Solution:** Under heavy load, memory allocations trigger a Gen 0 or Gen 1 garbage collection. Because `buffer` was not pinned using a `fixed (byte* p = buffer)` block or a `GCHandle.Alloc(buffer, GCHandleType.Pinned)`, the CLR GC compacted the heap, moving `buffer` to a new physical address. `ptr` continued to point to the old address, causing `NativeMethod` to write data into whatever new object the CLR relocated into that memory slot.
