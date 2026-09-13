# Week 2 — memory, ownership and ABI

## Lesson A: who owns a resource?

**Outcome:** separate managed memory lifetime from native resource lifetime.

Registers and caches reduce the time to access data; RAM holds a process's active working set. Cache locality affects speed, but this repository contains no proof that a particular cache behavior explains its launch overhead. Measure before assigning a cause.

Virtual memory is divided into pages. Page tables define mappings and access permissions; an access may fault and require OS handling. Stack frames hold call-related state, while longer-lived managed objects commonly reside on the managed heap. Neither a memory limit nor a garbage collector is a replacement for page permissions or kernel privilege separation.

The C# garbage collector reclaims unreachable managed objects. An OS handle represents a separate resource: a file, process, pipe or Job Object. Collecting its wrapper is not a timely cleanup protocol. Follow using, SafeFileHandle, Dispose and finally in [SuspendedProcessLauncher](../../src/MissionController.Infrastructure.Windows/SuspendedProcessLauncher.cs).

Rust ownership and Drop make ordinary resource cleanup more explicit, but raw handles, unsafe blocks and asynchronous task lifetimes still require reasoning. A process can outlive the task waiting for it. A lock protects access to state; it does not automatically terminate the resource that state describes.

## Lesson B: layout is an agreement between programs

**Outcome:** calculate a shared structure's width and offsets.

The BPF map compares bytes. Its lease_ipv4_key contains an eight-byte cgroup ID, four-byte address, two-byte port and two-byte padding field. Rust's LeaseIpv4Key uses repr(C) and a size assertion. Read both [C](../../native/splat-agent/src/bpf/lease_lsm.bpf.c) and [Rust](../../native/splat-agent/src/lease.rs): two structures with similar names are not enough; their bytes must agree. The [Rust layout reference](https://doc.rust-lang.org/reference/type-layout.html) defines what each representation guarantees.

Padding is part of a raw map key. If one producer leaves it indeterminate, an otherwise identical key can miss. Ports are in network byte order. Also inspect kernel_dev_from_st_dev: user-space and kernel device-number encodings differ.

A failed lookup is asymmetric: an executable missing from an allow-list is denied; a protected file missing from a deny-list may be allowed. This turns a low-level ABI error into a security error.

## Lab: model the actual boundary

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab -LabMode representation
rg -n 'LeaseIpv4Key|size_of|kernel_dev_from_st_dev' native/splat-agent/src/lease.rs
rg -n 'SafeFileHandle|CloseHandle|finally|Dispose' src/MissionController.Infrastructure.Windows
~~~

1. Draw the 16-byte key with offsets 0, 8, 12 and 14.
2. Compare it with the course's LeaseIpv4Layout. Explain why that C# model is not the JSON wire protocol.
3. Make a private fixture change that widens Port to uint; adjust no assertions. Record which assertion catches drift.
4. Restore the fixture and add a padding-offset assertion.
5. Select one stdout pipe handle and list its creator, owner transfer and release on success, failed launch and cancellation.

Expected: layout drift breaks the fixture assertion; a correct layout passes. Do not patch generated vmlinux.h.

**Cybersecurity case:** memory safety prevents some corruption; it does not establish correct authorization. A type-safe map lookup using the wrong bytes can still miss a protected object.

**Repair practice:** propose a narrow additional Rust offset/layout regression, or a handle-lifetime regression around a failed launch. Explain which failure it catches that successful process creation cannot.

**Submit:** byte-layout table and three-path ownership trace.

**Check yourself:** Does GC promptly close a native process handle? Is a deny-list lookup miss always safe?

**Answer checkpoint:** neither. Use explicit lifetime management, and interpret lookup failure according to whether the table grants or denies authority.
