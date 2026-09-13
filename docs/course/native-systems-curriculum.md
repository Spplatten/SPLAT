# SPLAT systems curriculum: from byte layout to kernel enforcement

Understand the existing SPLAT engine by isolating the mechanisms it depends on. Use Antigravity as the editor and debugger for small C/Rust experiments, then trace each result back to the production implementation. Every harness answers a specific SPLAT question.

**Format:** five levels over ten weeks, approximately 6–8 hours per week. Each level has two lessons, two practical sessions, an explanation checkpoint, and a passing gate. Advance when the gate passes; use the schedule as a guide.

**Starting knowledge:** variables, functions, loops, terminal commands, and basic Git. Before Level 0, practice pointers, arrays, hexadecimal notation, compiler diagnostics, and reading a C function alongside its Rust equivalent.

**Outcome:** explain and test the complete path from a C# execution request to Linux admission, kernel enforcement, telemetry, expiry, and the returned result. The exercises below are assignments; preparing this curriculum did not implement or execute them.

## Course map

| Weeks | Level | Main harness | Question it answers |
| --- | --- | --- | --- |
| 1–2 | 0. Silicon, struct alignment, and bitwise operations | C device encoder and C/Rust ABI comparison | Do both sides mean the same thing by these bytes? |
| 3–4 | 1. Process lifecycle and capability jails | C fork/join/drop/exec launcher | Is the workload constrained when its initial exec is checked? |
| 5–6 | 2. Memory visibility and ring buffers | C11 SPSC queue, followed by BPF ringbuf observation | When can another execution context safely consume an event? |
| 7–8 | 3. IPC and the last hop | Framed C Unix socket client/server, Rust peer, and VSOCK extension | Does the intended request cross the boundary with its authority intact? |
| 9–10 | 4. BPF-LSM and integration | Minimal BPF-LSM program, libbpf loader, and end-to-end capstone | Does the kernel deny the intended operation and report the correct outcome? |

The broader [SPLAT course](README.md) supplies surrounding C#, storage, application, and architecture lessons. This track concentrates on the five native mechanisms in this curriculum.

## Prepare the wind tunnel

Use an isolated Linux VM or suitable WSL2 guest for Linux-specific work. Antigravity edits and debugs the harnesses; the guest's actual kernel determines which experiments are supported. Record the architecture, kernel release, compiler, Rust toolchain, and source revision with every run.

Have a C compiler, Rust/Cargo, a debugger, `readelf` or `llvm-readelf`, `objdump` or `llvm-objdump`, and `strace`. Levels 2 and 4 additionally need BPF-capable Clang, libbpf, and bpftool. Start with ordinary user-space exercises. Before live kernel exercises, establish cgroup v2 controller availability, BTF availability, BPF-LSM configuration and activation, and the necessary guest permissions. Distinguish unavailable prerequisites from an executed failure. The kernel documents [BPF-LSM loading and attachment](https://docs.kernel.org/bpf/prog_lsm.html) and [cgroup v2 configuration](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Keep each experiment in a separate lab directory. For every lab: predict the result, state one invariant, implement the smallest harness, deliberately violate the invariant, compare observations, and identify the corresponding SPLAT code. Preserve deliberately faulty examples only as teaching fixtures.

## Level 0 — Silicon, struct alignment, and bitwise operations

**Learning objective:** derive the exact bytes used by a policy map key and explain why a numerically plausible value can still fail its lookup.

**Lesson A: numbers become bytes.** Study bits, CPU registers versus memory, unsigned integer widths, shifts, masks, hexadecimal, and byte order. Compare a small C bitwise function with its generated instructions. Separate a value's bit-field encoding from the order in which its bytes are stored. Include signed-shift hazards and shifts equal to or wider than the operand.

**Lesson B: bytes become shared structures.** Study `sizeof`, alignment, field offsets, internal and trailing padding, C `_Static_assert`, Rust `#[repr(C)]`, and initialized object representations. A BPF map key is compared as bytes; a correct field list alone does not establish layout compatibility.

**Correct the device-number model first.** For the Linux/glibc representation relevant here, glibc `dev_t` is 64-bit; the kernel's internal `dev_t` is 32-bit. Kernel `s_dev` uses `(major << 20) | minor`. The important mismatch is the encoding, as well as the width. Decode userspace `st_dev` with `major()` and `minor()`, then construct the kernel form within its supported range. An inode is a separate identity component, not another field to squeeze into that device value. See [glibc's encoding](https://raw.githubusercontent.com/bminor/glibc/master/bits/sysmacros.h), [kernel device types](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/types.h), and [kernel device packing](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/kdev_t.h).

**Antigravity harnesses:**

1. Write `device_bits.c` to pack and unpack values with `<<`, `>>`, `|`, and `&`. Compare its userspace encoding against `makedev()`, then convert a real file's device identity. Include synthetic major/minor boundary values and reject values outside the target kernel representation.
2. Use major 8, minor 1 as a worked case: userspace encoding `0x0000000000000801`, internal kernel encoding `0x00800001`. Display both integer values and their byte dumps. Serialize a separate 64-bit inode and verify that high inode bits survive.
3. Mirror SPLAT's `LeaseInodeKey` in C and Rust. On the target ABI, verify its 24-byte size and offsets: cgroup ID 0, inode 8, device 16, explicit padding 20. Check alignment and byte-for-byte equality using initialized fields; compare the companion 16-byte IPv4 key too.
4. Define a teaching `uint64_t` capability mask with distinct exec/open/connect bits. Implement grant, revoke, membership, and subset checks. Exercise bit 63, reject unknown bits, and distinguish “all required bits present” from “any bit present.” This is a policy-model exercise; it is neither a CPU hardware register nor the Linux capability API, and SPLAT currently uses policy maps for these decisions.

**Failure experiments:** pass raw `st_dev` into the kernel-key fixture; reorder a field; change one padding byte; truncate an inode. Show why the same lookup miss can deny an allowed executable while failing to recognize a protected file.

**Pass gate:** C and Rust produce identical complete keys; boundary conversions round-trip within the stated domain; mask tests pass; every deliberate mismatch is detected. Submit an offset table, byte dumps, assertions, and a short derivation of the conversion.

**SPLAT connection:** [lease.rs](../../native/splat-agent/src/lease.rs), especially `kernel_dev_from_st_dev`, `LeaseInodeKey`, and `LeaseIpv4Key`; compare them with the structures and lookup construction in [lease_lsm.bpf.c](../../native/splat-agent/src/bpf/lease_lsm.bpf.c).

**Explanation checkpoint:** Why can widening an incorrectly encoded device value to 64 bits leave the bug completely unchanged?

## Level 1 — Process lifecycle and capability jails

**Learning objective:** demonstrate the ordering that prevents a workload from reaching its first exec check outside its lease.

**Lesson A: process creation and execution.** Study `fork()`, copy-on-write, inherited descriptors, `execve()`, `argv`/environment ownership, exit status, signals, and `waitpid()`. After fork in a multithreaded process, inherited locks make ordinary allocation and logging unsafe before exec. Read [fork's restrictions](https://man7.org/linux/man-pages/man2/fork.2.html) alongside [Rust's `pre_exec` contract](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html).

**Lesson B: distinct isolation mechanisms.** Cgroups organize workloads and enforce enabled resource controls. Namespaces change which resources processes see. Credentials and Linux capabilities determine privileges. Study mount, PID, user, and network namespaces; effective/permitted/inheritable/ambient/bounding capability sets; supplementary groups; and `no_new_privs`. None of these mechanisms alone establishes every sandbox property. See [namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html) and [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).

**Antigravity harnesses:**

1. Write `launch_jail.c`. Prepare a dedicated cgroup v2 subtree, delegated controllers, resource limits, arguments, descriptors, and synchronization pipes before forking.
2. First implement parent-managed attachment: hold the child on a pipe; write its PID to the dedicated `cgroup.procs`; verify membership and setup; release the child only after admission succeeds. Compare this with child-managed attachment by writing `0` to its target `cgroup.procs` before exec. Fork inheritance and migration semantics are specified in the [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
3. Before exec, clear supplementary groups, set the intended GID and UID, establish the capability/no-new-privileges policy, and close unwanted descriptors. Determine which capability changes require privilege before dropping it. Abort on every setup error. Use an error pipe to distinguish setup failure from a successfully executed program's exit code.
4. Translate the minimal child setup into Rust `pre_exec`. Precompute memory and paths in the parent. Keep the child path free of allocation, locks, formatting, and unwinding; check complete writes and all syscall results.
5. Add one namespace experiment at a time. Compare `/proc` namespace identifiers and visible resources. Account for UID/GID mapping rules and the separate group-handling rules of user namespaces.

**Failure experiments:** introduce a controlled parent-attachment delay and observe the unsafe launch variant; deny a cgroup write; remove controller delegation; fail the identity drop; inherit an unwanted descriptor; launch a child that forks a grandchild. Verify limits by reading them back and measuring the relevant effect.

**Pass gate:** an entry probe confirms the intended cgroup and credentials; setup failure produces zero payload marker writes; descendants stay in the intended subtree; cancellation and expiry stop the workload tree and reap owned children. A `main()` marker is supporting evidence, not proof about every earlier instruction. Level 4 supplies the initial-exec kernel observation.

**Precise guarantee:** trusted launcher code necessarily executes after fork. The target is to establish containment before `execve()` admits the new workload image, including execution before `main()`. A cgroup move by itself does not enable BPF policy.

**SPLAT connection:** the launch closure in [main.rs](../../native/splat-agent/src/main.rs), membership and cleanup in [cgroup.rs](../../native/splat-agent/src/cgroup.rs), and lease expiry in [lease.rs](../../native/splat-agent/src/lease.rs).

**Explanation checkpoint:** Why is attaching the PID after `spawn()` returns too late to govern that program's initial exec?

## Level 2 — Memory visibility and ring buffers

**Learning objective:** explain publication, consumption, safe slot reuse, and observable event loss without relying on “the CPU probably executes this in order.”

**Lesson A: the memory model.** Study cache coherence, false sharing, atomics, data races, and happens-before relationships. A release publication can make earlier payload writes visible to an acquiring consumer that observes it. A second release/acquire relationship protects slot reuse after consumption. `volatile` is not a thread-synchronization mechanism. Use [Rust's atomic ordering reference](https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html) to compare the Rust implementation with the C11 model.

**Lesson B: queue mechanics.** Study power-of-two capacities, head/tail ownership, full/empty states, wraparound, bounded operations, shutdown, and overflow policy. Put producer and consumer counters on separately aligned regions using C11 `alignas(64)`; measure the machine's actual cache-line assumptions. Check whether the chosen atomic type is lock-free on the target before claiming a lock-free implementation.

**Antigravity harnesses:**

1. Write `spsc_ring.c` with exactly one producer and one consumer. Write a slot, then release-publish the producer position. Acquire the published position before reading the slot. Release the consumer position after reading, and acquire it before producer reuse.
2. Send numbered records with checksums. Exercise full/empty transitions, repeated wraparound, unequal producer/consumer rates, stop requests, and a specified drop-or-backpressure policy.
3. Port the queue to Rust with explicit unsafe ownership reasoning. Compare padded and unpadded layouts under the same workload; report throughput, latency percentiles, CPU use, and losses separately.
4. Inspect the production BPF event layout and consumer. After Level 4 provides a live producer, repeat overflow experiments with the actual kernel ring buffer.

**Correct the BPF analogy.** `BPF_MAP_TYPE_RINGBUF` supports multiple producers and one consumer. Its reservation path uses a spinlock; it is not the same algorithm as this SPSC queue. Reservations can fail, and an earlier uncommitted reservation can delay later records. Reserve/submit allows in-place event construction; the output helper copies data. Learn exactly which copy is avoided before using “zero-copy.” The [kernel ring-buffer design](https://docs.kernel.org/bpf/ringbuf.html) describes these distinctions.

**Failure experiments:** remove an ordering edge in a teaching fixture; run a race detector and explain its limits; force overflow; stop the consumer; vary scheduling and, where available, architecture. A faulty variant need not fail visibly on every run. Analyze the missing synchronization even when a stress test appears to pass.

**Pass gate:** all accepted records arrive intact, once, and in the specified order; overflow accounting reconciles attempts, accepted records, and drops; shutdown completes. Explain both publication and reuse ordering. When the live BPF exercise runs, denial must still occur even when its telemetry record cannot be reserved.

**SPLAT connection:** `violation_event`, `report`, and `violations` in [lease_lsm.bpf.c](../../native/splat-agent/src/bpf/lease_lsm.bpf.c), plus [violation.rs](../../native/splat-agent/src/violation.rs) and the daemon's ring-buffer drain in [main.rs](../../native/splat-agent/src/main.rs).

**Explanation checkpoint:** Why does a missing violation event fail to establish that the kernel allowed the operation?

## Level 3 — IPC and the last hop

**Learning objective:** preserve bytes, request meaning, caller authority, deadlines, and truthful outcomes across process and VM boundaries.

**Lesson A: stream protocols.** Study Unix domain sockets, `socket/bind/listen/accept/connect`, partial reads/writes, `EINTR`, EOF, backpressure, and framing. A stream does not preserve application-message boundaries. Define serialization independently of native structs: explicit widths, byte order, version, length, request ID, command path, argument vector, lease duration, and bounded field sizes. Never transmit pointers, implicit padding, or a shell command assembled from arguments. See [Unix domain socket semantics](https://man7.org/linux/man-pages/man7/unix.7.html).

**Lesson B: transport and authority.** Authenticate the peer and authorize the requested lease before starting work. Linux `SO_PEERCRED` supplies connection-time process credentials; a UID alone does not distinguish every application running as that user. VSOCK addresses VM endpoints through CIDs and ports; it does not by itself authenticate a particular controller process. A local Unix socket demonstration does not establish a VM crossing. See [Unix peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html) and [VSOCK addressing](https://man7.org/linux/man-pages/man7/vsock.7.html).

**Antigravity harnesses:**

1. Build a C Unix socket client/server with a bounded length-prefixed protocol. Begin with a decoder that records requests without executing them, then connect it to Level 1's launcher. Define explicit encoding and maximum sizes for every string and list.
2. Write a Rust peer and golden wire fixtures; add a small C# client using the same fixtures. Preserve arguments containing spaces and Unicode. Define rejection behavior for NULs, invalid encoding, malformed lengths, unsupported versions, and excessive lease durations.
3. Have the daemon derive a local monotonic deadline from the authorized duration. Define duplicate-request, disconnect, cancellation, and timeout behavior. A lost reply can leave execution uncertain; retries must not silently launch duplicate work.
4. Repeat the transport experiment across an actual supported VM boundary. For Windows/Hyper-V, study the host `AF_HYPERV` and guest `AF_VSOCK` mapping and service registration. Verify the actual WSL/Hyper-V environment; record unsupported transport as unverified. Microsoft's [Hyper-V socket documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service) explains the host/guest mapping.

**Failure experiments:** fragment a frame one byte at a time; coalesce several frames; disconnect mid-header and mid-payload; send oversized or unauthorized requests; stop the daemon; lose the completion response; retry a request ID. Confirm that invalid callers trigger zero launches.

**Pass gate:** C, Rust, and C# agree on fixtures; malformed inputs cause bounded rejection; an allowed request reaches the launcher; unauthorized requests have no execution effects; uncertain outcomes remain explicit. Benchmark warmed transport separately from process startup and kernel work. Report measured latency without assuming VSOCK is faster.

**SPLAT connection:** [WslLeasedExecutor.cs](../../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs), [main.rs](../../native/splat-agent/src/main.rs), and [auth.rs](../../native/splat-agent/src/auth.rs). The inspected bridge currently uses TCP with JSON messages; VSOCK is a proposed extension. A new binary lab protocol does not automatically interoperate with that bridge. Trace or adapt the existing wire contract explicitly.

**Explanation checkpoint:** What does a successful socket exchange establish, and what evidence is still needed to claim that a C# request received the intended Linux lease?

## Level 4 — The kernel security hook: BPF-LSM

**Learning objective:** load a narrowly scoped execution policy, explain the hook context and verdict, and distinguish verifier acceptance from correct authorization.

**Lesson A: source to attached policy.** Study Linux Security Modules, BPF instructions, ELF sections, maps, BTF, CO-RE relocations, libbpf loading, and link lifetime. Follow C source → BPF ELF → verifier → attached LSM hook. The verifier checks properties of the BPF program, including memory-access safety; accepting a program does not certify its policy intent. Read the [verifier documentation](https://docs.kernel.org/bpf/verifier.html).

**Lesson B: the exec decision.** Study `struct linux_binprm`, its file/inode context, current cgroup identity, map lookup, and existing verdict propagation. This is a hook in the execution path, not a generic interceptor for every syscall. Preserve an existing nonzero BPF verdict. In the normal LSM attachment used here, a negative errno denies the operation. See [BPF-LSM programming](https://docs.kernel.org/bpf/prog_lsm.html).

**Antigravity harnesses:**

1. Write `exec_gate.bpf.c` attaching to `bprm_check_security`. Scope the exercise to one dedicated cgroup and an allow-list using Level 0's inode-key representation. Leave unrelated guest processes outside the exercise policy.
2. Compile an ELF object with BPF-capable Clang, inspect its sections and instructions, and load/attach it with a small C libbpf loader. Retain and then deliberately close the BPF link to observe attachment lifetime. Save verifier logs for a deliberately rejected teaching variant.
3. Use Level 1's launcher to attempt an allowed executable and a denied executable as the initial workload. Compare user-space key bytes with observed kernel device/inode identity. Then allow a caller to run and have it attempt a second, forbidden exec.
4. Emit compact denial records through BPF ringbuf and decode them in Rust. Exhaust telemetry capacity while keeping the deny decision independent of event delivery.
5. Test interpreter/script cases and executable replacement. Explain what an inode identifies and what it does not guarantee about mutable file contents or an interpreter's future actions. Read SPLAT's `file_open` and `socket_connect` hooks to identify the additional operations that an exec-only harness does not govern.

**Correct the denial model.** Returning `-EPERM` rejects the exec attempt; it does not itself send a kill signal to the caller. Have the denied caller report `errno` and continue to demonstrate this. Terminating an already running workload at lease expiry requires a separate lifecycle mechanism. See [execve error behavior](https://man7.org/linux/man-pages/man2/execve.2.html).

**Failure experiments:** wrong device encoding; absent lease membership; missing allow-list entry; partial policy installation; attachment failure; premature map removal; concurrent leases with different permissions; ring-buffer exhaustion.

**Pass gate:** the allowed control runs, the denied initial workload produces no payload marker, and a denied later exec reports the expected error. Kernel observations attribute the decision to the intended cgroup/key. Unrelated workloads remain unaffected; two leases do not share permissions; missing enforcement prevents admission. On expiry, stop and drain the workload before withdrawing the policy that constrains it, then reap owned children.

**SPLAT connection:** [lease_lsm.bpf.c](../../native/splat-agent/src/bpf/lease_lsm.bpf.c), [lease.rs](../../native/splat-agent/src/lease.rs), and the existing [canary](../../native/splat-canary/README.md). The canary and daemon BPF files are separate artifacts; bind evidence to the actual object and source used.

**Explanation checkpoint:** How can a verifier-approved, successfully attached program still implement the wrong security policy?

## Capstone — Follow one request through all five levels

Use the existing SPLAT path as the final specimen: C# request → current bridge protocol → Rust daemon authentication and validation → policy installation → cgroup admission and privilege drop → initial exec check → workload → violation/output frames → caller-visible result → cleanup. Use the VSOCK harness as a separate transport experiment unless an explicit adapter connects it to this path.

| Scenario | Required observation |
| --- | --- |
| Allowed command | Intended binary and exact arguments run in the correct cgroup with the intended credentials; completion reaches C#. |
| Denied initial command | Kernel refuses initial exec; payload never writes its marker; caller receives a failure. |
| Denied later exec | An admitted process cannot execute a binary absent from its lease; the result identifies the denied operation. |
| Invalid caller or unavailable enforcement | Zero workload starts; refusal or unavailable state reaches the caller. |
| Two concurrent leases | Each receives only its own permissions; ending one does not remove the other's policy. |
| Expiry and cancellation | Descendants stop, owned children are reaped, and policy removal follows verified draining. |
| Broken connection or lost reply | The controller does not invent success, confirmed termination, or a safe retry. |
| Telemetry overflow | Denial continues; missing telemetry and measured losses are reported honestly. |

For a file-denial extension, use a temporary file that the workload can read in the control run. For a network extension, use a reachable permitted endpoint and a reachable forbidden endpoint. Existing DAC permissions or an offline endpoint must not masquerade as BPF enforcement.

Submit harness source, run commands, source/object hashes, environment details, predicted and actual results, negative and allowed controls, traces, and a claim-to-evidence table. Run the actual C#-to-daemon path before marking the last hop demonstrated. Reusing a recorded canary result establishes evidence review, not a fresh integration run.

## Assessment and proof boundary

Each level requires working positive and negative controls, a reproducible evidence bundle, and an explanation of one deliberate failure. The capstone passes only when request identity, policy scope, initial admission, denial, lifecycle cleanup, and returned outcomes agree in a live integrated run. Unavailable parts remain explicitly unverified.

The mathematical work is local and explicit: derive device-encoding identities over a stated domain; prove capability-mask properties; reason about queue ownership and happens-before edges; state the launch-order invariant. Tests then exercise those models on a recorded implementation and environment.

Completing five harnesses does not mathematically prove an entire containment system. Finite tests cannot establish every interleaving, kernel behavior, policy surface, or integration assumption. The course produces bounded proofs where a model supports them, executable evidence for the actual mechanisms, and a precise account of what remains unverified.
