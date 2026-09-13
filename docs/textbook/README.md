# 🏛️ SPLAT: Systems Architecture & Kernel Containment
## A Comprehensive University-Grade Treatise on Zero-Trust Agent Execution Substrates

**Author:** Distinguished Systems Architecture & Compiler Engineering Group  
**Target Platform:** Windows 11 / Linux (WSL2 Kernel 6.18.33.2+ with BPF-LSM)  
**Primary Languages:** C (eBPF CO-RE), Rust (libbpf-rs, tokio), C# (.NET 10, Win32 P/Invoke)

---

## 🧭 Executive Overview & Pedagogical Philosophy

Autonomous AI agents possess a structural vulnerability: **prompt injection is an architectural inevitability** whenever untrusted text is processed alongside instructions. Traditional defenses that execute in user space—such as regex filters, prompt guardrails, and API wrappers—run at the identical privilege level as the compromised agent. When an agent is hijacked, every mitigation operating within its privilege domain fails simultaneously.

The **SPLAT (Sandboxed Process Lease & Agent Telemetry)** engine resolves this crisis by placing containment **strictly below the agent**:
1. **On Windows**, sensor tools execute within suspended-spawn Job Objects under restricted tokens whose Administrative SIDs are converted to deny-only (`USE_FOR_DENY_ONLY`), whose integrity level is forced to Medium (`S-1-16-8192`), and whose filesystem access is constrained by inheritance-severed NTFS ACL jails. For non-networked tools, execution occurs inside an AppContainer possessing zero capability SIDs, severing the network stack at the kernel object manager level.
2. **On Linux (WSL2/Hyper-V)**, a custom BPF-LSM kernel module (`lease_lsm.bpf.c`) enforces a per-cgroup **capability lease** inside the kernel. Unauthorized `execve`, file `open`, or network `connect` operations are intercepted and denied with `-EPERM` before execution reaches the hardware.

This textbook is an exhaustive, rigorous reverse-engineering and pedagogical deconstruction of the entire SPLAT architecture. It serves as both a graduate-level systems engineering curriculum and an authoritative technical specification.

---

## 🪜 The Cognitive Ladder (Curriculum Progression)

```
+---------------------------------------------------------------------------------------+
| TIER 4: THEORETICAL & ARCHITECTURAL FRONTIERS                                         |
| Volume 08: Microarchitectural Optimization & Hardware Sympathy                        |
| Volume 10: Epilogue, Comparative Runtimes & Future Architectural Horizons             |
+---------------------------------------------------------------------------------------+
                                          ▲
                                          │
+---------------------------------------------------------------------------------------+
| TIER 3: ADVANCED SYSTEMS MECHANICS                                                    |
| Volume 04: Zero-Copy Streaming & Shared Memory Ring Buffers                           |
| Volume 06: Memory Management & Ownership Universes (C vs. Rust vs. .NET)              |
| Volume 07: Security Defenses, Validation & Exception Trapping                        |
+---------------------------------------------------------------------------------------+
                                          ▲
                                          │
+---------------------------------------------------------------------------------------+
| TIER 2: CORE RUNTIME & PIPELINES                                                      |
| Volume 03: Native FFI & Foreign Function Interfaces (Win32 & Linux Syscalls)          |
| Volume 05: Agent Builder Architecture & State Machine Pipelines                       |
| Volume 09: Master Laboratory Suite & Guided Interactive Walkthroughs                  |
+---------------------------------------------------------------------------------------+
                                          ▲
                                          │
+---------------------------------------------------------------------------------------+
| TIER 1: SKELETON & FOUNDATIONS                                                        |
| Volume 01: System Topology & Multi-Language Blueprint                                 |
| Volume 02: Core Data Contracts, Binary Alignment & Struct Anatomy                     |
+---------------------------------------------------------------------------------------+
```

---

## 📚 Master Volume Index

| Volume | Title | Focus Area | Core Source Artifacts |
| :--- | :--- | :--- | :--- |
| **[Volume 01](Volume_01_System_Topology_And_Multi_Language_Blueprint.md)** | **System Topology & Multi-Language Blueprint** | Multi-tiered runtime architecture, directory taxonomy, compilation toolchains (Cargo, MSBuild, Clang BPF), and execution entry points. | `splat-mcp/Program.cs`, `native/splat-agent/src/main.rs`, `MissionController.sln` |
| **[Volume 02](Volume_02_Core_Data_Contracts_And_Struct_Anatomy.md)** | **Core Data Contracts & Struct Anatomy** | Memory layouts, binary packing (`#[repr(C)]`, `[StructLayout]`), field offsets, and the critical glibc `dev_t` vs. kernel `s_dev` bitwise encoding defect. | `lease_lsm.bpf.c`, `lease.rs`, `Win32Interop.cs`, `Models.cs` |
| **[Volume 03](Volume_03_Native_FFI_And_Foreign_Function_Interfaces.md)** | **Native FFI & Foreign Function Interfaces** | ABI calling conventions (x64 Windows fastcall vs. System V), P/Invoke marshaling, suspended process creation, AppContainer capability stripping, and Rust `libc` FFI. | `SuspendedProcessLauncher.cs`, `RestrictedTokenProvider.cs`, `SensorAppContainer.cs` |
| **[Volume 04](Volume_04_Zero_Copy_Streaming_And_Shared_Memory_Ring_Buffers.md)** | **Zero-Copy Streaming & Shared Memory Ring Buffers** | Kernel ring buffer architecture (`BPF_MAP_TYPE_RINGBUF`), user-space polling threads, zero-copy pointer casting, and newline-delimited JSON-RPC framing hazards (UTF-8 BOM). | `lease_lsm.bpf.c`, `violation.rs`, `WslLeasedExecutor.cs`, `main.rs` |
| **[Volume 05](Volume_05_Agent_Builder_Architecture_And_State_Machine_Pipelines.md)** | **Agent Builder Architecture & State Machine Pipelines** | The 1:1:1 Governance Invariant, `MissionExecutionEngine` state pipeline, cognitive planning (`GovernedInvestigationLoop`, `GovernedCrewEngine`), and telemetry grounding. | `MissionExecutionEngine.cs`, `GovernedInvestigationLoop.cs`, `TelemetryGrounder.cs` |
| **[Volume 06](Volume_06_Memory_Management_And_Ownership_Universes.md)** | **Memory Management & Ownership Universes** | Tri-language memory mechanics: Rust ownership/borrow checker, .NET 10 generational tracing GC, C manual allocation, and kernel cgroup memory clamping. | `cgroup.rs`, `SqliteStorageContext.cs`, `Win32JobSandbox.cs` |
| **[Volume 07](Volume_07_Security_Defenses_Validation_And_Exception_Trapping.md)** | **Security Defenses, Validation & Exception Trapping** | Single-pass regex argument binding, SHA-256 chained audit ledger with salted retention erasure, pre-egress DLP scrubbing, and fail-closed security invariants. | `GovernedArgumentBinder.cs`, `SqliteChainedAuditLedger.cs`, `RegexDataLossPreventionSanitizer.cs` |
| **[Volume 08](Volume_08_Microarchitectural_Optimization_And_Hardware_Sympathy.md)** | **Microarchitectural Optimization & Hardware Sympathy** | Cache line alignment (`alignas(64)`), false sharing prevention, atomic memory ordering, 128-dim vector embeddings, and empirical latency benchmarks (`splat-bench`). | `SqliteSemanticMemoryIndex.cs`, `splat-bench/Program.cs`, `lease_lsm.bpf.c` |
| **[Volume 09](Volume_09_Master_Laboratory_Suite_And_Guided_Interactive_Walkthroughs.md)** | **Master Laboratory Suite & Guided Interactive Walkthroughs** | Five hands-on collegiate laboratory assignments with step-by-step disassembly, numerical traces, code exercises, and diagnostic debugging puzzles. | `native-systems-curriculum.md`, `canary.sh`, `probe-last-hop.ps1` |
| **[Volume 10](Volume_10_Epilogue_And_Architectural_Evolution.md)** | **Epilogue & Architectural Evolution** | Retrospective analysis of blast-radius containment, defense-in-depth trade-offs, AF_VSOCK peer identity, overlay mount namespaces, and future agent runtimes. | `ROADMAP.md`, `CONTEXT.md`, `SUPPORTED_POLICY.md` |

---

## 🛠️ Compilation & Publishing Engine

The entire curriculum is accompanied by a dual-mode compilation script located at the workspace root: [`build_pdf.py`](../build_pdf.py).

```bash
# 1. Compile HTML Web Book and Headless Vector PDF
python build_pdf.py

# Generated Artifacts:
# - master_textbook_compiled.html (Interactive, responsive, dark Monokai styling)
# - SPLAT_Master_Textbook.pdf     (Publication-grade vector PDF with bookmarks and pagination)
```

---

## 🎓 Recommended Study Tracks

### Track A: Systems Software & Security Researchers
Focus on **Volumes 02, 03, 04, 07, and 09**. This path explores low-level kernel hooks, binary packing, FFI boundaries, eBPF verification, and exploit mitigation.

### Track B: Distributed AI & Agent Infrastructure Architects
Focus on **Volumes 01, 05, 06, 08, and 10**. This path concentrates on multi-language orchestration, process isolation lifecycle, cognitive loop state machines, and microarchitectural latency profiling.
