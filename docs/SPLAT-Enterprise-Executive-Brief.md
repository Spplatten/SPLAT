# SPLAT: Sandboxed Process Lease & Agent Telemetry
## The Kernel-Enforced Containment Substrate for Autonomous AI Agents

**Executive Brief & Technical Overview**  
*Platten Industries — Enterprise AI Infrastructure*

---

### Executive Summary

As enterprises transition from passive chat interfaces to autonomous agentic workflows (orchestrators, MCP servers, DevOps bots, code interpreters), they face a critical infrastructure bottleneck: **execution containment**.

Today, most AI orchestration tools execute commands through unconstrained subshells. A single model hallucination or prompt injection can wipe file systems, read credentials, or exfiltrate sensitive data. The common workaround—remote cloud microVMs—pays a network round trip on every tool call, carries continuous compute subscription costs, and sends private enterprise data off the host.

**SPLAT** solves this fundamental bottleneck. It provides a **local-first, kernel-enforced execution substrate** that runs agent tool calls on the machine that issued them, with containment enforced at the operating system kernel boundary rather than by the agent's cooperation.

**Measured cost of that containment:** on Windows 10.0.26200, over 50 alternating iterations of the same tool run contained and bare, the governed path added **4.12 ms at p50 and 9.88 ms at p95** ([evidence](../src/splat-bench/evidence)). Most of a contained call is Windows process creation, which both arms pay; the locks themselves — ACL jail, job object, restricted token, jail drain — account for roughly 2.4 ms of it. Re-measure with `dotnet run --project src/splat-bench -c Release`.

```
                           THE SPLAT GUARANTEE
  
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. CONTROL PLANE (.NET 9 / WinUI 3)                                    │
 │    • MissionExecutionEngine: Enforces strict 1:1:1 Governed Flow       │
 │    • Merkle Audit Ledger: Cryptographically chained SOC2/HIPAA record  │
 │    • Capability Compiler: Translates tool contracts to kernel leases   │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ Hyper-V VSOCK (latency not yet measured)
 ┌──────────────────────────────────▼─────────────────────────────────────┐
 │ 2. LINUX SUBSTRATE (WSL2 MicroVM / Resident Rust Daemon)               │
 │    • Ephemeral cgroups v2: Hard CPU, Memory, and PID clamps            │
 │    • OverlayFS CoW: Discard-on-failure scratch spaces (atomic rollback)│
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
 ┌──────────────────────────────────▼─────────────────────────────────────┐
 │ 3. IN-KERNEL BPF-LSM AIRBAG (Linux Kernel Syscall Boundary)            │
 │                                                                        │
 │   • bprm_check_security ──► Unleased binary execution? ──► -EPERM     │
 │   • file_open           ──► Access protected inode?   ──► -EPERM     │
 │   • socket_connect      ──► Rogue egress destination? ──► -EPERM     │
 │                                                                        │
 │   ⚡ Direct BPF Ringbuffer: Instant violation telemetry streamed to HUD│
 └────────────────────────────────────────────────────────────────────────┘
```

---

### The Problem: Why Enterprise AI is Stalled at the Execution Layer

Only the SPLAT row below is measured. The others are left unquantified on purpose: this project has
not benchmarked E2B, Modal, or Docker, and publishing checkable numbers about named competitors that
we have not run is the fastest way to lose a technical reader.

| Approach | Added latency | Data Privacy | Security Boundary | Operational Cost |
| :--- | :--- | :--- | :--- | :--- |
| **Direct Subshell (`bash`/`cmd`)** | none — no boundary to cross | Local | **None** (full user compromise risk) | Low |
| **Cloud MicroVMs (E2B, Modal)** | a network round trip, not measured here | High Risk (cloud transmission) | Hypervisor | Per-hour active VM |
| **Standard Docker on Host** | not measured here | Local | Container daemon (root escape risk) | Medium |
| **SPLAT Substrate** | **4.12 ms p50 / 9.88 ms p95, measured** | **100% local** | **Kernel BPF-LSM + Job Sandbox** | **Zero cloud infrastructure** |

---

### Core Value Propositions

#### 1. Blast-Radius Containment, Not Semantic Guesswork
SPLAT does not rely on fragile prompt filters or semantic heuristics to detect attacks. Instead, it treats agent containment as an **operating system invariant**. Before any tool executes, SPLAT issues a single-use, seconds-scale **Capability Lease**. If an agent attempts to touch unauthorized files, execute foreign binaries, or initiate rogue network connections, the kernel immediately blocks the syscall with `-EPERM`.

#### 2. No Network Round Trip
By operating over local channels rather than the public internet, SPLAT keeps every tool call on the issuing machine. The measured containment cost is 4.12 ms at p50 on Windows 10.0.26200; the VSOCK transport itself has not been separately measured and is not claimed here.

#### 3. Zero Custom Kernel Maintenance (Stock Microsoft WSL2 Kernel)
SPLAT is engineered to run directly on stock Microsoft WSL2 Linux kernels (6.6+ / 6.18+). It leverages native `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`, and unified `cgroup v2` without requiring proprietary kernel builds or breaking system updates.

#### 4. Discard-on-Failure Atomic Rollback (OverlayFS CoW)
Every mission operates inside an ephemeral OverlayFS Copy-on-Write workspace. Changes are isolated to temporary scratch memory. If an operation fails, triggers a policy violation, or is revoked by the operator, the workspace is discarded instantly with zero side effects on the host filesystem.

#### 5. Tamper-Evident Merkle Audit Ledger (SOC2 / HIPAA Compliance)
Every tool invocation, standard output stream, and security violation is cryptographically signed and chained using SHA-256 into a tamper-evident audit ledger (`SqliteChainedAuditLedger`). SecOps and compliance teams have mathematical proof of execution integrity.

---

### Technical Highlights & Architecture

- **1:1:1 Invariant:** Strict governance ensuring 1 Model Session : 1 Tool Execution : 1 Ephemeral Jail.
- **BPF-LSM Enforcement Hooks:**
  - `lsm/bprm_check_security`: Restricts execution exclusively to declared binary inodes.
  - `lsm/file_open`: Blocks access to sensitive OS and credential paths (e.g. `/etc/shadow`, `.ssh`).
  - `lsm/socket_connect`: Hardware-level network egress clamping to approved destination /32 IPv4 addresses.
- **Hardware Clamps:** Strict cgroup v2 memory limits (e.g., 256MB), CPU quotas, and process count limits to prevent fork-bombs and resource exhaustion attacks.

---

### Commercial Applications

1. **Enterprise SecOps & Incident Response:** Safely grant AI agents terminal access to investigate live telemetry and logs without risk of unauthorized lateral movement.
2. **Autonomous Software Engineering & DevOps:** Execute LLM-generated code, build scripts, and test runners in a local sandbox on developer workstations, with no round trip off the machine.
3. **Regulated Workloads (FinTech, Healthcare, Defense):** Enable autonomous agent tooling on strictly air-gapped, on-premises workstations where cloud-based sandboxes violate compliance mandates.

---

### Summary

**SPLAT converts dangerous "AI code execution" into a hardened, high-speed, enterprise-grade primitive.** 

By bridging .NET control plane governance with kernel-level eBPF enforcement, SPLAT enables organizations to deploy truly autonomous agents with total confidence.

*Copyright © 2026 Platten Industries. All rights reserved.*
