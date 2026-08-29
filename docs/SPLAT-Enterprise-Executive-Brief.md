# SPLAT: Sandboxed Process Lease & Agent Telemetry
## The Kernel-Enforced Containment Substrate for Autonomous AI Agents

**Executive Brief & Technical Overview**  
*Platten Industries — Enterprise AI Infrastructure*

---

### Executive Summary

As enterprises transition from passive chat interfaces to autonomous agentic workflows (orchestrators, MCP servers, DevOps bots, code interpreters), they face a critical infrastructure bottleneck: **execution containment**.

Today, over 95% of AI orchestration tools execute commands through unconstrained subshells. A single model hallucination or prompt injection can wipe file systems, read credentials, or exfiltrate sensitive data. Existing workarounds—such as remote cloud microVMs—introduce 200–800ms of network latency, create continuous cloud compute subscription costs, and leak private enterprise data over the public internet.

**SPLAT** solves this fundamental bottleneck. It provides a **local-first, kernel-enforced execution substrate** that executes agent tool calls in sub-millisecond time ($<1\text{ms}$) while mathematically guaranteeing containment at the operating system kernel boundary.

```
                           THE SPLAT GUARANTEE
  
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. CONTROL PLANE (.NET 9 / WinUI 3)                                    │
 │    • MissionExecutionEngine: Enforces strict 1:1:1 Governed Flow       │
 │    • Merkle Audit Ledger: Cryptographically chained SOC2/HIPAA record  │
 │    • Capability Compiler: Translates tool contracts to kernel leases   │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ Hyper-V VSOCK (<1ms latency)
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

| Approach | Latency | Data Privacy | Security Boundary | Operational Cost |
| :--- | :--- | :--- | :--- | :--- |
| **Direct Subshell (`bash`/`cmd`)** | $\sim 1\text{ms}$ | Local | **None** (Full user compromise risk) | Low |
| **Cloud MicroVMs (E2B, Modal)** | $200–800\text{ms}$ | High Risk (Cloud transmission) | Hypervisor | High (\$0.05–\$0.20/hour active VM) |
| **Standard Docker on Host** | $50–150\text{ms}$ | Local | Container Daemon (root escape risk) | Medium |
| **SPLAT Substrate** | **$<1\text{ms}$** | **100% Local Air-Gapped** | **Kernel BPF-LSM + Job Sandbox** | **Zero Cloud Infrastructure** |

---

### Core Value Propositions

#### 1. Blast-Radius Containment, Not Semantic Guesswork
SPLAT does not rely on fragile prompt filters or semantic heuristics to detect attacks. Instead, it treats agent containment as an **operating system invariant**. Before any tool executes, SPLAT issues a single-use, seconds-scale **Capability Lease**. If an agent attempts to touch unauthorized files, execute foreign binaries, or initiate rogue network connections, the kernel immediately blocks the syscall with `-EPERM`.

#### 2. Sub-Millisecond Hyper-V VSOCK Speed
By operating over local memory channels (Hyper-V VSOCK and shared memory), SPLAT eliminates public internet round-trips. Multi-step agent loops that require 20–50 consecutive tool executions run in seconds rather than minutes.

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
2. **Autonomous Software Engineering & DevOps:** Execute LLM-generated code, build scripts, and test runners in an air-gapped, zero-latency sandbox on developer workstations.
3. **Regulated Workloads (FinTech, Healthcare, Defense):** Enable autonomous agent tooling on strictly air-gapped, on-premises workstations where cloud-based sandboxes violate compliance mandates.

---

### Summary

**SPLAT converts dangerous "AI code execution" into a hardened, high-speed, enterprise-grade primitive.** 

By bridging .NET control plane governance with kernel-level eBPF enforcement, SPLAT enables organizations to deploy truly autonomous agents with total confidence.

*Copyright © 2026 Platten Industries. All rights reserved.*
