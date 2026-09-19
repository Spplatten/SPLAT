# SPLAT: Sandboxed Process Lease & Agent Telemetry

## The Kernel-Enforced Containment Substrate for Autonomous AI Agents

**Executive Brief & Technical Overview**  
*Platten Industries — Enterprise AI Infrastructure*

> **Audience note, 2026-09-09.** Written for a direct enterprise buyer. That motion is no longer
> the plan (see [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md)), but this
> stays as the long-form positioning asset: it is the document to adapt for an OEM licensee's own
> end-customer materials, and the shortest statement of why the containment problem exists at all.
> Do not send it as-is to an engineering buyer —
> [the technical one-pager](BRIEF-technical-one-pager.md) is the one for them.

---

### Executive Summary

As enterprises transition from passive chat interfaces to autonomous agentic workflows (orchestrators, MCP servers, DevOps bots, code interpreters), they face a critical infrastructure bottleneck: **execution containment**.

Today, most AI orchestration tools execute commands through unconstrained subshells. A single model hallucination or prompt injection can wipe file systems, read credentials, or exfiltrate sensitive data. The common workaround—remote cloud microVMs—pays a network round trip on every tool call, carries continuous compute subscription costs, and sends private enterprise data off the host.

**SPLAT** solves this fundamental bottleneck. It provides a **local-first, kernel-enforced execution substrate** that runs agent tool calls on the machine that issued them, with containment enforced at the operating system kernel boundary rather than by the agent's cooperation.

**Measured cost of that containment:** on Windows 10.0.26200, over 50 alternating iterations of the same tool run contained and bare, the governed path added **4.12 ms at p50 and 9.88 ms at p95** ([evidence](../src/splat-bench/evidence)). Most of a contained call is Windows process creation, which both arms pay; the locks themselves — ACL jail, job object, restricted token, jail drain — account for roughly 2.4 ms of it. Re-measure with `dotnet run --project src/splat-bench -c Release`.

```
                           THE SPLAT GUARANTEE
  
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. CONTROL PLANE (.NET 10 / WinUI 3)                                    │
 │    • MissionExecutionEngine: Enforces strict 1:1:1 Governed Flow       │
 │    • Audit ledger: SHA-256 hash chain; HMAC-keyed by operator file     │
 │    • Capability Compiler: Translates tool contracts to kernel leases   │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ loopback TCP; each side proves the token (protocol 3)
 ┌──────────────────────────────────▼─────────────────────────────────────┐
 │ 2. LINUX SUBSTRATE (WSL2 MicroVM / Resident Rust Daemon)               │
 │    • Ephemeral cgroups v2: Hard CPU, Memory, and PID clamps            │
 │    • Read-only roots, CoW scratch: NOT BUILT YET (roadmap P2)          │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
 ┌──────────────────────────────────▼─────────────────────────────────────┐
 │ 3. IN-KERNEL BPF-LSM AIRBAG (Linux Kernel Syscall Boundary)            │
 │                                                                        │
 │   • bprm_check_security ──► Unleased binary execution? ──► -EPERM     │
 │   • file_open           ──► Access protected inode?   ──► -EPERM     │
 │   • socket_connect      ──► Rogue egress destination? ──► -EPERM     │
 │                                                                        │
 │   BPF ring buffer: kernel violations reach the MCP client, not the UI │
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
| **SPLAT Substrate** | **4.12 ms p50 / 9.88 ms p95, measured** | **Execution stays local**; SPLAT's own reasoning calls a cloud model after scrubbing | **Kernel BPF-LSM + Job Sandbox** | **Zero cloud infrastructure** |

---

### Core Value Propositions

#### 1. The Unit of Containment is a Task, Not a Box
Cloud sandboxes (E2B, Modal, Daytona, Fly) hand an agent an entire microVM where it can do whatever it wants inside the machine perimeter. Isolation is real, but the unit of containment is "the machine." Runtime observability tools (Falco, Tetragon) enforce eBPF policies, but their unit is a persistent cluster workload managed by a security team. SPLAT's unit is **one mission**: *this model, this binary, this destination, for this many seconds*. That is a single-use, seconds-scale **Capability Lease**, not a perimeter. Enforcing at this granularity requires a policy compiler, a dynamic lease lifecycle, and an in-kernel hook—stopping at the container is no longer sufficient.

#### 2. Local Host Execution on Unmodified Stock Kernels (The Commercial Wedge)
Every cloud sandbox requires shipping workloads, proprietary code, and sensitive enterprise data to third-party cloud infrastructure. This is an absolute non-starter for the exact buyers who most need containment: health systems, defense, finance, intelligence, and anyone operating under strict data residency or air-gap mandates. SPLAT contains agents locally on the stock Microsoft WSL2 kernel (6.18, the version it is proven on), leveraging native `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`, and unified `cgroup v2` without requiring proprietary kernel builds, custom forks, or breaking OS updates. That is an on-premises deployment story cloud sandboxes structurally cannot tell.

#### 3. Evidence-Backed Engineering Discipline
In an emerging security category where 90% of claims are aspirational, SPLAT makes every claim load-bearing:
- Automated tests (`DocumentationDriftTests`) fail the build in both directions if documentation undersells proven capability or oversells unproven capability.
- Proof records are cryptographically pinned to the SHA-256 digest of the exact BPF source that generated them; a proof cannot outlive its code.
- When [`src/splat-bench`](../src/splat-bench) benchmarked real containment overhead and retired the inherited `<1ms` marketing figure by measuring **4.12 ms p50 / 9.88 ms p95**, the project published the measured numbers rather than preserving marketing optics.

#### 4. Transparent Architectural Boundaries: Defense-in-Depth vs The Defensive Moat
SPLAT maintains clear distinctions between standard isolation and genuine moats. The Windows control plane implements the Chromium sandbox architecture (Win32 Job Objects, restricted tokens with `USE_FOR_DENY_ONLY` on the Administrators SID, Medium integrity drops, and NTFS ACL jails)—well-trodden and proven in production browsers since 2008. It is competently executed and asserted against `whoami` inside the sandbox, serving as robust local defense-in-depth. The defensible technological moat is the Linux capability lease enforced by BPF-LSM directly inside unmodified stock kernels.

#### 5. Discard-on-Failure Scratch (OverlayFS CoW): Not Built Yet
The goal is for every mission to work in an ephemeral OverlayFS copy-on-write workspace that is discarded when the mission fails or is revoked. It is not built. Today the daemon refuses `readOnlyFs` and `overlayFs.enableCow` rather than pretending to honour them, and roadmap P2 is the work that makes them real.

#### 6. Tamper-Evident Audit Ledger
Every governed action is written to a hash-chained audit ledger (`SqliteChainedAuditLedger`), and a Merkle tree can prove any entry is in it. It is chained, not signed. Unkeyed, the default, anyone who can write the file can recompute the chain; with the operator's key file, nobody without that key can rewrite it unnoticed. It is built with SOC 2 and HIPAA evidence in mind, but no auditor has assessed it, and it certifies nothing.

#### 7. Containment Substrate, Not an RPA Workflow Bot
A fundamental architectural boundary separates SPLAT from Robotic Process Automation (RPA) tools and unconstrained web bots. SPLAT does not build agents that scrape consumer inboxes (e.g. Gmail/Outlook) or puppeteer browser sessions across advertising dashboards (e.g. configuring TikTok or Meta OAuth consoles). 

In SPLAT's threat model, granting an LLM unconstrained browser access, broad egress, and administrative credentials creates an uncontainable blast radius where prompt injection leads directly to data exfiltration or credential theft. Instead, SPLAT operates strictly as an **execution containment substrate**:
- **Native Governed Tasks:** Operates through declarative 1:1:1 templates (1 Model : 1 Tool : 1 Jail : at most 1 declared destination) to execute local telemetry probes, log audits, and draft-only operational artifacts.
- **Substrate for External Agents (`splat-mcp`):** Provides the kernel-enforced sandbox, resource clamps, and tamper-evident audit ledger that allow external orchestrators (Claude Code, LangGraph, Cursor) to execute terminal commands and code safely without exposing the host system.

---

### Technical Highlights & Architecture

- **1:1:1 Invariant:** Strict governance ensuring 1 Model Session : 1 Tool Execution : 1 Ephemeral Jail.
- **BPF-LSM Enforcement Hooks:**
  - `lsm/bprm_check_security`: Restricts execution exclusively to declared binary inodes.
  - `lsm/file_open`: Refuses the lease's protected files; for `run_command` today those are `/etc/shadow` and `/etc/sudoers`.
  - `lsm/socket_connect`: Kernel-level egress clamping to the lease's approved IPv4 and IPv6 addresses.
- **Resource Clamps:** Strict cgroup v2 memory limits (e.g., 256MB), CPU quotas, and process count limits, read back after they are written, to prevent fork-bombs and resource exhaustion attacks.

---

### Commercial Applications

1. **Enterprise SecOps & Incident Response:** Safely grant AI agents terminal access to investigate live telemetry and logs without risk of unauthorized lateral movement.
2. **Autonomous Software Engineering & DevOps:** Execute LLM-generated code, build scripts, and test runners in a local sandbox on developer workstations, with no round trip off the machine.
3. **CI/CD & Supply-Chain Pipeline Execution:** Secure automated build steps, untrusted PR test execution, and third-party action runs. A build step is inherently declarative, short-lived, and manifest-driven—making it an ideal fit for kernel capability leases.
4. **Regulated Workloads (FinTech, Healthcare, Defense):** Enable autonomous agent tooling on strictly air-gapped, on-premises workstations where cloud-based sandboxes violate compliance and data sovereignty mandates. The containment runs offline; SPLAT's own reasoning calls a cloud model today, so an air-gapped deployment needs a local model that is not built.

---

### Summary

**SPLAT turns "AI code execution" into a contained, measured primitive.**

By bridging .NET control plane governance with kernel-level eBPF enforcement, SPLAT limits what an agent can reach on its worst day, and says plainly what it does not yet police.

*Copyright © 2026 Platten Industries. All rights reserved.*
