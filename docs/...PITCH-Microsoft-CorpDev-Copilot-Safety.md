# SPLAT: The Native Windows Safety Substrate for Microsoft Copilot

> **Status, 2026-09-09: byproduct, not a path.** Acquisition and strategic interest become possible
> for the same reason an OEM licence does — a traction record — and not one day sooner. Keep this
> for the day that record exists; do not sequence work around it. See
> [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md), §6.

**Transforming Autonomous Local Tool-Calling into a CISO-Approved Enterprise Primitive**  
*Platten Industries — Strategic Architecture & CorpDev Brief*

---

## Executive Summary

Microsoft is currently driving the largest platform transition in enterprise computing history: embedding autonomous AI agents into Windows 11, Microsoft 365 Copilot, Copilot Studio, and Semantic Kernel.

However, **enterprise security teams are reluctant to allow autonomous local tool execution on employee workstations**, for the reasons below.

### Why Enterprise CISOs Are Blocking Local Copilot Tool Execution
1. **Unconstrained Execution:** When an LLM decides to run a PowerShell command, bash script, or file tool, it traditionally executes with the user's full ambient Windows token (often with Local Administrator or domain rights).
2. **Prompt Injection & Hallucination Blast-Radius:** A malicious web page, email, or document can inject prompts that coerce Copilot into reading credentials (`%APPDATA%`, `LSASS`, `SAM`, `.ssh/id_rsa`), writing ransomware, or moving laterally.
3. **The MicroVM Trap:** Cloud-based execution sandboxes (e.g. E2B, Modal, Azure Container Instances) put a network round trip on every tool call and move private corporate data off the machine. We have not benchmarked them, so this brief gives them no numbers.

---

## The Solution: SPLAT (Sandboxed Process Lease & Agent Telemetry)

**SPLAT is the native Windows safety substrate engineered specifically to unlock autonomous Copilot deployments.**

```
                            THE SPLAT ARCHITECTURE
  
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. MICROSOFT COPILOT / COPILOT STUDIO / SEMANTIC KERNEL                │
 │    • Tool Calling Intent (PowerShell, CLI, Python, File I/O, Network)  │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ Pre-execution Filter Intercept
 ┌──────────────────────────────────▼─────────────────────────────────────┐
 │ 2. SPLAT CONTROL PLANE (.NET 10 / MissionController.Infrastructure)     │
 │    • SplatCopilotInvocationFilter: Pre-execution policy enforcement    │
 │    • Capability Lease Grant: Issues single-use, bounded execution token│
 │    • Merkle Chained Ledger: Tamper-evident cryptographic proof         │
 └───────────────────┬────────────────────────────────┬───────────────────┘
                     │                                │
 ┌───────────────────▼───────────┐   ┌────────────────▼───────────────────┐
 │ 3. KERNEL CONTAINMENT         │   │ 4. REAL-TIME SIEM STREAMING        │
 │ • Win32 Job Object (CPU/RAM)  │   │ • Microsoft Sentinel REST API      │
 │ • Restricted Low-Priv Token   │   │ • Azure Log Analytics Ingestion    │
 │ • Ephemeral NT ACL Jails      │   │ • Automated CISO SOAR Alerts       │
 │ • WSL2 eBPF-LSM Syscall Airbag│   │ • Merkle Root Cryptographic Audit  │
 └───────────────────────────────┘   └────────────────────────────────────┘
```

---

## Core Capabilities & Architecture

### 1. Kernel-Object Clamps & Stripped Privilege
- **Win32 Job Object Isolation:** Enforces hard caps on CPU percentage (e.g. 50%) and physical RAM (e.g. 256MB), preventing fork-bombs, cryptocurrency miners, or runaway Copilot loops.
- **Restricted Token Provider:** Strips administrative privileges and high integrity levels from Copilot tool execution processes before thread resumption (`CreateProcessAsUserW`).
- **Ephemeral NT ACL Jails:** Provisions single-use, access-controlled directories with stripped inheritance. Tools cannot wander outside their designated scratch space.
- **WSL2 eBPF-LSM Leases:** For cross-platform/Linux scripts, attaches kernel eBPF probes (`bprm_check_security`, `file_open`, `socket_connect`) directly to the stock Microsoft WSL2 kernel.

### 2. Turnkey Microsoft Semantic Kernel Integration
Integrating SPLAT into any Semantic Kernel agent or Copilot host requires just one line of code:

```csharp
// 1-Line Enterprise Hardening for Semantic Kernel
builder.Services.AddSplatCopilotSafety(
    policy: CopilotSafetyPolicy.CreateEnterpriseDefault(),
    sentinelConfig: new SiemConfiguration(
        Protocol: SiemProtocol.MicrosoftSentinel,
        HostOrUrl: "workspace.ods.opinsights.azure.com",
        Port: 443,
        WorkspaceId: azureWorkspaceId,
        SharedKey: azureSharedKey,
        LogType: "CopilotSecurityEvents"
    )
);

// Intercepts and sandboxes every tool call before execution
kernel.FunctionInvocationFilters.Add(serviceProvider.GetRequiredService<SplatCopilotInvocationFilter>());
```

### 3. Direct Streaming into Microsoft Sentinel & Azure Monitor
Every Copilot tool execution—whether successful, denied by policy, or killed by resource clamps—is written to SPLAT's hash-chained audit ledger and, when a Sentinel workspace is configured, forwarded over HMAC-authenticated HTTPS to **Microsoft Sentinel**.

- **One configuration block:** the workspace ID and shared key above; after that, denied file accesses and blocked commands are forwarded to Sentinel.
- **Forensic linkage:** Every action is linked to the session ID, agent ID and parameter hash, and any entry can be proven in the ledger's Merkle tree.

---

## Competitive Matrix

| Dimension | Standard Subshell (`cmd`/`ps`) | Cloud MicroVMs (E2B/Modal) | SPLAT Native Substrate |
| :--- | :--- | :--- | :--- |
| **Unit of Containment** | None (Full User Process) | **"The Machine"** (Perimeter-based VM) | **One Mission** (Task-level Capability Lease) |
| **Execution Location** | Local Workstation | 3rd Party Cloud Infrastructure | **Local Workstation (Zero Infrastructure Export)** |
| **Kernel Requirements** | Standard OS | Remote Hypervisor Guest | **Unmodified Stock Kernel (Windows + stock WSL2, zero forks)** |
| **Added execution latency** | none (no boundary crossed) | a network round trip, not measured by us | **4.12 ms p50 / 9.88 ms p95, measured on Windows 10.0.26200** |
| **Data Residency** | Local | 3rd Party Cloud | **Execution stays on the workstation** |
| **Security Boundary** | None (Full User Token) | Hypervisor (Cloud) | **Windows Job Sandbox + eBPF-LSM + Token De-escalation** |
| **Cost per Seat** | \$0 | per-hour VM pricing, not measured by us | **No cloud compute** |
| **Microsoft Sentinel Ingestion** | Requires custom scripts | Fragmented logs | **Native Real-Time RFC-5424 / CEF / Sentinel REST** |
| **What a reviewer can check** | Nothing to check | The provider's attestations | **Committed kernel evidence, and `splat-mcp doctor` on their own host** |

---

## The Pitch to Microsoft CorpDev

> **"SPLAT enables Microsoft to turn on autonomous local tool-calling for every enterprise Copilot seat in Windows 11 without triggering CISO security vetoes."**

### Strategic Value to Microsoft
1. **Unlocks the \$30/user/month Microsoft 365 Copilot Expansion:** Enterprise customers currently restrict Copilot to passive search and document summarization. SPLAT turns Copilot into an active, autonomous coworker on Windows 11 endpoints safely.
2. **Deepens Microsoft Sentinel & Azure Revenue:** Every enterprise Copilot seat running SPLAT streams structured telemetry directly into Microsoft Sentinel and Azure Log Analytics, accelerating Azure data consumption.
3. **Strengthens Windows 11 Commercial Differentiation:** Windows 11 would carry a kernel-enforced AI execution substrate on the stock WSL2 kernel it already ships.

---

## Technical Proof of Validation

The SPLAT Copilot Safety Primitive has been implemented and validated across our .NET 10 control plane:
- **The suite the README counts, all passing** (the count is held to the compiled assembly by a test), including:
  - Pre-execution CISO policy evaluation and regex heuristics
  - Win32 Job Object hardware limit clamping
  - Restricted Token creation and administrative privilege drops
  - Fail-closed execution when unauthorized paths or commands are requested
  - Semantic Kernel `SplatCopilotInvocationFilter` and `SplatCopilotPlugin`
  - Real-time Microsoft Sentinel HMAC-SHA256 authenticated payload streaming
  - Tamper-evident Merkle-chained audit ledger hashing

---

*Copyright © 2026 Platten Industries. All rights reserved.*
