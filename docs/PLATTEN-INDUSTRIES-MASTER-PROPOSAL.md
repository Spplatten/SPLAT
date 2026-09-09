# Platten Industries: SPLAT Commercial Master Strategy & Monetization Blueprint

> **Partly superseded, 2026-09-09.** Tracks A–D below are the four *direct-sales* motions —
> technician PLG, enterprise fleet, MSP wholesale, sovereign. All four were weighed against the
> reality of a solo operator and set aside in favour of **OEM / embedded licensing**, plus paid
> containment assessments as the first revenue. See
> [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md), §6 and §7. What survives
> here unchanged is the buyer-pain analysis, the unit economics, and the CISO ROI framing — the *reasons* were never the problem,
> the go-to-market was.

**Document Class:** Executive Commercial Strategy & Investment Memorandum  
**Company:** Platten Industries  
**Product:** SPLAT (Sandboxed Process Lease & Agent Telemetry)  
**Positioning:** The Zero-Trust Execution Airbag & Governance Substrate for Enterprise AI Agents  
**Target Audience:** Enterprise CISOs, IT Directors, MSP Leadership, Venture Capitalists, & Microsoft CorpDev  

---

## 1. Executive Summary & The Enterprise Dilemma

Enterprises, Managed Service Providers (MSPs), and higher-education IT organizations are urgently investing in autonomous AI agents (Microsoft Copilot, LangGraph, Claude Code, n8n, Custom ReAct Agents) to lower MTTR (Mean Time to Resolution) and slash tier-1/2 IT operational expenses.

However, **enterprise CISOs and Security Architects are actively vetoing and blocking autonomous local tool execution on corporate endpoints.**

### The Three Blockers Halting Enterprise Agent Adoption:
1. **Unconstrained Ambient Privilege (The Blast-Radius Dilemma):** Traditional AI agent frameworks execute CLI commands, PowerShell scripts, and Python routines using the user’s ambient Windows access token. If a model hallucinates or is coerced via prompt injection, it can wipe filesystems, access DPAPI secrets, read LSASS/SAM hashes, or move laterally across corporate networks.
2. **The MicroVM Latency & Cost Trap:** Cloud-based execution sandboxes (e.g. E2B, Modal, Daytona) require offloading enterprise workloads to external cloud virtual machines. This introduces 200–800ms of network latency per tool call, exposes proprietary data to public clouds, and incurs recurring compute costs (\$0.05–\$0.20 per active hour per seat) that destroy software margins.
3. **The Non-Repudiation Void (Audit Non-Compliance):** Regulatory bodies (HIPAA, SOC 2, NIST 800-207, CMMC) demand tamper-evident proof of every state-changing operational action. Standard orchestrator application logs can be truncated, deleted, or forged by a compromised host process.

### The Platten Industries Thesis:
> **"Don't build n8n, LangGraph, or Microsoft Copilot — Secure Them."**  
> Let high-level orchestrators handle workflow graphs, reasoning, and SaaS connectors. Route every privileged local command, diagnostic probe, and filesystem mutation through **SPLAT’s kernel-enforced, single-mission capability lease.**

---

## 2. Product Architecture & The Defensible Moat

SPLAT provides a local-first, dual-OS containment substrate that runs on stock, unmodified kernels with near-zero overhead (**4.12 ms p50 / 9.88 ms p95 measured on Windows 10.0.26200**).

```
                            THE SPLAT ENTERPRISE TOPOLOGY
  
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  HIGH-LEVEL ORCHESTRATION LAYER                                                 │
  │  • Microsoft Copilot / Semantic Kernel    • LangGraph / Python Multi-Agent      │
  │  • n8n Community Workflows               • Claude Code / MCP Clients            │
  └──────────────────────────────────────┬──────────────────────────────────────────┘
                                         │ Authenticated REST (:5678) / MCP Stdio
  ┌──────────────────────────────────────▼──────────────────────────────────────────┐
  │  SPLAT CONTROL PLANE (.NET 9 / MissionController.Infrastructure)                │
  │  • Capability Lease Compiler: Single-use, bounded seconds-scale execution lease │
  │  • In-Memory DLP Sanitizer: Pre-egress redaction of bare keys & corporate PII   │
  │  • In-Memory Egress Firewall: Pinned FQDN HTTP client filtering                 │
  │  • Tamper-Evident Merkle Ledger: SHA-256 chained audit log committed to SQLite  │
  └───────────────────┬─────────────────────────────────────────┬───────────────────┘
                      │ Windows Substrate                       │ Linux MicroVM Substrate
  ┌───────────────────▼─────────────────────┐  ┌────────────────▼───────────────────┐
  │ WINDOWS CONTAINMENT                     │  │ LINUX BPF-LSM AIRBAG               │
  │ • Win32 Job Object (Hard CPU/RAM caps)  │  │ • Unmodified stock WSL2 kernel     │
  │ • Low-Privilege AppContainer isolation │  │ • BPF-LSM hooks (bprm, open, sock) │
  │ • Stripped Admin Token (S-1-5-32-544)   │  │ • -EPERM kernel veto on rogue call │
  │ • Ephemeral NT ACL Jails                │  │ • Discard-on-failure OverlayFS CoW │
  │ • TransactionalScope Scratch Overlays   │  │ • Unified cgroup v2 resource clamps│
  └─────────────────────────────────────────┘  └────────────────────────────────────┘
```

### Core Technological Differentiators:
1. **Task-Level Capability Leases (Not Machine Perimeters):** While cloud sandboxes isolate by creating an entire virtual machine, SPLAT isolates at the granularity of a **single task** (*1 Template $\rightarrow$ 1 Model $\rightarrow$ 1 Tool $\rightarrow$ 1 Egress FQDN*).
2. **Stock Microsoft Kernel Compatibility:** Zero custom kernel forks or CVE burdens. Operates on standard Microsoft Windows 10/11 Enterprise and stock WSL2 Linux kernels (6.6+/6.18+) via standard `.wslconfig` BPF-LSM directives.
3. **Filesystem Atomicity (Ephemeral Scratch Overlays):** Speculative operations execute inside isolated, access-controlled directory overlays. If the assertion passes, changes commit; if the tool fails or times out, the overlay is instantly purged—guaranteeing the host filesystem remains untouched.
4. **Cryptographic Non-Repudiation:** Every action produces a SHA-256 chained entry where:
   $$\text{EntryHash} = \text{SHA256}(\text{PreviousHash} \parallel \text{Timestamp} \parallel \text{MissionId} \parallel \text{Action} \parallel \text{HMAC}(\text{Details}, \text{Salt}))$$
   Audit anchors are returned directly to calling orchestrators (LangGraph checkpointers, n8n payloads, Sentinel workbooks).

---

## 3. Commercial Packaging & Monetization Model

```mermaid
flowchart LR
    Community["Free Community\n(PLG / BYOK / Dev)"] --> Pro["Technician Pro\n(\$49 - \$99 / seat / mo)"]
    Pro --> Enterprise["Enterprise Fleet\n(\$5 - \$12 / endpoint / mo)"]
    Enterprise --> MSP["MSP Partner Program\n(\$2 - \$4 / managed seat / mo)"]
    Enterprise --> Sovereign["Sovereign / Air-Gapped\n(\$100k - \$500k+ / year)"]
```

### Track A: Technician Pro (Bottom-Up Product-Led Growth)
* **Target Customer:** Solo SysAdmins, IT Contractors, Tier-1/2 Helpdesk Technicians.
* **Pricing:** **\$49 – \$99 / technician / month** (or \$499 billed annually).
* **Delivery:** Standalone signed desktop application with BYOK (Bring Your Own Key for Anthropic / Gemini).
* **Value Metric:** Instant frontline diagnostic runbooks, automated ticket drafts, zero-privilege remediation scripts with rollback guarantees.

### Track B: Enterprise Fleet License (Primary Annual Recurring Revenue Engine)
* **Target Customer:** Mid-Market to Global Enterprise IT & SecOps (500 to 50,000+ endpoints).
* **Pricing:** **\$5 – \$12 / managed endpoint / month** (Annual contracts: \$30k – \$250k+ ARR).
* **Delivery:** Silent Microsoft Intune / SCCM MSIX deployment with central group policy management.
* **Features Included:**
  * Fleet-wide template distribution and policy enforcement.
  * Direct streaming to **Microsoft Sentinel** (CEF / RFC 5424 / REST API).
  * Cryptographic Merkle compliance archive export for external SOC 2 / HIPAA audits.
  * Windows DPAPI enterprise credential management.

### Track C: Managed Service Providers (MSP / MSSP Wholesale Program)
* **Target Customer:** IT Managed Service Providers managing multiple client corporate tenants.
* **Pricing:** **\$2 – \$4 / managed seat / month** (Tiered wholesale volume pricing).
* **Features Included:**
  * Multi-tenant reporting and billing attribution.
  * White-labeled executive remediation reports proving service value with signed cryptographic proof.
  * Zero liability: guarantees client endpoints cannot be compromised by MSP technician agents.

### Track D: Sovereign & Air-Gapped Edition
* **Target Customer:** Defense, Intelligence Community, National Labs, Critical Infrastructure, Healthcare.
* **Pricing:** **\$100k – \$500k+ / year** (Perpetual or high-value annual subscription).
* **Features Included:**
  * 100% offline air-gapped operation with local LLM inference engines (vLLM / Ollama).
  * Strict physical hardware token (YubiKey / SmartCard) enforcement.
  * Zero cloud telemetry or external network calls.

---

## 4. Expansion Revenue Streams & Unit Economics

1. **Platten Cloud AI Gateway (Inference Margin Markup):**
   * *Target:* Enterprises avoiding individual API key provisioning across thousands of workstations.
   * *Model:* Direct token billing with a **20%–35% margin markup**, providing rate-limiting, unified enterprise billing, and central DLP filtering.
2. **Governed Compliance Runbook Packs (Marketplace):**
   * Pre-packaged, signed runbooks tailored to compliance regimes:
     * *CMMC Level 2 & NIST 800-171 Readiness Squad* (\$3,999/yr)
     * *HIPAA Workstation Hardening & Drift Remediation Pack* (\$2,999/yr)
     * *Ransomware Persistence & Lateral Movement Hunter* (\$4,999/yr)
3. **Enterprise ITSM & EDR Recurring Connectors:**
   * Bidirectional sync connectors (\$5k–\$15k/yr) for ServiceNow, Jira Service Management, CrowdStrike Falcon, and Microsoft Defender for Endpoint.
4. **Professional Services & Custom Runbook Engineering:**
   * Enterprise migration converting legacy PowerShell/VBScript runbooks into governed 1:1:1 SPLAT templates (\$250/hr or \$15,000 fixed quick-start packages).

---

## 5. Go-To-Market (GTM) Strategy & Cashflow Velocity

### Speed-to-Cash Execution Phasing:

```
[ Phase 1: High-Velocity Cash (Days to Close) ]
  ├── Startups executing model-generated code (YC, AI Agent batches)
  ├── MCP platform and server developers
  └── AI consultancies building agentic systems for enterprise clients
  
[ Phase 2: Underserved Windows Flank (Weeks to Close) ]
  ├── Regional MSPs & IT automation providers (r/msp, MSP associations)
  └── Mid-size regulated firms (Fintech, Healthtech, Legaltech: 100-1,000 seats)
  
[ Phase 3: Platform Co-Sell & Enterprise Scale (Months to Close) ]
  ├── Microsoft Commercial Marketplace (Azure MACC budget drawdown)
  └── Microsoft Copilot CorpDev partnership ($30/user/mo Copilot unlock)
```

### The CISO ROI Pitch:
$$\text{Net Annual Savings} = (\text{Tickets Deflected} \times \$25\text{ avg ticket cost}) - \text{SPLAT Fleet License}$$

Run that formula on the worked example and it does not close at Track B list price:

| Term | 3,000 endpoints, 600 tickets/month deflected |
| --- | --- |
| Gross annual benefit | 600 × \$25 × 12 = **\$180,000** |
| Track B licence at \$5–\$12 / endpoint / month | **\$180,000 – \$432,000** |
| Net before model, deployment and support cost | **\$0 to –\$252,000** |
| Deflection needed to break even at \$5 / \$12 | **600 / 1,440 tickets per month** |

**This is the number to fix before the deck is shown, not after.** Either the deflection
assumption is far too low for a 3,000-seat estate, the \$25 ticket cost understates a
tier-2 truck roll, or fleet pricing has to sit below the deflection value it creates.
Pick one deliberately and carry it through every slide — a prospect's finance team will
run this arithmetic in about ninety seconds, and a memo that fails it loses the room on
credibility rather than on product.

*Placeholder pending pilot data: avoided technician minutes, repeat-incident rate and
all-in operating cost measured against the existing workflow, not model runs completed.*

---

## 6. Microsoft CorpDev & Strategic Acquisition Angles

SPLAT offers immense strategic value to Microsoft CorpDev and Azure leadership:
1. **Unlocks the \$30/user/month M365 Copilot Expansion:** Enterprise CISOs currently restrict Copilot to read-only document search. SPLAT turns Copilot on Windows 11 into an autonomous, safe coworker.
2. **Accelerates Microsoft Sentinel Data Consumption:** SPLAT streams continuous HMAC-signed telemetry into Azure Log Analytics, directly driving Azure consumption revenue.
3. **Hardware-Anchored Windows 11 Enterprise Moat:** Establishes Windows 11 as the only operating system with kernel-enforced AI process confinement natively built into the enterprise OS fabric.

---

*Copyright © 2026 Platten Industries. All rights reserved.*
