# SPLAT Antigravity Deep Audit: Orchestration, Substrate Reality, & Enterprise Threat Model

**Audit Date:** 2026-09-05 | **Auditor:** Antigravity (Advanced Agentic Architecture & Security Audit)  
**Target Repository:** `C:\C_AGENT_BUILDER` | **Base Commit:** `7df0e2f`  
**Scope:** Complete codebase inspection covering Windows Win32/NT security primitives, Linux BPF-LSM evidence, SPLAT Flow orchestration engine, MCP server, DLP filtering, and audit ledger integrity.

---

## Executive Summary & Core Verdict

**Verdict:** **SPLAT is a formidable, highly engineered zero-trust endpoint containment substrate, but its recent expansion into workflow orchestration (SPLAT Flow) introduces new control-plane attack surfaces that must be hardened before enterprise deployment.**

The original architecture correctly identified the enterprise agent dilemma: **AI agents cannot be given raw developer/admin shell access to host machines.** While competitors like n8n, Windmill, and LangGraph focus on workflow graph ergonomics and cloud API integrations, they execute code with broad host/container privileges and lack kernel-enforced, single-mission capability leases.

However, bridging SPLAT's "containment airbag" with an "agent orchestration builder" creates architectural tensions:
1. **The Loopback Exposure:** The newly added SPLAT Flow REST gateway (`:5678`) introduces an unauthenticated HTTP execution endpoint on the local loopback, exposing the host to cross-process command dispatch.
2. **The "Airbag vs. RPA" Identity Split:** Attempting to match n8n on connector breadth (hundreds of SaaS OAuth targets) dilutes SPLAT's core moat. SPLAT's defensible wedge is not being an n8n clone, but being the **hardened, unhackable execution engine beneath n8n, LangGraph, and enterprise Copilots.**
3. **Audit Ledger & Auth Disconnects:** Prior findings regarding MCP dispatching before actor resolution (`McpServerHandler.cs:574`) and the audit verifier ignoring the displayed payload text (`SqliteChainedAuditLedger.cs:183`) remain active in the tree.

---

## 1. Empirical System Diagnostics

| Diagnostic Check | Result | Verification & Evidence |
| :--- | :--- | :--- |
| **xUnit Test Suite** | **367 passed, 0 failed, 0 skipped** | 100% pass across unit, integration, and security tests (`WorkflowEngineTests.cs`, `HardeningSubsystemTests.cs`). |
| **Solution Compilation** | **0 errors, 0 warnings** | Full solution (.NET 9, WinUI 3, MCP, bench) compiles cleanly in Debug and Release. |
| **Documentation Drift Enforcement** | **PASSED** | `DocumentationDriftTests` mechanically checks that all 367 tests are accurately reflected in `README.md`, `TUTORIAL.md`, `SPLAT-Field-Guide.html`, and `BRIEF-technical-one-pager.md`. |
| **Measured Launch Overhead** | **4.12 ms p50 / 9.88 ms p95** | Recorded in `src/splat-bench/evidence/bench-windows-10.0.26200.0.json` (50 iterations on Windows 10.0.26200). Retires marketing claims of sub-millisecond execution. |
| **Linux Kernel BPF-LSM Canary** | **PASS (`6.18.33.2-microsoft-standard-WSL2`)** | Proven in `splat-canary/evidence/canary-6.18.33.2-microsoft-standard-WSL2.json`. In-kernel veto on `open` (inode 44904), `connect` (1.1.1.1), and `exec` (inode 1633). |
| **Linux Daemon Probe** | **PASS (`daemon-probe.json`)** | Root-spawned process denied `/etc/shadow` access, unleased second exec blocked, unleased egress blocked. |

---

## 2. Ranked Findings Matrix

| Finding ID | Severity | Category | Title | Affected File & Lines |
| :--- | :---: | :--- | :--- | :--- |
| **AG-F01** | **P1 (High)** | Orchestration | Unauthenticated REST Execution Gateway on Loopback | `EmbeddedWebhookListener.cs:231-295` |
| **AG-F02** | **P1 (High)** | Ledger | Audit Ledger Verifier Ignores Displayed Payload (`Details`) | `SqliteChainedAuditLedger.cs:157-195` |
| **AG-F03** | **P1 (High)** | MCP Server | Pre-Execution Authentication Bypass on `run_command` and `fs_write` | `McpServerHandler.cs:574-608, 792-808` |
| **AG-F04** | **P2 (Medium)** | Substrate | Windows Network Egress Pinning is Governed by Audit, Not Kernel WFP | `EgressFirewallHandler.cs:10-95`, `GovernedTemplateCatalog.cs:48-60` |
| **AG-F05** | **P2 (Medium)** | OAuth / DPAPI | OAuth Callback Missing Cryptographic State Nonce Validation | `EmbeddedWebhookListener.cs:144-188`, `OAuthCallbackCoordinator.cs:46-55` |
| **AG-F06** | **P2 (Medium)** | DLP Sanitizer | High-Entropy Bare Secret Blind Spots in Regex Redaction | `RegexDataLossPreventionSanitizer.cs:30-86` |
| **AG-F07** | **P2 (Medium)** | Vector Memory | 128-Dimensional Trigram Hash Collisions & Indirect Prompt Injection | `SqliteSemanticMemoryIndex.cs:118-161`, `WorkflowExecutionEngine.cs:460-495` |
| **AG-F08** | **P3 (Low)** | Orchestration | Speculative Transaction Rollback Lacks Filesystem Atomicity | `WorkflowExecutionEngine.cs:505-555` |

---

## 3. Deep-Dive Findings

### AG-F01 — P1: Unauthenticated REST Execution Gateway on Loopback (`:5678`)

**Location:** [`src/MissionController.Infrastructure.Network/Triggers/EmbeddedWebhookListener.cs:231-295`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Network/Triggers/EmbeddedWebhookListener.cs#L231-L295)

**The Vulnerability:**
The newly introduced REST API exposes `POST /api/v1/workflows/{id}/execute` on `http://127.0.0.1:5678/`. While this enables headless automation and CI/CD triggers, it performs **zero authorization, API key validation, or peer token verification**:

```csharp
// EmbeddedWebhookListener.cs:231
if (segments.Length == 5 &&
    segments[2].Equals("workflows", StringComparison.OrdinalIgnoreCase) &&
    segments[4].Equals("execute", StringComparison.OrdinalIgnoreCase))
{
    string workflowId = segments[3];
    if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
    {
        // Executes arbitrary registered workflow immediately with payload from request body!
        var result = await _executionEngine.ExecuteAsync(workflow, payload, "RestApiGateway");
        ...
```

**Attack Scenarios:**
1. **Local Privilege Escalation / Cross-Session Abuse:** On a multi-user Windows workstation or terminal server, any local non-admin user or background process can send an HTTP POST to `127.0.0.1:5678` and trigger script executions under the SPLAT operator's user account.
2. **Drive-By Web-to-Local Pivot (DNS Rebinding / Local Network Access):** A user visiting a malicious or compromised website in their browser could be subjected to cross-origin POST requests or DNS rebinding targeting `http://127.0.0.1:5678/api/v1/workflows/{id}/execute`. Even with CORS preflights, certain simple POST requests or browser extensions bypass restrictions.

**Remediation:**
1. Generate an ephemeral high-entropy API key at startup stored in DPAPI / memory.
2. Require an `Authorization: Bearer <token>` header on all `/api/v1/` routes.
3. Reject any request where `Host` header does not strictly match `127.0.0.1:5678` or `localhost:5678`.

---

### AG-F02 — P1: Audit Ledger Verifier Ignores Displayed Payload (`Details`)

**Location:** [`src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs:157-195`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs#L157-L195)

**The Vulnerability:**
In `VerifyLedgerIntegrityAsync`, version 2 entries calculate the row entry hash from `DetailsCommitment` instead of checking that `Details` matches `DetailsCommitment`:

```csharp
// SqliteChainedAuditLedger.cs:183-190
if (hashVersion >= 2 && commitment is not null)
{
    // commitment is read directly from the database row!
    calculatedHash = ComputeEntryHashV2(prev, ts, mid, tid, act, commitment, op, hmacKey);
    if (!string.Equals(entry, calculatedHash, StringComparison.OrdinalIgnoreCase) && hmacKey != null)
    {
        calculatedHash = ComputeEntryHashV2(prev, ts, mid, tid, act, commitment, op, null);
    }
}
```

Notice that `det` (the narrative `Details` string) is read at line 168, but **never verified against `commitment`**. `DetailsSalt` is not even selected from the table!

**Impact:**
An attacker with SQLite write access can execute:
```sql
UPDATE AuditLedger SET Details = 'Operator approved all security overrides. All systems healthy.' WHERE Id = 12;
```
When an auditor calls `VerifyLedgerIntegrityAsync()`, the function re-hashes using the unchanged `DetailsCommitment` column and returns **`true` (INTEGRITY VERIFIED)**! The displayed evidence is forged while the cryptographic verification reports green.

**Remediation:**
In `VerifyLedgerIntegrityAsync`, select `DetailsSalt` and verify that `HMAC_SHA256(Details, DetailsSalt) == DetailsCommitment`. If they do not match, immediately return `false`.

---

### AG-F03 — P1: Pre-Execution Authentication Bypass in MCP Server

**Location:** [`src/splat-mcp/McpServerHandler.cs:574-608, 792-808`](file:///c:/C_AGENT_BUILDER/src/splat-mcp/McpServerHandler.cs#L574-L608)

**The Vulnerability:**
In `McpServerHandler.cs`, tool execution occurs **before** caller authorization is resolved:

```csharp
// McpServerHandler.cs:574
var execResult = await _leasedExecutor.ExecuteLeasedAsync(
    lease,
    command,
    arguments,
    violations: violationProgress,
    ct: ct);

// Execution has ALREADY completed!
...
await _auditLedger.AppendLogAsync(
    ...,
    await ResolveActorAsync(ct), // <-- Actor is resolved AFTER execution
    ct);
```

Similarly, in `fs_write` (lines 792-808), the file is written to disk before `ResolveActorAsync` is called.

**Impact:**
If an identity provider rejects the caller, the command has already executed and the file has already been written. Furthermore, because `ResolveActorAsync` throws on an invalid identity, the audit logging at line 603 is skipped—leaving an execution on the host with **zero flight recorder trail**.

**Remediation:**
Call `var actor = await ResolveActorAsync(ct);` at the entry of `HandleToolCallAsync` before any executor or filesystem call is initiated.

---

### AG-F04 — P2: Windows Network Egress Pinning is Governed by Audit, Not Kernel WFP

**Location:** [`src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs:10-95`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs#L10-L95) and [`GovernedTemplateCatalog.cs:48-60`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Data/Catalog/GovernedTemplateCatalog.cs#L48-L60)

**The Architectural Reality:**
`EgressFirewallHandler` is a .NET `DelegatingHandler` implemented in userspace. It inspects `HttpRequestMessage` objects issued by SPLAT's own `HttpClient`.
- For Windows child processes (e.g. `tasklist.exe`, `powershell.exe`), network containment is enforced via `SuspendedProcessLauncher.cs` by allocating an AppContainer with **zero capabilities** (`denyNetworkAccess = true`). This successfully blocks all raw IP and DNS access at the kernel boundary.
- **The Gap:** When a sensor template or workflow script *does* require network egress (e.g. `business-api.tiktok.com`), AppContainer is granted `internetClient`. On Windows, `internetClient` grants unrestricted outbound TCP access to **any** internet IP.
- SPLAT cannot pin the destination IP/FQDN on Windows without a Windows Filtering Platform (WFP) driver or Windows Defender Firewall rule.
- On Linux, this is fully solved: `splat-agent` uses BPF-LSM (`sock_addr` and `socket_connect`) to deny any `connect()` syscall not matching the leased destination IP.

**Documentation Accuracy:**
To SPLAT's credit, this limitation is documented honestly in `GovernedTemplateCatalog.cs:56-60` and `TUTORIAL.md:117`. However, in enterprise sales briefs, claiming "one-line-out egress firewall" can mislead prospects into believing Windows has per-FQDN packet filtering.

---

### AG-F05 — P2: OAuth Callback Missing Cryptographic State Nonce Validation

**Location:** [`src/MissionController.Infrastructure.Network/Triggers/EmbeddedWebhookListener.cs:144-188`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Network/Triggers/EmbeddedWebhookListener.cs#L144-L188) and [`OAuthCallbackCoordinator.cs:46-55`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Network/Triggers/OAuthCallbackCoordinator.cs#L46-L55)

**The Vulnerability:**
When `GET /oauth/callback/{provider}` is reached:
```csharp
string provider = segments[2];
string code = request.QueryString["code"] ?? string.Empty;
string state = request.QueryString["state"] ?? string.Empty;

if (!string.IsNullOrEmpty(code) && _oauthHandlers.TryGetValue(provider, out var oauthHandler))
{
    handled = await oauthHandler(code, state);
}
```
In `OAuthCallbackCoordinator.cs`:
```csharp
public async Task<bool> InterceptCallbackAsync(string provider, string code, string state)
{
    // The state parameter is received, but NEVER checked against a saved cryptographically random nonce!
    return await ExchangeCodeAndVaultTokenAsync(provider, code);
}
```

**Impact:**
Standard OAuth 2.0 RFC 6749 §10.12 mandates checking `state` to prevent **Cross-Site Request Forgery (CSRF)**. Without state validation, an attacker could craft an authorization callback URL containing the attacker's authorization code and trick the victim's browser into visiting `http://127.0.0.1:5678/oauth/callback/tiktok?code=ATTACKER_CODE`. The victim's SPLAT vault would then store tokens bound to the attacker's account.

**Remediation:**
Store an in-memory `ConcurrentDictionary<string, (string StateNonce, DateTime ExpiresUtc)>`. When `BuildAuthorizationUrl` generates a `state`, record it. In `InterceptCallbackAsync`, verify that `state == expectedNonce` and invalidate it immediately.

---

### AG-F06 — P2: High-Entropy Bare Secret Blind Spots in DLP Sanitizer

**Location:** [`src/MissionController.Infrastructure.Network/Dlp/RegexDataLossPreventionSanitizer.cs:30-86`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Network/Dlp/RegexDataLossPreventionSanitizer.cs#L30-L86)

**The Blind Spot:**
The DLP sanitizer rule `CredentialAssignment` requires an assignment operator (`:` or `=`):
```csharp
new Regex(@"(?i)(password|passwd|pwd|secret|apikey|api_key|access_token|bearer)\s*([:=])\s*([^\s;,""']+)")
```
If an unredacted log or terminal dump outputs a bare secret without an explicit assignment keyword, it escapes redaction completely:
- **AWS Access Key:** `AKIAIOSFODNN7EXAMPLE` (not caught unless prefixed with `apikey=`)
- **GitHub Token:** `ghp_ABC123xyz456...` (not caught)
- **OpenAI API Key:** `sk-proj-abc123...` (not caught)
- **Stripe Secret Key:** `sk_live_abc123...` (not caught)
- **Bare JWT Token:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` (not caught unless preceded by `bearer:`)
- **Base64-encoded basic auth:** `Basic dXNlcjpwYXNz` (not caught)

**Remediation:**
Add dedicated token-format rules to `_rules`:
```csharp
new DlpRule("AwsKey", new Regex(@"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
new DlpRule("GitHubToken", new Regex(@"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"), "[REDACTED_GITHUB_TOKEN]"),
new DlpRule("OpenAiKey", new Regex(@"\b(sk-[a-zA-Z0-9]{48,64})\b"), "[REDACTED_OPENAI_KEY]"),
new DlpRule("JwtToken", new Regex(@"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]")
```

---

### AG-F07 — P2: 128-Dimensional Trigram Hash Collisions & Memory Poisoning

**Location:** [`src/MissionController.Infrastructure.Data/Vector/SqliteSemanticMemoryIndex.cs:118-161`](file:///c:/C_AGENT_BUILDER/src/MissionController.Infrastructure.Data/Vector/SqliteSemanticMemoryIndex.cs#L118-L161)

**The Engineering Reality:**
`SqliteSemanticMemoryIndex` generates embeddings without machine learning by taking words and character trigrams, computing `SHA256(token) % 128`, and populating a `float[128]` vector normalized to unit length.
- **Pros:** Completely offline, zero cloud API cost, executes in ~0.05 ms in pure C#, zero Python dependencies.
- **Cons (Hash Collision & Resolution Limit):** A 128-dimensional vector hashed modulo 128 suffers from severe pigeonhole saturation once documents exceed ~50-100 words. Collisions between unrelated technical terms (e.g. `registry` vs `database`) distort cosine similarity scores.
- **Security Vector (Indirect Prompt Injection):** If an untrusted document (e.g. scraped log or email body) is indexed via `WorkflowNodeType.MemoryStore`, and later retrieved by `WorkflowNodeType.MemoryRecall`, an attacker can plant indirect prompt injection instructions into the vector database that gets concatenated into downstream agent prompts without separation delimiters.

**Remediation:**
1. Increase the dimension from 128 to 512 or 1024 to minimize trigram collisions.
2. In `WorkflowExecutionEngine.cs:ExecuteMemoryRecallNodeAsync`, wrap recalled context in XML containment tags:
   ```markdown
   <untrusted_historical_memory source="{templateId}">
   {content}
   </untrusted_historical_memory>
   ```
   Instruct models never to parse system instructions from inside memory tags.

---

### AG-F08 — P3: Speculative Transaction Rollback Lacks Filesystem Atomicity

**Location:** [`src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs:505-555`](file:///c:/C_AGENT_BUILDER/src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs#L505-L555)

**The Limitation:**
`TransactionalScope` executes `primaryCommand`, evaluates whether stdout contains an `Assertion` string, and runs `rollbackCommand` if the assertion fails.
- This is a **compensatory transaction**, not an ACID rollback.
- If the primary script modifies files, changes registry keys, or kills processes, and then crashes due to an out-of-memory error, job kill-on-close, or timeout, the `rollbackCommand` may never execute.
- If `rollbackCommand` itself errors or lacks idempotency, the host remains in an inconsistent state.

**Remediation:**
For critical enterprise file operations, leverage Windows Volume Shadow Copies (VSS) or provision a transient `NtAclJailManager` workspace where changes occur strictly in a sandboxed directory and are copied to destination only upon assertion commit.

---

## 4. Strategic Comparison: SPLAT vs. Competitors

```
               [ High Orchestration / Low Containment ]
                                    ▲
                                    │      ● n8n
                                    │      ● Activepieces
                                    │      ● Windmill
                                    │
                                    │
  ◄─────────────────────────────────┼─────────────────────────────────►
  [ Low OS Enforced Moat ]          │          [ High OS Enforced Moat ]
                                    │
                                    │      ★ SPLAT
                                    │        (Kernel BPF-LSM + Job Objects +
                                    │         DLP + Merkle Audit + Flow)
                                    │      ● E2B / Daytona (MicroVMs)
                                    ▼
               [ Low Orchestration / High Containment ]
```

### The Commercial Reality: Don't Build n8n, Secure It

| Dimension | n8n / LangGraph / Activepieces | E2B / Modal / Daytona | SPLAT (with SPLAT Flow) |
| :--- | :--- | :--- | :--- |
| **Execution Environment** | Unconstrained Node.js host / shared Docker container | Ephemeral Firecracker microVMs (Cloud / BYOC) | **Local bare-metal OS containment** (Win32 Job Object + Linux BPF-LSM) |
| **Data Sovereignty** | Workload exported to cloud / containers | Workload exported to microVM cluster | **100% on-prem / local host execution** (crucial for HIPAA/DoD) |
| **Connector Breadth** | 400+ SaaS connectors | General Python/Node SDK | **Native endpoint diagnostic CLI tools** + Flow triggers |
| **Security Guarantees** | Application-layer prompts / user RBAC | MicroVM hardware boundary | **1:1:1 OS capability lease**, hard CPU/RAM caps, in-memory DLP |
| **Audit Defense** | Application event logs | VM session logs | **Cryptographically chained SHA-256 Merkle ledger** |

### The Strategic Recommendation:
Attempting to replicate n8n's 400+ API integrations is a strategic trap. SPLAT's undeniable market wedge is:
> **"The Zero-Trust Execution Airbag for Enterprise AI."**  
> Let n8n, LangGraph, or Claude Code handle high-level logic, but route every single privileged command, file read, and endpoint probe through SPLAT's locked room.

---

## 5. Prioritized Remediation Roadmap

```
PHASE 1: Immediate Safety (P1 Fixes)
├── 1. Add loopback API authorization token to EmbeddedWebhookListener (:5678)
├── 2. Fix SqliteChainedAuditLedger to verify HMAC(Details, DetailsSalt) == DetailsCommitment
└── 3. Move ResolveActorAsync to pre-execution entry in McpServerHandler

PHASE 2: Protocol & DLP Hardening (P2 Fixes)
├── 1. Add CSRF state nonce tracking to OAuthCallbackCoordinator
├── 2. Add raw token regex rules (AWS, GitHub, JWT, Stripe, OpenAI) to DLP sanitizer
└── 3. Wrap recalled vector memories in untrusted XML delimiters

PHASE 3: Enterprise Integration
├── 1. Build an authenticated n8n Community Node / LangGraph Tool connecting to SPLAT
└── 2. Implement ephemeral directory scratch overlays for TransactionalScope
```

---

*This audit represents an empirical, adversarial evaluation of the repository state as of September 5, 2026. SPLAT possesses a defensible, mathematically grounded core; executing the Phase 1 remediations will elevate it from an internal prototype to an enterprise-grade security substrate.*
