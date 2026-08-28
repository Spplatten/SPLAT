# Scope of Work (SOW): Enterprise IT Mission Controller (SPLAT)

**Project Identity:** AI-Native IT & SysOps Mission Controller (SPLAT)  
**Target Platform:** Windows 10/11 Enterprise & Pro (Microsoft Intune / SCCM Managed)  
**Primary Runtime & Stack:** C# 13 / .NET 9 LTS, WinUI 3 (Windows App SDK 1.6), Native Win32 Interop  
**Execution Paradigm:** Trunk-First, Zero-Mock Production Pipeline  

---

## 1. Executive Summary & Core Objective

The Enterprise IT Mission Controller (SPLAT) is a governed, native Windows desktop appliance engineered for Enterprise IT, SecOps, and Campus Systems Administration teams. It bridges frontline operational diagnostics with production-grade AI reasoning models.

The software standardizes institutional runbooks into signed, declarative 1:1:1 execution templates (1 Template $\rightarrow$ 1 Model $\rightarrow$ 1 Dedicated Native Tool $\rightarrow$ 1 Allowed Egress FQDN), executing tools inside low-privilege Win32 Job Object sandboxes and streaming real-time diagnostic synthesis to frontline operators without data leaks, code editing, or administrative privilege escalation.

---

## 2. Updated Project Boundaries & Architectural Constraints

```
+===================================================================================================+
|                                  SPLAT BOUNDARY & INTEGRATION TOPOLOGY                            |
+===================================================================================================+
|                                                                                                   |
|  [ IN-SCOPE PRODUCTION DELIVERABLES ]                                                             |
|  ├── Live-First Dual Model Gateway (Live Anthropic Messages + Google Gemini SSE Stream)           |
|  ├── Strict 1:1:1 Template Runtime Engine (Zero Multi-Agent Swarms / Zero Recursive Loops)        |
|  ├── Bounded Sequential Project Playbooks (maximum 6 governed agent stages, no dynamic loops)    |
|  ├── Zero-Mock Hard Error Boundaries (Hard stop on missing keys; zero simulated output)           |
|  ├── Win32 Job Object Process Clamping (CREATE_SUSPENDED -> AssignToJob -> ResumeThread)          |
|  ├── Hardened NT ACL Directory Jails (%LOCALAPPDATA%\MissionController\Jails\{MissionId})         |
|  ├── Windows DPAPI Credential Vault (CurrentUser scope + cryptographic memory zeroing)            |
|  ├── In-Memory Egress Firewall (DelegatingHandler matching active template FQDN)                  |
|  ├── Native SChannel & Enterprise Proxy Auto-Traversal (WPAD/PAC/Zscaler TLS root trust)          |
|  ├── Embedded SQLite Engine (WAL Mode) + Sequential SHA-256 Chained Hash Audit Ledger             |
|  ├── Reactive WinUI 3 Desktop Shell (Catalog, Tuning Cards, Live Monitor, Audit Explorer)        |
|  └── Enterprise MSIX Package (runFullTrust, Intune/SCCM silent deploy ready)                      |
|                                                                                                   |
|  [ EXPLICIT ARCHITECTURAL EXCLUSIONS ]                                                            |
|  ├── Simulated fallback modes, mock token generators, and placeholder demo responses              |
|  ├── Cross-platform desktop targets (macOS / Linux desktop)                                      |
|  ├── Multi-agent recursive DAG routing, agent swarms, and open-ended debate loops                 |
|  ├── IDE capabilities (code editors, terminal emulators, dynamic script debuggers)                |
|  ├── Dormant enterprise identity code (PKCE loopback quarantined until enterprise tenant phase)   |
|  └── External database servers (remote PostgreSQL / MongoDB / Redis clusters)                     |
+===================================================================================================+
```

---

## 3. Phased Execution Roadmap (Trunk-First Sequencing)

```
[ Phase 1: Live Vertical Slice ] ──► [ Phase 2: Kernel & Sandbox Hardening ]
                                                     │
                                                     ▼
[ Phase 4: WinUI 3 Shell & MVVM ] ◄── [ Phase 3: Governed Data & Chained Ledger ]
               │
               ▼
[ Phase 5: MSIX & Enterprise DoD ]
```

### Phase 1: The Live-First Vertical Slice (Zero Mock Baseline)
* **Live Model Gateway (`IModelStreamClient`):** Direct HTTPS/SSE streaming implementation targeting Anthropic Messages API (`claude-3-5-sonnet` / `claude-opus`) and Google Gemini API (`gemini-2.5-flash` / `gemini-2.5-pro`).
* **Zero-Mock Key Enforcement:** Implement `ProviderKeyClassifier` and direct DPAPI resolution. If no key is detected, the engine throws an explicit `AuthenticationRequiredException` and triggers the key entry dialog. All simulated responses and placeholder fallback paths are deleted.
* **Basic Native Process Invocation:** Launch a real compiled diagnostic utility (e.g., `netstat`, `ping`, or custom native `.exe`), capture live stdout/stderr, pipe the structured string into the live model context, and stream real tokens over `IAsyncEnumerable<string>`.

### Phase 2: Windows Kernel Hardening, Job Objects & NT ACL Jails
* **Win32 Job Object Interop:** P/Invoke bindings for `kernel32.dll` (`CreateJobObject`, `SetInformationJobObject`, `AssignProcessToJobObject`).
* **Suspended Startup Protocol:** Implement safe process instantiation via `CreateProcessW` with `CREATE_SUSPENDED` (0x00000004), bind to Job Object, apply `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (enforcing `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, memory limits, and `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`), then call `ResumeThread`.
* **NT ACL Filesystem Jailing:** Provision isolated directory at `%LOCALAPPDATA%\MissionController\Jails\{MissionId}\`. Strip inherited permissions via `SetAccessRuleProtection(true, false)` and grant exclusive `FileSystemAccessRule` only to the current user SID and worker process. Implement post-mission retry handle drain and startup orphan purges.
* **In-Memory Egress Firewall:** Custom `DelegatingHandler` pinned to Windows `SocketsHttpHandler` with SChannel certificate store integration and enterprise proxy resolution, dropping any outbound call not matching the active template's `AllowedEgressFqdn`.

### Phase 3: Governed 1:1:1 Template Engine & Chained Audit Ledger
* **1:1:1 Schema Validator:** Enforce strict validation rules on declarative JSON templates: exactly 1 Target Model, 1 Dedicated Native Executable Tool, and 1 Allowed Egress FQDN.
* **In-Process SQLite Engine:** Configure SQLite in WAL mode (`PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`).
* **Sequential SHA-256 Chained Hash Audit Worker:** Implement a dedicated single-threaded `System.Threading.Channels.Channel<AuditLogEntry>` background writer to eliminate WAL lock contention and compute tamper-evident hash chains:
  $$\text{EntryHash} = \text{SHA256}(\text{PreviousHash} \parallel \text{TimestampUtc} \parallel \text{MissionId} \parallel \text{Action} \parallel \text{Details})$$

### Phase 4: WinUI 3 Desktop Shell & MVVM Presentation
* **Presentation Architecture:** `CommunityToolkit.Mvvm` implementation using `ObservableObject` and `AsyncRelayCommand`.
* **Live Mission Monitor:** Real-time token streaming rendered via `DispatcherQueue.TryEnqueue` with live Job Object CPU and RAM metric meters.
* **Template Catalog & Guided Tuning Cards:** 3-to-5 field parameter input cards mapping directly to tool CLI arguments without exposing raw prompts or system instructions.
* **Security & Audit Explorer:** Interactive view of the SQLite ledger with one-click cryptographic hash-chain verification and tamper detection.

### Phase 5: MSIX Enterprise Packaging & Verification
* **Package Manifest Configuration:** Configure MSIX with `<rescap:Capability Name="runFullTrust" />` and `<desktop6:FileSystemWriteVirtualization>disabled</desktop6:FileSystemWriteVirtualization>`.
* **Enterprise Policy Compliance:** Validate silent Intune/SCCM deployment flags and verify zero EDR false positives on Microsoft Defender for Endpoint.

---

## 4. Total Final Product Clause

```
+===================================================================================================+
|                                    TOTAL FINAL PRODUCT CLAUSE                                     |
+===================================================================================================+
|                                                                                                   |
|  Upon final delivery and milestone sign-off, the SPLAT application shall constitute a complete,   |
|  self-contained, standalone Windows Enterprise desktop executable appliance.                      |
|                                                                                                   |
|  1. ABSOLUTE ZERO MOCK GUARANTEE:                                                                 |
|     No module, interface, view model, or service shall contain synthetic test data, hardcoded   |
|     token generators, or simulated fallback strings. All workflows must execute against live     |
|     operating system APIs and live AI model endpoints.                                            |
|                                                                                                   |
|  2. STANDALONE LOCAL RUNTIME:                                                                     |
|     The software shall operate without external server dependencies, database clusters, or        |
|     background daemon installations. All state, audit logs, vector indices, and template stores   |
|     shall reside entirely within an embedded in-process SQLite instance.                          |
|                                                                                                   |
|  3. COMPLETE ZERO-LEAK HARDENING:                                                                 |
|     The application must provably terminate 100% of spawned child processes on exit via native    |
|     Win32 Job Objects, enforce complete NT ACL filesystem isolation against system drives, and   |
|     block all unauthorized network egress attempts at the in-memory socket pipeline.              |
|                                                                                                   |
|  4. ENTERPRISE PACKAGING READINESS:                                                               |
|     The final artifact must be delivered as a signed, deployable MSIX bundle capable of silent   |
|     installation via Microsoft Intune or SCCM without requiring end-user administrator rights.   |
|                                                                                                   |
+===================================================================================================+
```

---

## 5. Acceptance Criteria & Definition of Done (DoD)

| Category | Production Acceptance Criteria |
| :--- | :--- |
| **Model Gateway** | Streams real token chunks from Anthropic Messages or Google Gemini APIs over `IAsyncEnumerable`. If an invalid key or network failure occurs, the engine raises a visible, unhandled error state—never canned or simulated text. |
| **Process Sandboxing** | Terminating the main application process instantly reaps all running child tools via the Win32 Job Object, leaving zero orphaned processes in Task Manager. |
| **Filesystem Jail** | Any child tool attempting to read or write outside `%LOCALAPPDATA%\MissionController\Jails\{MissionId}` receives an explicit Win32 `ERROR_ACCESS_DENIED` (5). |
| **Egress Firewall** | Outbound HTTP calls targeting any domain other than the active template's `AllowedEgressFqdn` are dropped in memory by the `DelegatingHandler` and logged as security violations. |
| **Audit Ledger** | Any direct out-of-band edit or deletion of a row in the SQLite database causes the cryptographic verification tool to fail and display the exact corrupted block ID. |
| **Deployment** | The MSIX package installs cleanly under a standard (non-admin) corporate user profile via Intune and launches without UAC elevation prompts. |
