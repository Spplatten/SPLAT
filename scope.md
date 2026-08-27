# Scope of Work (SOW): Enterprise IT Mission Controller

**Project Identity:** AI-Native IT & SysOps Mission Controller (SPLAT)  
**Target Platform:** Windows 10/11 Enterprise & Pro (Intune / SCCM Managed)  
**Primary Language / Runtime:** C# 13 / .NET 9 LTS (Native WinUI 3 / Windows App SDK 1.6)  

---

## 1. Project Objectives & Deliverables

```
+===================================================================================================+
|                                    PROJECT SOW WORKFLOW & BOUNDARIES                              |
+===================================================================================================+
|                                                                                                   |
|  [ IN-SCOPE DELIVERABLES ]                                                                        |
|  ├── Core 1:1:1 Engine (1 Template -> 1 Model -> 1 Tool -> 1 Egress FQDN)                         |
|  ├── Win32 Job Object Subprocess Clamping (CREATE_SUSPENDED -> AssignToJob -> ResumeThread)       |
|  ├── NT ACL Filesystem Jailing (%LOCALAPPDATA%\MissionController\Jails\{MissionId})               |
|  ├── SChannel & Enterprise Proxy Traversal (WPAD, PAC, Zscaler TLS root inspection)               |
|  ├── Dual Identity Subsystem (RFC 8252 PKCE Loopback & IT Service Account JSON)                   |
|  ├── In-Memory Egress Firewall (Custom DelegatingHandler with FQDN blocking)                      |
|  ├── SQLite WAL Storage Engine + Sequential SHA-256 Chained Hash Audit Ledger                     |
|  ├── WinUI 3 Desktop Shell (Catalog, Tuning Cards, Live Monitor, Audit Viewer)                    |
|  └── MSIX Enterprise Deployment Package (runFullTrust, Intune silent install ready)               |
|                                                                                                   |
|  [ EXPLICIT OUT-OF-SCOPE EXCLUSIONS ]                                                             |
|  ├── Cross-platform desktop targets (macOS / Linux desktop)                                      |
|  ├── Multi-agent recursive DAG routing / agent debate swarms                                      |
|  ├── Open-ended developer IDE features (code editors, terminal emulators, syntax highlighters)   |
|  └── External database servers (remote PostgreSQL / MongoDB clusters)                            |
+===================================================================================================+
```

---

## 2. Phased Milestone Breakdown

### Phase 1: Windows Kernel Hardening & Filesystem Jailing (`Infrastructure.Windows`)
* **Win32 Job Object Sandboxing:**
  * P/Invoke bindings for `kernel32.dll` (`CreateJobObject`, `SetInformationJobObject`, `AssignProcessToJobObject`).
  * Enforce `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_JOB_MEMORY`, and `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`.
  * Safe suspended process startup: `CreateProcessW` with `CREATE_SUSPENDED` (0x00000004), bind to Job Object, then `ResumeThread`.
* **NT ACL Directory Jails:**
  * Provision dynamic directories at `%LOCALAPPDATA%\MissionController\Jails\{MissionId}\`.
  * Strip inherited drive permissions via `directorySecurity.SetAccessRuleProtection(true, false)`.
  * Grant exclusive `FileSystemAccessRule` only to the current user SID and sandbox worker.
  * Implement post-mission handle-release drain cycles with startup orphan cleanup routines.
* **Windows DPAPI Credential Vault:**
  * Token encryption via `ProtectedData.Protect` (`DataProtectionScope.CurrentUser`) with pinned byte arrays and cryptographic zeroing memory wipes.

### Phase 2: Enterprise Networking, Identity & Vertex AI (`Infrastructure.Network`)
* **Enterprise SChannel & Proxy Auto-Traversal:**
  * `SocketsHttpHandler` configured with `CertificateRevocationCheckMode = X509RevocationMode.Online`, `UseProxy = true`, and `DefaultProxyCredentials = CredentialCache.DefaultNetworkCredentials` for seamless Zscaler/Netskope inspection.
* **Dual Identity Subsystem:**
  * *Support A:* RFC 8252 PKCE loopback on `127.0.0.1:0` with default browser launch and local port binding.
  * *Support B:* Direct Enterprise Google Cloud Service Account JSON parser for pre-provisioned corporate tenants.
* **In-Memory Egress Firewall:**
  * Custom `DelegatingHandler` validating all outbound URIs against the active template's `allowed_egress_domain`.
* **Vertex AI SSE Streaming Client:**
  * `IAsyncEnumerable<string>` parser consuming `gemini-2.5-flash` / `gemini-2.5-pro` `streamGenerateContent` endpoints.

### Phase 3: In-Process Data & 1:1:1 Template Runtime (`Core` & `Data`)
* **Embedded SQLite WAL Engine:**
  * SQLite configured with `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, and single-instance file locking.
* **Tamper-Evident SHA-256 Audit Ledger:**
  * Sequential audit log worker backed by a bounded background `Channel<AuditLogEntry>` to eliminate WAL write contention.
  * Formula: $\text{EntryHash} = \text{SHA256}(\text{PreviousHash} \parallel \text{TimestampUtc} \parallel \text{MissionId} \parallel \text{Action} \parallel \text{Details})$.
* **1:1:1 Execution Pipeline Coordinator:**
  * Enforce strict contract: $\text{1 Template} \longrightarrow \text{1 Model} \longrightarrow \text{1 Dedicated Native Tool (.exe)} \longrightarrow \text{1 Allowed Egress FQDN}$.

### Phase 4: WinUI 3 Desktop Shell & MVVM ViewModels (`UI`)
* **MVVM Layer (`CommunityToolkit.Mvvm`):**
  * `MissionDashboardViewModel`: System health, active Win32 jobs, recent missions.
  * `TemplateCatalogViewModel`: Governed template selection and 3-to-5 field guided parameter tuning cards.
  * `LiveMissionMonitorViewModel`: Real-time streaming output dispatched via `DispatcherQueue.TryEnqueue` with live Job Object CPU/RAM meters.
  * `SecurityAuditViewModel`: Chained audit log explorer with one-click cryptographic verification.
  * `JailInspectorViewModel`: Active Win32 Job Objects, jailed processes, and filesystem isolation status.

### Phase 5: Packaging, MSIX & Enterprise Validation (`Packaging`)
* **MSIX Configuration:**
  * Package manifest configured with `<rescap:Capability Name="runFullTrust" />` and `<desktop6:FileSystemWriteVirtualization>disabled</desktop6:FileSystemWriteVirtualization>`.
* **Deployment Validation:**
  * Silent installation parameter validation for Microsoft Intune / SCCM deployment.
  * EDR baseline testing against Windows Defender for Endpoint.

---

## 3. Acceptance Criteria & Definition of Done (DoD)

| Category | Acceptance Criteria |
| :--- | :--- |
| **Sandboxing** | Killing the Mission Controller UI instantly terminates all running child tool processes via the Win32 Job Object with zero orphaned zombie processes. |
| **Filesystem Jail** | Child tool execution attempting to access `%USERPROFILE%\Documents` or `C:\Windows` throws an immediate Access Denied exception. |
| **Network Egress** | An outbound HTTP request targeting any domain other than the active template's `allowed_egress_domain` is dropped in-memory by the `DelegatingHandler`. |
| **Identity & Proxy** | Google Vertex AI streams tokens smoothly through enterprise Zscaler/MITM proxies without certificate validation failures. |
| **Audit Integrity** | Manually editing any row in the SQLite audit table triggers an instant integrity violation flag upon running the cryptographic verification tool. |
