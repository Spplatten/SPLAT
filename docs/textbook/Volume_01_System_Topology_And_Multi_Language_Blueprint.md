# Volume 01: System Topology & Multi-Language Blueprint

## Master Table of Contents
1. [Architectural Paradigm: The Zero-Trust Agent Runtime](#1-architectural-paradigm-the-zero-trust-agent-runtime)
2. [Multi-Tier System Topology & Interconnect Fabric](#2-multi-tier-system-topology--interconnect-fabric)
3. [Repository Taxonomy & Compilation Artifacts](#3-repository-taxonomy--compilation-artifacts)
4. [Toolchains & Cross-Compilation Pipelines](#4-toolchains--cross-compilation-pipelines)
5. [Process Bootstrapping & Configuration Lifecycles](#5-process-bootstrapping--configuration-lifecycles)
6. [Line-by-Line Code Breakdown: Entry Points](#6-line-by-line-code-breakdown-entry-points)
7. [Step-by-Step Numerical Walkthrough: Bootstrapping Addresses & State Transitions](#7-step-by-step-numerical-walkthrough-bootstrapping-addresses--state-transitions)
8. [Interactive University Checkpoints & Debugging Puzzles](#8-interactive-university-checkpoints--debugging-puzzles)

---

## 1. Architectural Paradigm: The Zero-Trust Agent Runtime

Modern autonomous artificial intelligence systems operate by receiving unstructured natural language directives, decomposing objectives into task graphs, and executing native system utilities (`whoami.exe`, `netstat.exe`, `wevtutil.exe`, `sh`, `curl`, `python3`) to observe or mutate host infrastructure. In traditional agent architectures, containment is implemented at the application layer—typically through prompt system rules, regular expression pattern guards, and user-space API wrappers.

From an operating systems and security perspective, **user-space guardrails are fundamentally flawed**. When an untrusted input channel (such as a retrieved web page, log entry, or database query) is evaluated by an LLM alongside instructional prompts, adversarial text can trigger **prompt injection**. At the microsecond of compromise, the agent’s execution intent mutates. Because application-level filters execute within the *same security context and privilege ring* as the agent interpreter itself, an adversary who controls the agent’s generation stream can bypass user-space guards entirely.

```
TRADITIONAL RUNTIMES (FLAWED BOUNDARY):
+-----------------------------------------------------------------------------+
| User Space (Ring 3)                                                         |
|  [ Untrusted Agent ] <---- Prompt Injection Exploitation                    |
|         │                                                                   |
|         ▼ (Co-located, Same Privilege)                                      |
|  [ Regex Guards / Guardrails ] <--- BYPASSED (Attacker controls interpreter)|
|         │                                                                   |
|         ▼                                                                   |
|  [ Direct Host Execution / Unchecked OS API Calls ]                         |
+-----------------------------------------------------------------------------+
| Kernel Space (Ring 0): Grants Full Privileges Borrowed from User Process    |
+-----------------------------------------------------------------------------+

SPLAT RUNTIME (IN-KERNEL CAPABILITY LEASE):
+-----------------------------------------------------------------------------+
| User Space (Ring 3)                                                         |
|  [ Untrusted Agent ]                                                        |
|         │                                                                   |
|         ▼                                                                   |
|  [ SPLAT Host Control Plane ] ─── 1:1:1 Governance Compilation             |
|         │                                                                   |
|         ▼ Suspended Spawn / Cgroup v2 Migration                             |
|  [ Sandboxed Sensor Process ]                                               |
+═════════════════════════════════════════════════════════════════════════════+
| KERNEL BOUNDARY ENFORCEMENT                                                 |
|                                                                             |
| Windows (Win32 Kernel Objects):                                             |
|   • Job Object: Hard Working Set Clamps (256 MB) & Active Process Caps (32) |
|   • Restricted Token: SeChangeNotifyPrivilege only, Admin SID Deny-Only    |
|   • AppContainer: Zero Capability SIDs -> Complete Network Stack Severance  |
|                                                                             |
| Linux (eBPF-LSM on Stock WSL2 Kernel 6.18+):                                |
|   • bprm_check_security -> Inode allow-list enforcement (-EPERM)            |
|   • file_open           -> Protected inode denial (/etc/shadow) (-EPERM)    |
|   • socket_connect      -> IPv4 endpoint clamp (/32 IP + Port) (-EPERM)     |
+-----------------------------------------------------------------------------+
```

The SPLAT architecture establishes that **containment must exist strictly below the agent**. Rather than attempting to divine whether an agent has been injected, SPLAT treats every agent as potentially hostile and enforces a **deterministic capability lease**: a strictly bounded, non-renewable window of time, CPU, memory, filesystem, and network authority. If an agent attempts an action outside its lease, the host kernel object manager terminates or refuses the call with `-EPERM`.

---

## 2. Multi-Tier System Topology & Interconnect Fabric

The SPLAT system topology spans multiple distinct execution environments, runtimes, and operating systems:

```
+---------------------------------------------------------------------------------------------------+
| WINDOWS HOST ENVIRONMENT (NT 10.0.26200+)                                                          |
|                                                                                                   |
|  +─────────────────────────+      +────────────────────────────────────────────────────────────+  |
|  | MissionController.UI    |      | splat-mcp (Autonomous Headless Server)                     |  |
|  | WinUI 3 Desktop Console |      | stdio JSON-RPC 2.0 Interface (12 Governed Tools)           |  |
|  +────────────┬────────────+      +─────────────────────────────┬──────────────────────────────+  |
|               │                                                 │                                 |
|               └───────────────────────┬─────────────────────────┘                                 |
|                                       ▼                                                           |
|                       +───────────────────────────────+                                           |
|                       |   MissionController.Core      |                                           |
|                       |   Governed Execution Engine   |                                           |
|                       +───────────────┬───────────────+                                           |
|                                       │                                                           |
|             ┌─────────────────────────┴─────────────────────────┐                                 |
|             ▼                                                   ▼                                 |
|  +──────────────────────────────────+        +──────────────────────────────────+                 |
|  | Infrastructure.Windows           |        | Infrastructure.Linux             |                 |
|  | - SuspendedProcessLauncher       |        | - WslLeasedExecutor              |                 |
|  | - Win32JobSandbox                |        | - TemplatePolicyCompiler         |                 |
|  | - RestrictedTokenProvider        |        | - WslSubstrateHealthChecker      |                 |
|  | - NtAclJailManager               |        +─────────────────┬────────────────+                 |
|  | - SensorAppContainer             |                          │ Loopback TCP / VSOCK             |
|  +──────────────────────────────────+                          │ Port 50051 (Framed JSON-RPC)     |
+────────────────────────────────────────────────────────────────┼──────────────────────────────────+
                                                                 │
                                                                 ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LINUX GUEST VM (WSL2 Hyper-V Isolation: 6.18.33.2-microsoft-standard-WSL2)                         |
|                                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────────────────────+  |
|  | splat-agent Daemon (Rust tokio, libbpf-rs 0.24, UID 0 / CAP_BPF / CAP_SYS_ADMIN)            |  |
|  | - PeerAuth: Root-owned /etc/splat/agent.token verification                                  |  |
|  | - LeaseManager: Active lease lifecycle & deterministic 1-second reaper                      |  |
|  | - EphemeralCgroup: /sys/fs/cgroup/splat-missions/ leaf creation & resource limits            |  |
|  | - RingBuffer Poll: /sys/fs/bpf ring buffer drain thread                                     |  |
|  +──────────────────────────────────────────────┬──────────────────────────────────────────────+  |
|                                                 │                                                 |
|                   ┌─────────────────────────────┴─────────────────────────────┐                   |
|                   ▼                                                           ▼                   |
|  +──────────────────────────────────+               +──────────────────────────────────+          |
|  | Linux Security Module (eBPF-LSM) |               | Sandboxed Workload Subprocess    |          |
|  | lease_lsm.bpf.c                  |               | Forked Child (pre_exec join)     |          |
|  | - bprm_check_security            | ── -EPERM ──> | - PID joined to cgroup v2        |          |
|  | - file_open                      |               | - supplementary groups cleared   |          |
|  | - socket_connect                 |               | - setresgid/setresuid to nobody  |          |
|  | - BPF RingBuffer (violations)    |               | - execve("/bin/tool", argv)      |          |
|  +──────────────────────────────────+               +──────────────────────────────────+          |
+---------------------------------------------------------------------------------------------------+
```

### Communication Boundaries and Invariants
1. **Windows Native Path**: Fully contained on the Windows host. Uses native Win32 system APIs via P/Invoke. Execution remains in the host operating system, clamped by Win32 Job Objects and low-privilege tokens.
2. **Linux Substrate Bridge**: Crossed exclusively by `splat-mcp` via `WslLeasedExecutor`. Communication occurs over loopback TCP (or Hyper-V VSOCK), serializing lease specifications and piping standard streams and violation telemetry asynchronously.
3. **Control Isolation**: The WinUI 3 desktop console does not reference `MissionController.Infrastructure.Linux`. Only `splat-mcp` connects to the Linux guest daemon.

---

## 3. Repository Taxonomy & Compilation Artifacts

The repository adheres to a strict separation of concerns across managed C# assemblies, native Rust crates, C eBPF kernel code, and supporting test suites:

```
c:\C_AGENT_BUILDER\
├── MissionController.sln                  # Master Visual Studio solution binding all .NET projects
├── src\
│   ├── MissionController.Core\           # Domain abstractions, models, contracts, and engines
│   │   ├── Brain\                         # AgentBrainEngine: LLM natural-language goal decomposition
│   │   ├── Crew\                          # GovernedCrewEngine: multi-agent task execution
│   │   ├── QualityIsland\                 # Output validation, grounding verification, and scoring
│   │   ├── Workflow\                      # WorkflowExecutionEngine: directed acyclic graph executor
│   │   ├── GovernedArgumentBinder.cs      # Single-pass regex parameter binder & injection firewall
│   │   ├── GovernedInvestigationLoop.cs   # Bounded ReAct investigation loop
│   │   ├── MissionExecutionEngine.cs      # 1:1:1 mission lifecycle pipeline
│   │   └── Models.cs                      # Immutable records (SingleToolTemplate, LeaseSpec, etc.)
│   │
│   ├── MissionController.Infrastructure.Windows\ # Windows containment primitives
│   │   ├── JobObjects\                    # Win32JobSandbox: Job Object lifecycle and memory/CPU limits
│   │   ├── Jails\                         # NtAclJailManager: inheritance-severed NTFS directory jails
│   │   ├── Process\                       # SuspendedProcessLauncher: CreateProcessW in CREATE_SUSPENDED
│   │   ├── Security\                      # RestrictedTokenProvider & SensorAppContainer
│   │   ├── Native\Win32Interop.cs         # P/Invoke structs, enums, and kernel32/advapi32/userenv imports
│   │   └── Vault\DpapiCredentialVault.cs  # Cryptographic secret storage via Windows DPAPI
│   │
│   ├── MissionController.Infrastructure.Linux\   # WSL2 / eBPF guest orchestration
│   │   ├── WslLeasedExecutor.cs           # Socket transport client & JSON-RPC stream multiplexer
│   │   ├── TemplatePolicyCompiler.cs      # Transforms SingleToolTemplate into kernel LeaseSpec
│   │   ├── WslAgentToken.cs               # Host-side credential reader for /etc/splat/agent.token
│   │   └── WslSubstrateHealthChecker.cs   # Diagnostic verification of WSL2 kernel configuration
│   │
│   ├── MissionController.Infrastructure.Data\    # Persistence, audit ledger, and vector memory
│   │   ├── Audit\SqliteChainedAuditLedger.cs # SHA-256 chained hash ledger & Merkle engine
│   │   ├── Catalog\                       # GovernedTemplateCatalog: 40+ built-in operational templates
│   │   └── Vector\SqliteSemanticMemoryIndex.cs # Local 128-dim vector embeddings & cosine search
│   │
│   ├── MissionController.Infrastructure.Network\ # DLP, Egress Firewall, and AI Gateway
│   │   ├── Ai\                            # ClaudeStreamClient & GeminiStreamClient implementations
│   │   ├── Dlp\RegexDataLossPreventionSanitizer.cs # In-memory pre-egress regex redaction engine
│   │   └── EgressFirewallHandler.cs       # DelegatingHandler enforcing strict destination FQDN allow-lists
│   │
│   ├── MissionController.UI\              # WinUI 3 / Windows App SDK 1.6 desktop management console
│   │   ├── Views\                         # XAML windows and pages (Dashboard, SecurityHub, Studio)
│   │   └── ViewModels\                    # MVVM viewmodels with CommunityToolkit observable properties
│   │
│   ├── splat-mcp\                         # Model Context Protocol (MCP) server
│   │   ├── McpServerHandler.cs            # JSON-RPC dispatcher exposing 12 governed tools
│   │   ├── WorkspaceGuard.cs              # Canonical path containment for fs_read / fs_write
│   │   └── Program.cs                     # Standalone CLI entry point and hand-wired composition root
│   │
│   └── splat-bench\                       # Microbenchmark harness measuring Windows sandbox overhead
│
├── native\
│   ├── splat-agent\                       # Resident Linux eBPF daemon
│   │   ├── Cargo.toml                     # Rust dependency manifest (tokio, libbpf-rs 0.24, serde)
│   │   ├── build.rs                       # Compiles lease_lsm.bpf.c to skeleton via libbpf-cargo
│   │   └── src\
│   │       ├── main.rs                    # Daemon event loop, TCP server, and child pre_exec launcher
│   │       ├── lease.rs                   # LeaseManager, inode conversion, and BPF map updater
│   │       ├── cgroup.rs                  # Ephemeral cgroup v2 subtree controller and limit validator
│   │       ├── auth.rs                    # 0600 root-owned token validator
│   │       ├── violation.rs               # Deserializer for struct violation_event
│   │       └── bpf\
│   │           ├── lease_lsm.bpf.c        # In-kernel BPF-LSM security hooks
│   │           └── vmlinux.h              # Kernel type definitions generated via BTF
│   │
│   └── splat-canary\                      # Minimal verification harness confirming -EPERM hooks
│
└── tests\
    └── MissionController.Tests\           # 505 xUnit unit, integration, and security verification tests
```

---

## 4. Toolchains & Cross-Compilation Pipelines

Building SPLAT requires synchronizing three distinct compiler toolchains across Windows and Linux:

```
+----------------------------------------------------------------------------------------------------+
| 1. .NET 10 / MSBUILD TOOLCHAIN (WINDOWS HOST)                                                      |
|                                                                                                    |
|  [ *.cs Source Files ] ───> Roslyn Compiler (csc) ───> MSIL Bytecode                               |
|                                                            │                                       |
|                                                            ▼                                       |
|  Target Frameworks:                                   Single-File Publish Engine                   |
|    - net10.0-windows10.0.19041.0 (Libraries & MCP)          │                                       |
|    - net9.0-windows10.0.19041.0 (WinUI 3 Console)           ▼                                       |
|                                                       dist\splat-mcp.exe (74 MB Native Packed PE)  |
+----------------------------------------------------------------------------------------------------+

+----------------------------------------------------------------------------------------------------+
| 2. RUST / CARGO TOOLCHAIN (LINUX GUEST / WSL2)                                                     |
|                                                                                                    |
|  [ *.rs Source Files ] ───> rustc (LLVM Backend) ────> ELF x86_64 Native Daemon Executable         |
|                                                            ▲                                       |
|                                                            │ Links Auto-Generated Rust Bindings    |
|                                                            │                                       |
+------------------------------------------------------------┼────────────────────────────────-------+
| 3. CLANG / LIBBPF-CARGO BPF TOOLCHAIN                      │                                       |
|                                                            │                                       |
|  [ lease_lsm.bpf.c ] + [ vmlinux.h ]                       │                                       |
|          │                                                 │                                       |
|          ▼ Clang Target (-target bpf -O2 -g)               │                                       |
|  [ lease_lsm.bpf.o ] (eBPF Bytecode ELF Object)            │                                       |
|          │                                                 │                                       |
|          ▼ libbpf-cargo / bpftool                          │                                       |
|  [ lease_lsm.skel.rs ] (CO-RE Skeleton & Map Accessors) ───┘                                       |
+----------------------------------------------------------------------------------------------------+
```

### Build Invocation Commands
1. **Windows Assemblies (`dotnet`)**:
   ```powershell
   # Compile entire solution in Release configuration
   dotnet build MissionController.sln -c Release
   
   # Publish self-contained, single-file MCP server executable
   powershell -ExecutionPolicy Bypass -File packaging\publish-splat-mcp.ps1
   ```
2. **Linux eBPF Daemon (`cargo` in WSL2)**:
   ```bash
   # Build eBPF skeleton and resident daemon
   cd native/splat-agent
   cargo build --release
   ```
   During `cargo build`, `build.rs` invokes `libbpf-cargo` to compile `src/bpf/lease_lsm.bpf.c` against `vmlinux.h` using Clang with BPF target flags (`-target bpf -g -O2`), generating the Rust skeleton file in `$OUT_DIR/lease_lsm.skel.rs`.

---

## 5. Process Bootstrapping & Configuration Lifecycles

### The `splat-mcp` Bootstrapping Lifecycle
When an AI agent client (such as Claude Code, Cursor, or an autonomous orchestrator) launches `splat-mcp`, the process initializes according to a strict fail-closed contract:

```
[ CLI Invocation: splat-mcp --workspace <dir> --egress <ip:port> ]
                             │
                             ▼
              [ McpServerCommand.Parse(args) ]
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
     [ ShowHelp / UsageError ]         [ Valid Serve Command ]
     Print to stderr / Exit (2)              │
                                             ▼
                             [ Configure Console Streams ]
                             Console.OutputEncoding = UTF-8
                             Console.InputEncoding  = UTF-8
                             (Stdout strictly reserved for JSON-RPC)
                                             │
                                             ▼
                             [ Data Layer Initialization ]
                             - SQLite Storage Context (audit_ledger.db)
                             - Chained Audit Ledger (SHA-256)
                             - Template Registry Seeding (40+ templates)
                             - Local Semantic Memory Index (128-dim)
                                             │
                                             ▼
                             [ Security Subsystem Bootstrapping ]
                             - RestrictedTokenProvider
                             - NtAclJailManager
                             - SuspendedProcessLauncher
                             - RegexDataLossPreventionSanitizer
                             - DpapiCredentialVault
                                             │
                                             ▼
                             [ AI Gateway & Hardened HTTP Client ]
                             - EgressFirewallHandler
                             - ClaudeStreamClient & GeminiStreamClient
                             - ModelClientRouter
                                             │
                                             ▼
                             [ Core Execution Engines ]
                             - MissionExecutionEngine
                             - GovernedInvestigationLoop
                             - AgentBrainEngine
                                             │
                                             ▼
                             [ Enter stdio JSON-RPC Event Loop ]
```

---

## 6. Line-by-Line Code Breakdown: Entry Points

### 6.1 `src/splat-mcp/Program.cs`
The entry point of the standalone MCP server illustrates how the system establishes invariants before allocating any system resources.

```csharp
// Lines 31-48: Early CLI Command Parsing
public static async Task<int> Main(string[] args)
{
    // Decided before anything is built: a bad invocation must not create the ledger database,
    // seed the catalog or reach for the daemon. stdout is the JSON-RPC channel, so everything that
    // is not a protocol message - errors, and the startup note - goes to stderr.
    var command = McpServerCommand.Parse(args);
    if (command is McpServerCommand.ShowHelp)
    {
        Console.Out.Write(McpServerCommand.Usage);
        return 0;
    }

    if (command is McpServerCommand.UsageError error)
    {
        Console.Error.WriteLine($"splat-mcp: {error.Message}");
        Console.Error.WriteLine("Run 'splat-mcp --help' for usage.");
        return McpServerCommand.UsageExitCode;
    }
```
*Architectural Rationale:* The Model Context Protocol mandates that `stdout` carry pure, unadulterated JSON-RPC messages. If unhandled exceptions, debug prints, or startup banners were emitted to `stdout`, the client’s JSON parser would desynchronize and terminate the connection. SPLAT routes all diagnostic logging and errors exclusively to `stderr`.

```csharp
// Lines 53-55: Strict UTF-8 Stream Enforcement
    Console.OutputEncoding = Encoding.UTF8;
    Console.InputEncoding = Encoding.UTF8;
```
*Architectural Rationale:* Windows consoles default to OEM code pages (such as CP437 or CP1252). Failure to explicitly force UTF-8 leads to byte corruption when serializing Unicode paths, mathematical symbols, or international character sets across the stdio pipe.

```csharp
// Lines 70-76: SQLite & Audit Ledger Initialization
    string dbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT", "audit_ledger.db");
    var storageContext = new SqliteStorageContext(dbPath);
    var auditLedger = new SqliteChainedAuditLedger(storageContext);
    var templateRegistry = new SqliteTemplateRegistry(storageContext);
    var semanticMemory = new SqliteSemanticMemoryIndex(storageContext);
```
*Architectural Rationale:* Before accepting any tool execution request, SPLAT ensures that its tamper-evident audit ledger and template registries are operational. Every subsequent tool execution, rejection, or error is cryptographically recorded in this database.

---

### 6.2 `native/splat-agent/src/main.rs`
The Linux daemon entry point demonstrates the initialization of the eBPF subsystem and fail-closed validation.

```rust
// Lines 248-265: Main Initialization & eBPF Skeleton Loading
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Starting SPLAT Resident eBPF Containment Daemon on {}", args.listen);

    let (viol_tx, _viol_rx) = broadcast::channel::<ViolationEvent>(128);
    let mut bpf_sync: Option<Arc<dyn BpfMapSync>> = None;

    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        warn!("Running unprivileged. In-kernel BPF-LSM hooks require CAP_BPF / CAP_SYS_ADMIN.");
    } else if !args.mock_bpf {
        info!("Initializing in-kernel BPF-LSM capability lease skeleton...");
        let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
        let skel_builder = LeaseLsmSkelBuilder::default();
        match skel_builder.open(open_object) {
            Ok(open_skel) => match open_skel.load() {
                Ok(mut skel) => match skel.attach() {
                    Ok(_) => {
                        info!("BPF-LSM programs attached successfully.");
                        let skel = Box::leak(Box::new(skel));
```
*Architectural Rationale:* The daemon utilizes CO-RE (Compile Once – Run Everywhere) via `libbpf-rs`. The BPF program must be opened, loaded into the kernel (where the kernel's in-kernel verifier proves memory safety), and attached to the corresponding LSM hook points (`lsm/bprm_check_security`, `lsm/file_open`, `lsm/socket_connect`). `Box::leak` ensures the skeleton structures remain pinned in memory for the static lifetime of the daemon process.

```rust
// Lines 328-334: Fail-Closed Kernel Enforcement Gate
    if bpf_sync.is_none() && !args.mock_bpf {
        error!(
            "Refusing to start: BPF-LSM enforcement is not live{}. Re-run as root on a BPF-LSM kernel, or pass --mock-bpf for a daemon that openly does not contain anything.",
            if is_root { "" } else { " (not running as root)" }
        );
        std::process::exit(1);
    }
```
*Architectural Rationale:* **Fail closed.** If the daemon cannot acquire live handles to the BPF maps, it aborts immediately with exit code 1. A resident process that accepts execution requests when its security hooks are non-functional is not a degraded sandbox; it is an arbitrary remote code execution backdoor.

---

## 7. Step-by-Step Numerical Walkthrough: Bootstrapping Addresses & State Transitions

Consider a typical startup and execution lifecycle on an x86-64 host. The table below traces memory addresses, CPU register states, and data payloads during the bootstrapping sequence.

| Step | Component / Subsystem | Virtual Address / Register | Hex / Binary Payload | Description |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `splat-mcp.exe` Entry | `RIP = 0x00007FF71A401000` | `48 83 EC 28` (`sub rsp, 40`) | Process begins execution in user mode. Allocates shadow stack space. |
| **2** | CLI Argument Parser | `R8 = 0x000001D400201040` | `"--workspace"` | Evaluates command-line arguments passed by agent client. |
| **3** | `WslLeasedExecutor` | `Socket FD = 0x00000000000001A4` | `AF_INET, 127.0.0.1:50051` | Connects over TCP loopback to Linux guest daemon. |
| **4** | `splat-agent` Listener | `0x00007FFF50100000` | `0x000000000000C383` (Port 50051) | Linux kernel signals socket accept event on listening thread. |
| **5** | Token Validation | `0x00007FFF50201080` | `SHA256(Secret)` | Verifies 32-byte hex shared secret read from `/etc/splat/agent.token`. |
| **6** | eBPF Skeleton Attachment | `FD = 0x0000000000000007` | `BPF_PROG_TYPE_LSM` | Kernel confirms attachment to `bprm_check_security`. |
| **7** | Cgroup Allocation | `/sys/fs/cgroup/splat-missions/1` | `cgroup_id = 0x000000000000104A` | Kernel assigns 64-bit unique cgroup inode identifier `4170`. |

---

## 8. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 1.1: The Silent Failure of Unchecked Return Values
**Scenario:** A junior systems developer modifies `splat-agent` to eliminate the `Box::leak` call on the BPF skeleton, allowing the skeleton variable to fall out of scope at the end of the initialization block. When testing with an allow-listed executable, the command succeeds. When testing an unleased executable, the unleased executable *also* succeeds.
- **Question:** What occurred at the kernel boundary when the skeleton fell out of scope, and why did the system silently permit forbidden actions rather than crashing?
- **Solution:** In `libbpf-rs`, dropping an attached skeleton triggers the `Drop` implementation of the underlying `Link` objects, which invokes the `bpf_link_detach` or `close(link_fd)` syscall. This automatically unhooks the BPF-LSM programs from the kernel hooks (`bprm_check_security`). Because the hooks were no longer registered, the Linux Security Module framework defaulted to standard Discretionary Access Control (DAC), permitting any binary executable by the current UID without evaluating the lease maps.

### Checkpoint 1.2: The stdio Pollution Bug
**Scenario:** A developer adds a telemetry tracing macro `println!("[DEBUG] Lease created for mission: {}", mission_id);` inside `splat-mcp`'s tool dispatcher. Immediately, all MCP clients (Claude Code, IDE agents) report `Fatal JSON-RPC Parse Error` and refuse to interact with SPLAT.
- **Question:** Why does writing a simple diagnostic log string to stdout cause catastrophic failure in an MCP-compliant architecture?
- **Solution:** MCP communicates over stdio using line-delimited or Content-Length framed JSON-RPC 2.0. The client’s reader expects every byte on `stdout` to parse into a valid JSON object (`{"jsonrpc": "2.0", ...}`). Emitting unstructured plain text (`[DEBUG] ...`) corrupts the framing stream, causing the client's JSON parser to throw an unrecoverable deserialization exception and terminate the session. All diagnostics must be directed strictly to `stderr`.
