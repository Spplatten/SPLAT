<!-- Written 2026-09-23 against the tree at 40caaa0. Every "State" below was read out of the code,
     the tests or a committed evidence file on that day, and each cell says which. Three things were
     run here, in a Linux container without a BPF-LSM kernel: the SHA-256 of both BPF sources
     against the hashes the evidence files name; `cargo test --release` in native/splat-agent
     (61 passed, 0 failed); and a wiring sweep (`git grep -lw <Type> -- src`). The xUnit suite needs
     a Windows host and was NOT run here; its count is the README's, which
     TheAdvertisedTestCount_MatchesTheSuite binds to the compiled assembly. Part 2 of the brief that
     asked for this record - the two governance templates - lives in ../RFC_TEMPLATE.md and
     ../EXECUTIVE_STATUS_TEMPLATE.md. -->

# Status gate and gap analysis — 2026-09-23

Two questions, answered against the tree rather than the documents: **where does each of the five
functional layers stand**, and **what are the highest-yield changes from here to an alpha or beta**.
The vocabulary is the repository's own: a boundary is enforced by a kernel object, a kernel LSM
hook, a check in SPLAT's process, or nobody. A capability is **Done** when a composition root
reaches it and evidence shows it holding; **In-Progress** when it is built but unwired, unproven, or
proven for a program that no longer ships; **Stub** when the target names something the tree does
not contain.

**The one fact that colours every Linux row.** The daemon's kernel program,
[`lease_lsm.bpf.c`](../../native/splat-agent/src/bpf/lease_lsm.bpf.c), hashes to `e7822f35…`
today. The two evidence files that prove the daemon and the last hop —
[`daemon-probe.json`](../../native/splat-agent/evidence/daemon-probe.json) and
[`last-hop-probe.json`](../../native/splat-agent/evidence/last-hop-probe.json) — both name
`8ac49790…`, the program as it stood on 2026-09-15. The canary's frozen copy still matches its
evidence (`0d222b98…`). So the standalone kernel proof stands, and everything that landed on the
daemon between 2026-09-20 and 2026-09-21 — the mount-namespace jail, the guest-side ceiling, the
datagram hook, the record's clock and counters — is **built and unproven**, exactly as the README
already says. `DocumentationDriftTests` is what keeps it saying so.

---

## Part 1 — the status gate

| Functional layer | Target capability | Status | Blocking gap |
| --- | --- | --- | --- |
| **Kernel / host sandbox** | Process quotas (cgroup / Job Objects), bounded execution leases | **In-Progress.** Windows quotas: Done. Linux lease: built through 2026-09-21, kernel proof pending since 2026-09-20 | Roadmap 2.3 — the root re-proof, which only the operator can run. Behind it: hooks that outlive the daemon (2.7) and caller identity on the bridge (2.4) |
| **Telemetry pipeline** | Ring-buffer event dispatch, zero-copy buffer reads (`Span<T>`) | **In-Progress.** Kernel → daemon ring buffer: Done, zero-copy by `#[repr(C)]` cast. Host-side `Span<T>` zero-copy path: **Stub, and a non-goal** by the continuum map | None on the critical path. Real gaps: the daemon's own frames are unproven (2.6); Windows containment emits no denial events at all; drops are counted host-wide, not per lease |
| **State machine engine** | In-process cyclic graph (`StateGraph<TState>`), channel dispatch | **Stub** against the target as written; **Done** against the project's invariant. `WorkflowGraph` is a DAG that *refuses* cycles; no `Channel<T>` dispatch exists; bounded loops live in the engines; cyclic graphs are delegated to the LangGraph adapter outside the process | A product decision, not code: the target contradicts "bounded composition, not swarms" and the one-execution-tier invariant. The workflow engine itself is built, registered in the console, resolved by no screen, and absent from `splat-mcp` |
| **Security & auth broker** | Dynamic token lifecycle, PKCE loopback, encrypted local vault | **In-Progress.** Vault: Done. Daemon peer auth (protocol 3): Done, proven 2026-09-15. Principal + revocation before effects: Done in both hosts. Token lifecycle: built, registered, called by nothing. PKCE loopback: built, Google-only, constructed by no host, dormant by decision | Caller identity on the bridge (2.4) — a shared secret identifies no caller; agents under an identity of their own (enterprise candidate); a key-custody story for the ledger and run-record keys |
| **Audit & forensic trail** | SHA-256 Merkle chain persistence (`IAuditLedger`), tamper evidence | **Done, with stated limits.** Persisted: a SHA-256 hash chain over salted commitments, HMAC-keyed once the operator gives a key. Merkle: computed at export, per-entry inclusion proofs, signed bundles verified on a live mission 2026-09-20 | Unkeyed and two chains per host **by default**; truncation caught only by a saved anchor, and nothing publishes one; a Linux lease leaves no signed record (2.5); `DataRetentionService` is scheduled by no host |

**Gate verdict.** The Windows control plane and the licensee surface (`splat-mcp`, `doctor`,
`provision`, one self-contained executable, the run record) are **alpha-grade today**: installable
and provable by a stranger, which P1 recorded on a second machine on 2026-09-18. The moat — the
Linux lease — is **built ahead of its proof**. Nothing here is beta until 2.3 has been run and
2.5–2.7 have landed, and the README's own withdrawn claims are the correct statement of that.

### Layer 1 — kernel / host sandbox, in detail

| Component | State | Read from |
| --- | --- | --- |
| Win32 job object: `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, 32 active processes, job and process memory caps, CPU hard cap; limits **read back** from the kernel object; no breakaway flags | Done | [`Win32JobSandbox.cs`](../../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs); `HardeningSubsystemTests`; the run record cites the read-back |
| Restricted token (privileges stripped, Administrators deny-only, Medium integrity), per-mission ACL jail, suspended spawn then assign then resume | Done | [`ARCHITECTURE-windows-substrate.md`](../ARCHITECTURE-windows-substrate.md); asserted against `whoami` inside the sandbox |
| Network denial (AppContainer, zero capabilities) | Done, **partial by measurement**: applied to the templates where it changes nothing in their output — the 2026-09-21 re-tiering, pinned by `NetworkToolsUnderDenialTests` | [`THREAT-MODEL.md`](../THREAT-MODEL.md) |
| What the Windows tier does not cap | Open: no UI restrictions on the job (clipboard, window messages), no disk or IOPS quota, the token keeps the operator's SID, `ToolProcess` destinations are a declaration | Threat model, measured 2026-09-22 |
| Launch overhead of the governed path | Measured: 4.12 ms p50 / 9.88 ms p95 over bare, of which the locks are about 2.4 ms | [`bench-windows-10.0.26200.0.json`](../../src/splat-bench/evidence/bench-windows-10.0.26200.0.json) |
| Linux cgroup v2 clamps: `memory.max`, `cpu.max`, `pids.max` written then read back; a clamp that did not take refuses the lease; controllers delegated to children | Done in userspace; proven under root on the 2026-09-15 program | [`cgroup.rs`](../../native/splat-agent/src/cgroup.rs); `daemon-probe.json` |
| Lease lifetime: 5–300 s, clamped by the ceiling; reaper every 1 s kills inside the still-installed policy, then withdraws it; a tree that will not drain is held and retried | Done; expiry measured at 5.5 s into a 60 s sleep on 2026-09-15 | [`lease.rs`](../../native/splat-agent/src/lease.rs), [`main.rs`](../../native/splat-agent/src/main.rs) |
| BPF-LSM hooks: `bprm_check_security`, `file_open`, `socket_connect`, `socket_sendmsg`; every map key carries the cgroup id; an earlier LSM's deny is never overridden | Built. Three hooks proven on the previous program; the datagram hook and the short-address refusal are unproven | [`lease_lsm.bpf.c`](../../native/splat-agent/src/bpf/lease_lsm.bpf.c); [`SUPPORTED_POLICY.md`](../../native/splat-agent/SUPPORTED_POLICY.md) |
| Mount-namespace jail: `unshare(CLONE_NEWNS)`, read-only system binds, fresh `/tmp`, `/proc`, six device nodes, `pivot_root`, all in `pre_exec` between the cgroup join and the privilege drop | Built 2026-09-20; six userspace tests; unproven under root. The probe carries five checks for it, none recorded | [`jail.rs`](../../native/splat-agent/src/jail.rs) |
| Guest-side ceiling: root-owned `/etc/splat/policy.json`, intersected with every request | Built 2026-09-21; ten userspace tests; needs no root to prove the intersection | [`ceiling.rs`](../../native/splat-agent/src/ceiling.rs) |
| Hooks and maps outliving the daemon (bpffs pinning) | Not started. A daemon that dies unpolices every live lease for the restart-and-drain window; orphans are reaped on the next start | Roadmap 2.7 |
| Caller identity on the bridge | Half: the token never crosses the wire and both ends prove it; a same-user Windows process can still read it | [`auth.rs`](../../native/splat-agent/src/auth.rs); roadmap 2.4 |
| Userspace tests of the daemon | 61 passed, 0 failed, in this container on 2026-09-23, after the BPF program compiled under `-mcpu=v3` | `cargo test --release` |

### Layer 2 — telemetry pipeline, in detail

| Component | State | Read from |
| --- | --- | --- |
| Kernel record: `struct violation_event`, 56 bytes, 8-byte aligned, carrying `ktime_ns`, a sequence number taken before the reservation, hook, detail, `comm` | Built 2026-09-20; layout asserted at compile time on the Rust side; unproven under root | [`SCHEMA.md`](../SCHEMA.md) §A |
| Ring buffer: `BPF_MAP_TYPE_RINGBUF`, 1 MiB; a full buffer drops the record, keeps the `-EPERM`, skips the number and increments `counters[1]` | Built | `report()` in the BPF source |
| Drain: one thread polls every 100 ms, tolerates `EINTR`, casts each record to `RawViolationEvent` without copying, fans out through a 128-slot broadcast channel; each lease subscribes before it spawns and forwards only its own cgroup's events; a lagging subscriber is told how many it missed | Done | `main.rs` |
| Daemon → bridge: JSON lines, `VIOLATION` frames carrying `seq`, `ktimeNs`, `timestampMs`; `EXIT` carries `violationsDropped`; 64 KiB output frames; 1 MiB frame cap both ways | Done (decoupled by design) | `SCHEMA.md` §B; `WslLeasedExecutorWireTests` |
| Bridge → control plane: `LeaseViolationEvent` records; output captured into a 4 MiB capped transcript; drops surfaced as `[KERNEL_EVENTS_DROPPED]` | Done | [`WslLeasedExecutor.cs`](../../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs) |
| Zero-copy `Span<T>` reads on the host | **Stub.** `Span<`/`ReadOnlySpan` appear in two files (`WorkspaceGuard`'s path buffer, a shader helper); no `Channel<T>`, no `MemoryMarshal`, no host-side ring buffer. The continuum map calls this the right answer: "zero-copy would buy nothing at the rate a tool prints" | `git grep` over `src/`; [`ARCHITECTURE.md`](../ARCHITECTURE.md) |
| Windows-side denial telemetry | **Absent by construction.** A job object and an AppContainer produce no events; a Windows record carries limits read back and controls applied, never a refusal. The textbook's Volume 04 describes shared-memory ring buffers that do not exist in `src/`; the claims audit left it on the not-yet-audited list | [`2026-09-19-claims-audit.md`](2026-09-19-claims-audit.md) |
| Proof of the daemon's own frames | Open. `VIOLATION`, `STDOUT` and `EXIT` reach the ledger unproven | Roadmap 2.6 |

### Layer 3 — state machine engine, in detail

| Component | State | Read from |
| --- | --- | --- |
| `StateGraph<TState>` | Does not exist | `git grep StateGraph -- src`: no match |
| `WorkflowGraph` | A DAG: duplicate ids refused, edges checked, **cycles refused** by Kahn's algorithm, topological execution, conditional-branch skipping that propagates, single-pass `{node.field}` substitution | [`WorkflowModels.cs`](../../src/MissionController.Core/Workflow/WorkflowModels.cs), [`WorkflowExecutionEngine.cs`](../../src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs) |
| Channel dispatch | None. `Channel<` appears nowhere in `src/`. The mission stream is `IAsyncEnumerable<MissionChunk>` (21 sites) | `git grep` |
| Bounded loops | In the engines, enforced in code: investigation loop (hard step ceiling, no repeats), brain (re-plan on grounded telemetry), crews (delegation cycles halted), projects (at most six stages) | [`ARCHITECTURE-control-plane.md`](../ARCHITECTURE-control-plane.md) |
| Cyclic agent graphs | Outside the process: `splat-langgraph` wraps eight MCP tools for LangGraph, which owns the cycle; SPLAT is the substrate under each tool call | [`ARCHITECTURE-agent-surface.md`](../ARCHITECTURE-agent-surface.md) |
| Wiring | Registered in the console's container, resolved by no view model; not constructed by `splat-mcp`; `InMemoryWorkflowRegistry` only; triggers constructed by no host; `SandboxedScript` refused; `GovernedHttp` answers `NOT_IMPLEMENTED` | `git grep -lw WorkflowExecutionEngine -- src`; roadmap "Deferred by decision" |

### Layer 4 — security & auth broker, in detail

| Component | State | Read from |
| --- | --- | --- |
| `DpapiCredentialVault`: DPAPI `CurrentUser`, fixed entropy, one file per secret, plaintext zeroed after use, ciphertext overwritten before unlink | Done, both hosts. Bound: any process running as the operator decrypts | [`DpapiCredentialVault.cs`](../../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs) |
| Model keys: vault or environment, routed by which key exists; each client pins its own egress host | Done | `ModelClientRouter` |
| `TokenLifecycleManager`: refresh handlers, expiry tracking, JWT `exp` parsing, per-key refresh lock, purge of expired secrets | Built and tested; registered in the console container; **no caller** of `GetValidAccessTokenAsync`, `RegisterRefreshHandler` or `PurgeExpiredTokensAsync` in `src/` | `git grep` |
| `PkceLoopbackAuthService`: S256 verifier and challenge, ephemeral loopback `HttpListener`, refresh timer, firewall scope on the token host | Built, Google-only, constructed by no host, quarantined by [`scope.md`](../../scope.md) until an enterprise tenant phase. Visible on read and not fixed here because the code is dormant: no OAuth `state` parameter, so the loopback redirect has no request binding; the renewal timer swallows every exception; a `client_secret` in a native-app flow; the listener accepts the first local request on the port | [`PkceLoopbackAuthService.cs`](../../src/MissionController.Infrastructure.Network/PkceLoopbackAuthService.cs) |
| Daemon peer auth, protocol 3: root-owned 0600 token, nonce handshake, HMAC-SHA256 proofs over both nonces + sequence + exact bytes, fixed-time verification, test vectors asserted on both sides | Done; proven 2026-09-15 (`daemon_proved_it_holds_the_token`, `protocol_2_token_in_the_clear_refused`) | [`auth.rs`](../../native/splat-agent/src/auth.rs); `WslAgentSessionTests` |
| Principal before effects: Windows logon session, or a validated JWT / API key in `splat-mcp`; a failed credential refuses with `-32001` | Done | `McpOperatorIdentityProvider`, `JwtTokenValidator`, `ApiKeyValidator` |
| Revocation that survives a restart and is checked before any effect, in both hosts | Done 2026-09-19 (F19). `Program.cs` passes the same `IncidentRevocationManager` the tool-call gate uses into the MCP host's mission engine; four sentences across three architecture pages still said "console only" and are corrected in this commit | `Program.cs`; `McpServerHandler.cs`; `MissionExecutionEngine.cs` |
| The lease ceiling as a bound on what a stolen token buys | Built 2026-09-21 | [`ceiling.rs`](../../native/splat-agent/src/ceiling.rs) |
| Caller identity on the bridge | Open: no transport carries a Windows peer identity; the note in `auth.rs` argues this is where the boundary *is* | Roadmap 2.4 |

### Layer 5 — audit & forensic trail, in detail

| Component | State | Read from |
| --- | --- | --- |
| Chain: each append in one transaction reads the newest row by primary key, draws a 256-bit salt, commits to `SHA-256(salt‖details)`, chains `SHA-256` or `HMAC-SHA256` over previous hash, timestamp, mission, template, action, commitment and operator; hash version per row (1 plaintext, 2 unkeyed, 3 keyed) | Done | [`SqliteChainedAuditLedger.cs`](../../src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs) |
| Keying: the first keyed append writes `LEDGER_KEYED` committing to the unkeyed history; a keyed ledger refuses extension without its key or with another; a keyed verifier refuses an unkeyed chain and a downgrade | Done 2026-09-18 | `LedgerKeyingTests` |
| Verification checks the commitment against the displayed `Details`, refuses a redacted row that kept its salt, and never retries a keyed row unkeyed | Done | same file |
| Retention: cryptographic erasure keeps the commitment and destroys payload and salt; `secure_delete`, WAL truncate verified, vacuum | Built and tested; **no host constructs `DataRetentionService`** | roadmap F23 |
| Merkle proofs: tree over `(Id, EntryHash, timestamp, action, operator)` leaves, odd leaf duplicated, inclusion proofs verified by two scripts | Done; verified on a live mission's bundle 2026-09-20 | [`MerkleTreeEngine.cs`](../../src/MissionController.Infrastructure.Data/Compliance/MerkleTreeEngine.cs); `LiveMissionTests` |
| Run record: `MISSION_RUN_FACTS` sealed on every exit path; six-group record assembled from the ledger alone; RSA-signed bundle when a key exists, and the scripts exit 2 when it does not | Done for a Windows mission | [`ARCHITECTURE-windows-substrate.md`](../ARCHITECTURE-windows-substrate.md) |
| Audit anchor on every MCP result; external trace correlation row | Done | `McpTraceAnchorTests` |
| What the chain cannot see | Unkeyed: a rewrite from genesis. Keyed: a rewrite by whoever reads the key file. Either: deletion of the newest rows, caught only by a saved anchor — and nothing yet publishes one off-host | README compliance note |
| Two chains per machine | Open by default. `SPLAT_DB_PATH` unifies both hosts only when set | roadmap "Two ledgers" |
| A Linux lease's evidence | Open: `run_command` writes one plain row; no `LEASE_RUN_FACTS`, no daemon signature | roadmap 2.5 |
| Proof cost | `GenerateProof` walks `ContainsEntry` once per level: O(n) per level, O(n log n) per proof, O(n² log n) for a bundle of n entries. Invisible at mission scale (tens of rows); a wall at fleet scale. An index from entry id to leaf position makes it O(log n) | `MerkleTreeEngine.cs` |
| Compliance package prose | Not yet audited: the summary still claims non-repudiation and "zero ePHI leakage" | claims audit, "Not yet audited" |

---

## Part 3 — gap analysis and recommendations

### 1. Critical-path remediation — the three highest-yield fixes

| # | Fix | Why it is highest-yield | Effort · owner | Done when |
| --- | --- | --- | --- | --- |
| 1 | **Re-prove the substrate, then make re-proof one unattended command.** `packaging/reprove-substrate.ps1`: stop the unit, build, start a fresh daemon as root through `wsl -u root`, run `probe-daemon.sh` and `probe-last-hop.ps1` with the evidence directory pointed at the tree, restart the unit, print both verdicts | Four landed changes (jail, ceiling, datagram hook, record clock and counters) are unproven, and the README's two headline claims are withdrawn until the hashes match again. Every later kernel-side change withdraws them again, so the cost of proof decides the pace of the whole P2 phase. 2.5, 2.6 and 2.7 are all sequenced "after 2.3" | S for the script, agent; one afternoon, operator — the permission classifier refuses an agent every route to a root daemon | `daemon-probe.json` and `last-hop-probe.json` name `e7822f35…` with PASS; `DocumentationDriftTests` turns the suite red until the README's claims are restored, which is the test doing its job |
| 2 | **Give the kernel-enforced path the evidence the Windows path already has.** (a) 2.5: the daemon signs each lease's outcome with an Ed25519 key generated in the guest, its public half reported by `HEALTH_RESPONSE` and `doctor`; `run_command` seals a `LEASE_RUN_FACTS` row; the assembler builds a bundle for a lease id. (b) 2.6: a MAC on the daemon's `VIOLATION`, `STDOUT` and `EXIT` frames under the session, with its own label and sequence | The moat produces the weakest evidence: a Windows sensor mission leaves a signed six-group record, a kernel-refused `run_command` leaves one plain ledger row. The first paid deliverable in [the plan](2026-09-09-oem-subtraction-plan.md) §6 is a reachability report built from exactly this evidence | M, agent, after 2.3 | A lease's bundle verifies with the same two scripts a mission's does, a hand-edited violation fails them, and `WslAgentSessionTests` refuse a daemon frame whose proof does not verify |
| 3 | **Close the two windows an evaluator hits first: pin the hooks under bpffs (2.7), and make the ledger one chain per host, keyed, by default.** Pin the four program links and five maps under `/sys/fs/bpf/splat/<sha256 prefix>/`, reuse on a hash match, remove on a mismatch, and kill an inherited lease *while it is still policed*. Have `provision --apply` generate the ledger key file into the operator's keys folder, and default both hosts to one `SPLAT_DB_PATH` | Today a daemon that dies unpolices every live lease for the restart-and-drain window, and a fresh install's `doctor` says a ledger rewrite is undetectable, twice. Both are the first things a careful evaluator reads back to you | M + S, agent, after 2.3; the key-file default is a decision | `kill -9` the daemon mid-lease and an exec outside the lease is still refused before the unit restarts; `doctor` on a fresh provision reports keyed, one chain |

Not in the three, and why: the WFP filter for Windows destination pinning is a decision with a DNS
condition attached; the five templates that need rights the token removes are a tiering decision;
job-object UI limits ship after all 49 templates report the same with them on; scheduling
`DataRetentionService` is an afternoon once someone names the host that runs it.

### 2. Pragmatism vs decoupling — the verdict

The continuum map in [`ARCHITECTURE.md`](../ARCHITECTURE.md) was re-read row by row against the
code and holds for every **live** layer: the BPF hooks read kernel structs through CO-RE with no
serializer; the ring-buffer record is a checked cast; the mission engine is one sequence with one
`finally`; the ledger is a local chain; the daemon and the bridge meet at a versioned line protocol
with proofs over exact bytes. None of those should move, and each would be *weakened* by the
abstraction that would make it look more configurable.

The problem is not placement. It is **mass**: the tree carries a large body of decoupled code that
no composition root reaches, and every audit since 2026-09-04 has spent effort re-establishing that
it is dormant — the claims audit found the console advertising two of these as live.

**Premature abstraction — complexity and audit cost without value today.** Line counts from the
tree on 2026-09-23.

| Code | Lines | State | What it costs |
| --- | --- | --- | --- |
| Workflow layer: engine, synthesizer, models, `InMemoryWorkflowRegistry`; `Triggers/` (webhook listener, OAuth coordinator, scheduler) | 1,593 + 824 | Engine registered in the console and resolved by no screen; absent from `splat-mcp`; thirteen node types of which one is refused and one answers `NOT_IMPLEMENTED`; triggers constructed by no host. Deferred by decision 2026-09-09 | Two claims-audit findings, a `TransactionalScope` that is compensation rather than rollback (AG-F08), and a second launcher path outside the mission sequence |
| Copilot / Semantic Kernel adapter | 944 | No Semantic Kernel package is referenced; the Linux path builds an empty exec list and is refused; no shipped composition supplies its executor; the console registers it and no screen uses it | An integration surface written before a licensee asked for it, carrying its own policy engine and Sentinel bridge |
| `PkceLoopbackAuthService`, `ServiceAccountAuthService`, `VertexAiStreamClient` | 403 | Google-specific, constructed by no host | Dormant credential code with its own defects (Layer 4 above) that a reader has to re-discover |
| `TemplatePolicyCompiler` | 221 | Constructed by `splat-mcp` and handed to a handler that never calls it; `run_command` authors its lease inline | The most dangerous kind of dormant code: a policy compiler that never compiles policy reads as the authorization source. Two lease authors, one dead |
| `TokenLifecycleManager` | 213 | Registered, never called | Same |
| Console `Effects/` and `Graphics/`: HLSL, Win2D, a Direct3D swap-chain loop | 4,115 | On a console the plan says "ships nothing and gates nothing" | Build surface (`fxc` detection, shader asset tests) for a screen no licensee runs |
| Quality island: `SpeculativeBestOfN` mode and the Bradley–Terry arbiter | part of 1,986 | The default `LeanFailSafe` mode never ranks a cohort | A mode nobody runs, with tests that keep it honest at a cost |

Two smaller smells of the same kind: `IProcessLauncher.LaunchSuspendedInJobAsync` takes ten
parameters including two booleans that decide containment (`dropAdminPrivileges`,
`denyNetworkAccess`), so the containment decision is spread across call sites instead of one
options record; and the lease clamps (256 MiB, 50 %, 100 pids) are stated in `McpServerHandler`,
in `LeaseResourceLimits`' defaults, in `main.rs`' ceilings and in the `policy.json` example — four
copies, one kernel read-back.

**Recommendation.** Keep the rule "built is not wired" and give it a budget. Either a subsystem is
named by a roadmap phase and gets wired in that phase, or it leaves the solution — an `attic/`
directory outside the `.sln`, or deletion with git as the record. Concretely: make
`TemplatePolicyCompiler` the single lease author or delete it (make it the author: it has tests,
and `ExecuteRunCommandAsync` becomes a caller); park the Copilot adapter and `Triggers/`; keep the
workflow layer only if the Layer 3 decision goes in-process; leave the quality island as is.

**Under-decoupled — dangerously so.**

| Code | Lines | The coupling | The seam to cut |
| --- | --- | --- | --- |
| [`McpServerHandler.cs`](../../src/splat-mcp/McpServerHandler.cs) | 1,655 | JSON-RPC dispatch, twelve tool bodies, actor resolution, the egress policy call, audit anchoring, and the assembly of the `LeaseSpec` the kernel enforces — in one request handler, beside string parsing | A pure `LeaseAuthor`: request + operator policy → `LeaseSpec` or a named refusal, with its own tests; the handler becomes transport |
| [`main.rs`](../../native/splat-agent/src/main.rs) | 1,721 | BPF loading, the drain, protocol parsing, session auth, provisioning, `pre_exec`, streaming, reaping. The one closure in the repository that must be async-signal-safe lives in its largest file | `protocol.rs` (frames, `HELLO`, `AUTHENTICATED`), `session.rs`, `provision.rs` (cgroup, lease, jail, ceiling), `spawn.rs` holding only `pre_exec` under a header that states its contract, `stream.rs`. The RFC template's memory and concurrency section exists for this file |
| Two composition roots | `App.xaml.cs` and `Program.cs` | The console uses a DI container, `splat-mcp` hand-wires, and they drift: this record found four sentences on three architecture pages still saying revocation was console-only; the roadmap records two ledgers and a Linux path only one host has | One `SplatComposition` that builds the engine graph from a `HostOptions`, with both hosts as thin shells, so `CompositionRootTests` pins one graph |
| Model ids | six or more string literals | Documented in the control-plane page: a retired id fails wherever it was still named | One `ModelCatalog` |

**Keep coupled, and say so when asked:** BPF hooks to kernel structs, the ring-buffer cast, the
mission sequence, the local ledger, the Win32 objects behind one interface each. The map's reasons
are the right ones.

### 3. Enterprise rollout — the minimal viable demonstration

The demonstration is [the plan's](2026-09-09-oem-subtraction-plan.md) §6 engagement made
visible: *what can your coding agent actually reach?* Fifteen minutes, on the evaluator's own
Windows 11 machine with WSL2, in this order.

1. **`splat-mcp doctor`** — kernel, `bpf` on the boot line, daemon reachable *and* enforcing,
   ceiling present, ledger keyed, run records signed; exit 0. The manifest it prints is bound to
   `SUPPORTED_POLICY.md` by a test, so the evaluator reads what will and will not be enforced before
   anything runs.
2. **The refusals, from their MCP client, with controls.** `run_command cat /etc/hostname` refused
   with a `VIOLATION` frame carrying hook 2, a sequence number and the kernel's clock, while a
   control run outside the lease reads the same 644 file; `sh -c dpkg` refused at exec; `curl` to an
   address outside the lease refused while the operator's `--egress` endpoint is reached; a name
   lookup with no resolver in the lease refused as a datagram. The last two need 2.3 first.
3. **A signed run record.** `export_run_record` for a Windows `diagnose_system` mission, then
   `verify_proofs.py` on a *second* machine: proofs, file hashes and signature.
4. **Tamper evidence.** Edit one ledger row with `sqlite3`; `doctor` and the Security Audit screen
   report FAILED, because the ledger was keyed at provision.
5. **Optional, after 2.7:** `kill -9` the daemon mid-lease; the exec is still refused.

| Needed before an external evaluator sees it | State on 2026-09-23 | Roadmap |
| --- | --- | --- |
| One self-contained executable | Exists, 77 MB, unsigned; SmartScreen will interrupt an unsigned download | 4.7 — the certificate is the operator's |
| `doctor` and `provision --apply` | Done, met on a second machine 2026-09-18 | — |
| Kernel claims that match the program that ships | Pending | 2.3 |
| Keyed ledger, one chain, by default | Mechanism exists; the default is unkeyed and two | 3.2 done; the default is a decision |
| A signed record for a Linux lease | Open | 2.5 |
| SPLAT's own WSL distro, imported at mount | Not started; without it the buyer runs `wsl --shutdown` mid-demo and glibc is whatever their distro has | 4.6 — a decision first |
| Unmount, from a manifest, so the machine goes back | Not started | 4.2 |
| Evaluator-facing paper: `SUPPORTED_POLICY.md` as Exhibit A, the one-pager, `SCHEMA.md` | Done | — |

**Leave out of the demonstration:** the console, workflows, crews, the brain, the Copilot adapter,
remediation (the catalog ships no fixes), the five templates that need rights the token removes,
and any Windows `ToolProcess` destination claim.

**Sequence:** 2.3 → 2.5 and 2.6 → the keyed, single-ledger default → 2.7 → 4.2, 4.6, 4.7 → the
demonstration. One operator afternoon for the proof, then three to four weeks of agent work behind
two decisions (the distro, the certificate).

---

## What this record changed in the tree

- Added [`RFC_TEMPLATE.md`](../RFC_TEMPLATE.md) and
  [`EXECUTIVE_STATUS_TEMPLATE.md`](../EXECUTIVE_STATUS_TEMPLATE.md), indexed in
  [`docs/README.md`](../README.md).
- Corrected four sentences that said the revocation check was console-only, in
  [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`ARCHITECTURE-control-plane.md`](../ARCHITECTURE-control-plane.md)
  and [`ARCHITECTURE-agent-surface.md`](../ARCHITECTURE-agent-surface.md): F19 wired it into the
  MCP host's mission engine on 2026-09-19, and `Program.cs` shows it.
- The script half of fix 1 landed the same day: [`packaging/reprove-substrate.ps1`](../../packaging/reprove-substrate.ps1).
  The run is the operator's.
- Two of the smaller findings above were closed the same day, because each was an afternoon:
  `MerkleTreeEngine` proves by leaf position, one sibling lookup per level, and `run_command`
  takes its clamps from `LeaseResourceLimits`' defaults rather than restating them.
- Nothing else. Every other gap above is a roadmap row or a decision, and is left there.
