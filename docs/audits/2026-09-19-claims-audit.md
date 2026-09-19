# Claims audit, first pass — 2026-09-19

The operator's note that started this: "we are SERIOUSLY far away from being finished with the claims
laid out all over the docs." This pass checked the claims a buyer, a partner or the operator reads
first against the code, the tests and the committed evidence on `main` at `4a288ef`.

**Verdicts:**
- **True:** holds as written.
- **Partly:** true for some of what it covers, or with a qualification it leaves out.
- **False:** does not hold, or describes something that does not exist.

The **Action** column says what was changed in the same commit as this record, or where the gap now lives.

## The app's own screen

| Claim | Verdict | Evidence | Action |
| --- | --- | --- | --- |
| Status bar: JOB SANDBOX ENFORCED · ACL JAILS ISOLATED · SHA-256 LEDGER VERIFIED, green | **False** as status | Typed into `MainWindow.xaml`; no code checked them. The ledger light stayed green whatever `VerifyLedgerIntegrityAsync` said | Each light is now a check run at start on the same types a mission uses: a job object created and closed, a jail provisioned and drained, the chain verified. Each says READY or VERIFIED, or FAILED |
| Header: CONTROL PLANE ONLINE, green | **False** as status | Typed into the XAML | Now SELF-CHECK PASSED, or SELF-CHECK: n FAILED, from the checks above |
| Status bar: 8-LAYER GOVERNED APPLIANCE | **Unsupported** | Nothing in the code or docs counts eight layers; the Field Guide draws five rings | "8-LAYER" removed |
| Project Studio: Webhook Trigger and OAuth Receiver at `127.0.0.1:5678`, shown as live | **False** | No host constructs `EmbeddedWebhookListener` or `OAuthCallbackCoordinator`; the roadmap defers trigger hosting | Replaced with a line saying both are designed and not started |
| Project Studio's example prompt: a TikTok OAuth receiver capturing a token | **Contradicts the Field Guide**, which says SPLAT does not do that | Part 3 of the guide | Example is now a diagnostic chain the templates do |
| Jail Inspector: "Hardware & filesystem isolation… zero-zombie process termination" | **Partly** | Job objects and ACLs are kernel objects, not hardware; `KILL_ON_JOB_CLOSE` is set (`Win32JobSandbox.cs:24`) | Reworded to kernel job objects and NTFS ACL jails |
| "HARDENED ENTERPRISE" badge; "Autonomous Agent" labels | Branding, not a checkable claim | — | Left for the operator to decide |
| Rollback shows "Rollback Verified: Restored previous state" | **False**; it verifies only that the undo command exited 0 | Committed `QuickDiagnosticianViewModel.cs:256` | Not changed here, because another session has that file open with a fix (roadmap 3.6) |

## The Field Guide and the tutorial

| Claim | Verdict | Evidence | Action |
| --- | --- | --- | --- |
| Part 6: "a logbook nobody can quietly edit", "the ledger can't lie to you" | **False** while unkeyed | Nothing supplied a key; `doctor` says a rewrite is undetectable | Fixed on 2026-09-18 with the keyed ledger (3.2) |
| 1:1:1 — one internet address per template, "anything else is refused… by plumbing" | **Partly** | 33 of 49 tools get no network; 16 keep one with no enforced destination on Windows (the guide's own Part 7) | Now "at most one address", with a pointer to Part 7 |
| Ring 4: outbound traffic to exactly one approved address | **Partly** | As above | Relabelled |
| "Rings 1, 2 and 5 are enforced by the Windows kernel's own object system" | **False** for ring 5 | Ring 5 is the ledger, a SQLite file the app writes | Caption now says rings 1 and 2, and ring 4 where a tool has no network; the censor and the logbook are SPLAT's code |
| Step 5: the tool "can't wander the filesystem… can't call anywhere except its one approved address" | **False** for 16 tools | Restricted-token tools keep the user's SID and can read what the user reads; only the 33 in the AppContainer are kept from the network and the profile | Rewritten |
| Step 8, Part 8: "Risky fixes come with a rollback", "anything risky ships with an undo" | **False** as a guarantee | `CanRollback` and the rollback command are optional on `RemediationAction`; nothing requires one for a risky fix | Rewritten: every fix is labelled with its risk and runs only on a click; an undo is optional |
| Part 3: "filesystem access is jailed"; glossary: a fix comes "with a rollback (undo) for anything that changes state" | **False**, for the reasons in the two rows above | The jail is the tool's working folder; the undo is optional | Rewritten |
| Memory: "search by meaning, not keywords" | **False** | `SqliteSemanticMemoryIndex` hashes words and three-letter fragments into 128 slots and ranks by cosine: word similarity, not meaning | Rewritten |
| API key "never sits on disk in readable form" | True | DPAPI, CurrentUser scope, zeroed after use (`DpapiCredentialVault.cs`) | — |
| Every fix "has a clearly labeled risk level" | True | `RemediationRiskLevel` on every `RemediationAction` | — |

## The technical one-pager

| Claim | Verdict | Action |
| --- | --- | --- |
| "one allowed destination… enforced by the operating system" | **Partly**: on the Linux lease, yes; on Windows the OS enforces only whether a tool has a network | Qualified |
| "455 automated tests currently pass" | Stale; nothing held this document to the count | Now 578, dated |
| "The audit ledger is unkeyed" | Stale since 3.2 | Now describes default and keyed |
| Everything under "What is proven" and "What is NOT proven" | True against the committed evidence | — |

## The executive brief

| Claim | Verdict | Action |
| --- | --- | --- |
| Transport is "Hyper-V VSOCK" | **False**: loopback TCP to 127.0.0.1:50051; the bridge says AF_VSOCK is not implemented | Corrected |
| "Every mission operates inside an ephemeral OverlayFS CoW workspace… discarded instantly" | **False**: not built; the daemon refuses `overlayFs.enableCow`; roadmap P2 | Section retitled "Not Built Yet" and rewritten |
| Ledger "cryptographically signed", a "SOC2/HIPAA record", "mathematical proof" | **False**: hash-chained, not signed; unassessed | Rewritten |
| Violations "streamed to HUD" | **False**: the console never routes a mission through the daemon | Now says they reach the MCP client |
| `file_open` "blocks … `.ssh`" | **False**: `run_command` leases protect `/etc/shadow` and `/etc/sudoers` | Corrected |
| "Hardware-level" egress and "hardware clamps" | **False** wording: kernel-level and cgroups | Corrected, and IPv6 added |
| "100% local" | **Partly**: execution is local; the app's own reasoning calls a cloud model | Qualified |
| Kernels "6.6+ / 6.18+" | **Partly**: proven on 6.18 only | Narrowed |
| "Deploy truly autonomous agents with total confidence" | Unsupported | Rewritten |

## The Microsoft pitch

| Claim | Verdict | Action |
| --- | --- | --- |
| Competitors cost "200–800ms" and "$0.05–$0.20 per hour", "$50–$200 per user per month" | **Unmeasured**; the one-pager's own rule keeps such numbers out | Removed |
| Actions "cryptographically signed into a SHA-256 Merkle tree and streamed… to Sentinel", "zero configuration" | **False** as written: chained, not signed; forwarded when a workspace is configured, from the configuration the pitch itself shows | Rewritten |
| "Forensic guarantee" including kernel resource metrics | **False**: the Linux path reports metrics as unavailable | Rewritten |
| "100% Air-Gapped", "Instant Approval (Mathematical Containment)", "the only enterprise OS" | Unsupported | Replaced with what a reviewer can actually check |
| "185 passing tests" | Stale | 578, dated |
| The Semantic Kernel integration code | True: `AddSplatCopilotSafety`, `CreateEnterpriseDefault` and `SplatCopilotInvocationFilter` exist | — |

## The master proposal

| Claim | Verdict | Action |
| --- | --- | --- |
| "Authenticated REST (:5678)" into the control plane | **False**: nothing starts it | Corrected |
| "TransactionalScope Scratch Overlays", "Discard-on-failure OverlayFS CoW", "Filesystem Atomicity… guaranteeing the host filesystem remains untouched" | **False**: not built (P2; AG-F08 calls TransactionalScope compensation, not rollback) | Marked planned |
| "Cryptographic Non-Repudiation" with an out-of-date hash formula | **Partly**: the README calls non-repudiation half complete | Formula corrected; keyed option described |
| "rollback guarantees" | **False** | Rewritten |
| "Zero liability: guarantees client endpoints cannot be compromised" | **False, and a liability in itself** | Removed |
| Track D: offline local models, YubiKey/SmartCard enforcement | **False**: no local-model client and no hardware-token code exist | Marked planned |
| Track B fleet distribution and policy | **False**: not built | Marked planned |
| Windows "10/11" and kernels "6.6+" | **Partly**: proven on Windows 11 and 6.18 | Narrowed |

## Not yet audited

- **`docs/textbook/`** — ten volumes, a compiled PDF and three HTML pages, 3.7 MB. The volume titles alone name things this pass could not find in the code: zero-copy streaming, shared-memory ring buffers beyond the daemon's BPF ring buffer, and microarchitectural optimisation. This is the operator's learning material, so a claim that does not exist costs more there than anywhere. It gets its own pass.
- **`docs/course/`** — ten weeks and five companion pages.
- **The architecture pages, CONTEXT, MODULE_INFO and the README.** They were edited carefully all week, and `DocumentationDriftTests` binds much of the README, but none of them was re-read line by line here.
- **`scope.md` and `build.memory`** at the root. `build.memory` still describes a 161-test net9 tree.
- **`docs/ARCHITECTURAL-BREAKTHROUGHS.md`**, uncommitted work from another session. Its header says `DocumentationDriftTests` verifies its links; no test reads it.

## Product gaps these claims pointed at

Each of these would make an honest version of a claim above true, rather than just less wrong:
- An undo required for any fix labelled risky.
- A lease that keeps SSH keys out of reach. The `/mnt` stopgap covers the Windows profile until P2, but `run_command` still protects only two files.
- Memory search that works on meaning, if "by meaning" is wanted.
- The webhook and OAuth listeners, if Project Studio is to offer them.
- A local model client, for any offline claim.
