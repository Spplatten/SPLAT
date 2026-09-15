<!-- The one status record. When an item's state changes, change its row here in the same commit
     that changes it. When the ORDER changes, the argument goes in the plan and the rows move here.
     Every "State" below was checked against the tree when it was written, and each carries the date
     it changed: a row that says "open" was
     looked for in the code, not carried over from an older document. -->

# Roadmap

Everything still to do, in the order it pays to do it, with who can do it and what "done" means.
The argument for this order is [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md);
this file is only the state. The
[competition audit](audits/2026-09-04-competition-and-scope.md) asked for exactly this — "one
authoritative status record" — and until 2026-09-10 the state was spread across the plan, the wave
plan, three audits and the runbook, where it drifted in all of them.

**Owner:** *agent* — can be done without you. *you* — needs `sudo`, an install, money, a signature or
a decision. Where both appear, the agent does the work and you do the one step it cannot.

---

## Done recently

| Item | Evidence |
| --- | --- |
| The server's first byte is the JSON | Every MCP client's first response began with a UTF-8 byte order mark — `ef bb bf` before `{` — which strict JSON parsers reject. Found by reading the bytes, fixed with 1.1, and pinned by a test on the stream itself |
| P0 — the shipping tree on .NET 10 | `0027e57`: 459/459 on `.NETCoreApp,Version=v10.0`, and the frozen console still builds on the net9 leg |
| F21, SQLite half — a high-severity advisory was shipping | `0027e57`: `SQLitePCLRaw` 2.1.10 → 2.1.12, clearing `GHSA-2m69-gcr7-jv3q`. `dist\App` republished, and the patched `e_sqlite3.dll` confirmed loaded in the running app |
| A cold build is warning-free, and now stays that way | 2026-09-12, a fresh worktree so nothing was warm: `dotnet build MissionController.sln` reported **0 Warning(s), 0 Error(s)**. It had been true on 2026-09-10 too, but nothing held it — 1.7 does now, which is why the claim stopped being a guarded overclaim in `DocumentationDriftTests` on the same day |
| Preflight stopped reporting an unmounted securityfs as YELLOW | `1343457` |
| The runbook's commands run in the shell you actually have | `fa48915`: 11 of 11 PowerShell blocks parse under Windows PowerShell 5.1 |
| The honesty suite stopped raising false alarms | `5822067`: seven tests stood up a loopback daemon and then raced production's two-second budget. The same exchange measured 12ms alone and 363ms under the suite's own parallel load, and the loser reported an unreachable daemon — the exact bug those tests exist to catch. The budget is now the caller's; the default is unchanged |
| The Field Guide stopped understating Windows containment | `052dcd7`: Part 7 told a non-engineer that on Windows the locks "do not filter network sockets". The census disproves that for 33 of 49 templates. Windows enforces **whether**, the Linux guard enforces **where** — and the audited-promise caveat now applies to the sixteen it actually describes. Every count in both copies is swept from `GovernedTemplateCatalog`, not typed |
| A retired claim is retired everywhere, not just in the README | `73a33b1`: `RetiredOverclaims_DoNotReappear` was written against the README, so it was watching the wrong file while the guide carried the claim above for weeks. It now reads all three documents |
| The published Field Guide can no longer rot unseen | `71e0276` + `b486724`: the page a non-engineer actually reads lives outside this repository and sat at 511 tests with that false claim live. `docs/SPLAT-Field-Guide.published` records the source's hash and the suite recomputes it, so editing the guide without republishing fails the build. `packaging/build-field-guide-artifact.ps1` makes republishing one command and keeps recording a separate switch, because the one failure the check cannot see is someone updating the hash instead of the page |
| `provision` stopped sending people to edit lines WSL ignores | `.wslconfig` was judged "already sets kernelCommandLine" by a substring test, so a commented-out `# kernelCommandLine`, or the same key under another section, told the user to add `bpf` to a line that could never take effect — and the restart they were sent to make came back with the same answer, the silent fallback 1.3's done-when rules out. It is now read the way WSL reads it: a live key under `[wsl2]`. An existing `[wsl2]` section is named, never duplicated, because whether WSL honours a key in a repeated section is unobserved. The path is injectable, so the append is tested at last — before, no test could reach it without writing to the developer's own config, and the dry-run test could not see it at all: it records guest commands, and this file is written on the Windows side |
| Two templates stopped printing their own containment evidence | `web-autonomous-site-deploy` announced a copy-on-write workspace and restricted egress that nothing measured; `marketing-social-campaign-publisher` printed "BPF-LSM Egress Lease: Locked" on Windows, which has no BPF-LSM, from a tool with no network — and a credential vault "verified" that nothing had read. Tool stdout is what findings are grounded against, so each line certified its own fabrication. Deleted, and `TemplateEvidenceHonestyTests` fails if any template's script carries that vocabulary again, or if the scripts ever stop being readable as the text PowerShell runs |
| The bridge stopped starting whatever daemon it could find | 2026-09-13. `WslLeasedExecutor` raced a loopback connect against 200 ms, and a connect that lost ran a root script that started the first `splat-agent` in `/tmp/splat_agent_target` or the repository's `target/` — in a guest where any process can write to `/tmp`. Only a refused connection starts anything now, and what it starts is the installed service, or the lease is refused naming `splat-mcp provision --apply`; setup no longer spends the lease's clock. `provision` had the same exposure: its source build ran in `/tmp` and root installed the result, with a failed build reporting success through a pipe, and its shipped install sent a check through a fixed `/tmp` file. Neither touches `/tmp` now, and the shipped daemon is hashed after it is copied, because `/mnt/c` is writable from inside the guest — `nobody` wrote to it on this machine |
| The token stopped crossing the wire | 2026-09-15, protocol 3. The bridge sent the daemon's secret in every request, so while the daemon was down anything that took `127.0.0.1:50051` could collect it — a listener run as `nobody` received what Windows sent. Now the daemon proves it holds the token over the bridge's nonce before anything else is sent, and every request proves it back over both nonces, its place on the connection and its bytes. Verified on this machine: with the daemon stopped and a `nobody` listener on its port answering with a forged challenge, `splat-mcp doctor` sent it one `HELLO`, nothing else, and reported REFUSED; both probes re-recorded PASS under protocol 3, the root probe with the token sent in the clear refused; and the Rust and C# proofs agree on one fixed vector |
| Remediation waves 1–3, and Wave 4's F10, F11 and F15/F17 | [WAVE-PLAN](audits/WAVE-PLAN.md) |

---

## Now — P1: installable and provable by a stranger

**Exit:** a stranger with WSL2 adds one stanza to their MCP config, runs a command the kernel refuses,
and can point to the line in [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) that
predicted it — **recorded on 2026-09-11** in `last-hop-probe.json` (1.8), so what remains of P1 is
getting it onto a machine that is not this one. This is also the first thing that can be invoiced: a
containment assessment needs P1
and nothing after it.

| # | Item | Owner | State | Done when |
| --- | --- | --- | --- | --- |
| 1.1 | A `splat-mcp` command line — `--workspace`, help, refusal of unknown options — validated **before** any startup effect | agent | **Done 2026-09-11.** Parsed before anything is built: a bad option or a missing workspace exits 2 with the ledger untouched, and a workspace is never created. `--workspace` is optional on purpose — without it the file tools stay in SPLAT's private folder, which fails safe, and the server names that folder on stderr | The selected root reaches `WorkspaceGuard`, and a bad option exits without creating a database — both shown on the real exe, not only in tests |
| 1.2 | `splat-mcp doctor` | agent | **Done 2026-09-12.** Probes this host — kernel, `lsm=` on the boot line, daemon reachable, its answer authenticated, and live BPF maps behind it — and prints what a lease enforces, refuses and does not police, read from the one capability manifest (1.5), which is bound to `SUPPORTED_POLICY.md` by a test. Exit 0 only when a lease reaches the kernel. On this host: enforcing, exit 0 | It reports this host's kernel, BPF-LSM state, daemon and token, then what will and will not be enforced — read from the policy tables, never hardcoded — and refuses the enforcing modes when the substrate is absent |
| 1.3 | First-run WSL provisioning | agent; `wsl --install` and `wsl --shutdown` are yours | **Done 2026-09-12.** `splat-mcp provision` checks WSL, systemd and `bpf` on the boot line, installs the daemon at `/opt/splat/splat-agent` — not `/tmp`, which is tmpfs and went with the distro twice on 2026-09-11 — writes a systemd unit, enables it, and passes only when the authenticated health check says a lease reaches the kernel. A dry run by default; `--apply` makes the changes. On this host, `--apply` built, installed and enabled it, and the verdict was enforcing, exit 0. After a `wsl --shutdown`, the unit brought the daemon back on its own (`systemctl is-active`: active). Since 1.9 the daemon it installs is the copy `splat-mcp.exe` carries; only a checkout of this repository, which carries none, builds it in the guest with cargo | A clean machine reaches a kernel-contained mission with no manual shell step, and a broken provision names the missing piece instead of falling back silently |
| 1.4 | Distribution: one downloadable `splat-mcp` | agent | **Done 2026-09-12** for the single file. `packaging/publish-splat-mcp.ps1` produces a self-contained 77.4 MB `splat-mcp.exe` with its native SQLite and, since 1.9, the Linux daemon inside, plus a SHA-256, and stops rather than reporting success on a non-zero publish, a missing output, a stray file beside the executable, an executable that cannot print its usage, a daemon linked against libelf, zlib or zstd, or an executable that does not carry the daemon it was built with. **No `dotnet tool`:** `PackAsTool` rejects a platform TFM (NETSDK1146) and this project must target `net10.0-windows` for the Win32 primitives; a tool package would need a second, platform-neutral wrapper carrying the exe as payload. **No `npx` shim:** that needs a published release binary and an npm account — yours to decide | One downloaded file plus one config stanza is the whole setup, and the artifact cannot ship unverified |
| 1.5 | F24 — one capability manifest | agent | **Done 2026-09-12.** `CapabilityManifest` in Core states what a lease enforces, refuses and does not police; what holds each MCP tool; and — counted from the shipped catalog, never authored — how many templates run outside the Windows AppContainer. `doctor` prints it, every `tools/list` description ends with the enforcement it names, and tests bind it to `SUPPORTED_POLICY.md`, to the served tool list in both directions, and to the census sentence in this file. The README tool table is still prose a reader must trust | The CLI, `tools/list`, `SUPPORTED_POLICY.md` and the tests all read one file — including which templates run outside the Windows AppContainer — and drift between them fails the build |
| 1.6 | Bound every request frame before parsing it | agent | **Done 2026-09-11.** Both ends cap a frame at 1 MiB before parsing: the daemon reads through `take`, says so and hangs up (the tail of an oversized frame must not be re-read as frames of its own); `splat-mcp` answers `-32700` and skips to the next newline, because a stdio client has no second connection | A frame exactly at the limit parses, and one byte over is refused before it can grow — asserted on both ends, the daemon's test trailing ten unread megabytes behind the refusal |
| 1.7 | Warnings fail the build on the shipping projects | agent | **Done 2026-09-12.** `src/Directory.Build.props` and `tests/Directory.Build.props` set `TreatWarningsAsErrors`, and a test asserts the frozen console is the only project allowed to opt out — so a second exemption has to appear in a diff. Kept out of the repository root deliberately: `coursework/` is another tree with its own owner. Proven by injecting an unused local into `splat-mcp` — `CS0219` came back as `error CS0219` and the build exited 1 | A new warning in Core, Data, Linux, Network, Windows, `splat-mcp` or the tests fails the build |
| 1.8 | Record the last hop | agent builds it; you start the root daemon | **Done 2026-09-11.** [`probe-last-hop.ps1`](../native/splat-agent/probe-last-hop.ps1) drives `splat-mcp.exe` over stdio as a client does; the kernel refused an undeclared exec and an out-of-lease connect while the permitted command ran as `nobody`. The run found the defect that made the hop unusable: the bridge's `wsl.exe` children inherited the server's stdin and ate the JSON-RPC stream | Evidence is committed of an MCP client's command refused by the kernel, bound to the sources that produced it, and `DocumentationDriftTests` holds the README to it in both directions |
| 1.9 | The daemon inside `splat-mcp.exe` | agent | **Done 2026-09-13.** `packaging/publish-splat-mcp.ps1` builds the daemon in WSL with the crate's `portable` feature — libelf, zlib and zstd linked in, glibc 2.39 or newer and the libgcc runtime the only things it needs from a guest — and embeds it, then checks the published executable carries it by the daemon's GNU build ID. `provision --apply` stages that binary in the guest, runs it once so a glibc or library mismatch is named by the loader rather than failing at boot, renames it into place, and replaces an installed daemon only when its hash differs — restarting the service when it does. Proven on this host with cargo hidden from root and the default user, and the daemon and its unit removed: the dry run named the embedded daemon and exited 1; `--apply` installed it with no toolchain and exited 0; the installed binary was byte-for-byte the embedded one, with no libelf, zlib or zstd linked dynamically; `doctor` exited 0; a second `--apply` recognised it and replaced nothing; and the project's kernel probe passed every check against that shipped daemon. On the way, `RunWslAsync` stopped appending wsl.exe's own stderr to successful answers: on a guest printing "Failed to start the systemd user session" on every call, as this one did, `ps -p 1` would have read as something other than `systemd` and a `wslpath` answer as a path that does not exist | `provision --apply` reaches enforcing on a guest with no Rust toolchain installed |

---

## Next — P2: the workload's own mount namespace

Three of the gaps people ask about first — read-only roots, copy-on-write scratch, running code an
agent just wrote — are one missing capability. The plan's §3 has the argument.

| # | Item | Owner | State | Done when |
| --- | --- | --- | --- | --- |
| 2.1 | `unshare(CLONE_NEWNS)` and `pivot_root` inside the spawn's `pre_exec` closure | agent | Not started; it exists as a comment in `cow.rs`. The hard one: async-signal-safe code in a forked child of a multithreaded process | `readOnlyFs` and `overlayFs.enableCow` move out of `SUPPORTED_POLICY.md`'s **Refused** table |
| 2.2 | Leased scratch execution for code an agent just wrote | agent | Blocked on 2.1 | A file created in scratch executes, the same file outside scratch does not, and the scratch layer is gone after teardown |
| 2.3 | The proof, under root | you — `sudo` for the daemon and its token | Blocked on 2.1 | `daemon-probe.json` gains those checks and is re-recorded; the runbook gets a section for it |
| 2.4 | Caller identity on the bridge | agent | Half done. Protocol 3, 2026-09-14: the shared secret no longer crosses the wire. The daemon proves it holds it over a nonce the bridge chose, before the bridge sends anything else, and every request proves it back over both nonces, its place on the connection and its bytes — so a listener that takes the port while the daemon is down, like the one run as `nobody` on 2026-09-13, is sent one nonce and cannot answer it. Still open: a shared secret identifies no caller, and another process running as the same Windows user can read it just as the bridge does. The code's own notes name AF_VSOCK, or `SO_PEERCRED` over a Unix socket | The threat model is written down first — which callers each option actually excludes; AF_VSOCK identifies a VM, not a Windows process — and the daemon enforces what it says |

---

## Then — P3: the per-mission run record

**Exit:** someone who did not run a mission can verify from the bundle alone what it was permitted to
do and what it did. The schema already exists — the six-group evidence contract in
[the 09-04 roadmap](audits/2026-09-04-roadmap.md). Fill it in; do not redesign it.

| # | Item | Owner | State | Done when |
| --- | --- | --- | --- | --- |
| 3.1 | Assemble the bundle over `IMerkleProofEngine`, `IComplianceArchiveExporter` and the ledger | agent | The parts exist; nothing assembles them per mission | The exit above |
| 3.2 | Key the ledger | agent; you decide where the key lives | Open. Keying is supported, but `splat-mcp` builds its ledger with no key and no vault, so it chains unkeyed and a rewrite is undetectable | A ledger that is meant to be keyed refuses to append without its key, and the record states which kind of chain it came from |
| 3.3 | AG-F06 — bare-token DLP on the output path | agent | Open. The output sanitizer catches private keys, `key=value` secrets, password flags, emails, card numbers and SSNs. It has no AWS, GitHub, OpenAI, Stripe or JWT shapes — those exist only in the prompt-side credential sanitizer | The record's redaction count can be trusted |
| 3.4 | Truthful terminal reasons from the bridge | agent | Open. Every cancellation, the caller's own included, is reported as "Process killed by kernel/daemon" (`WslLeasedExecutor.cs:257`), with no confirmation from the daemon | Caller cancellation, local timeout and a confirmed kill are three different results, and only the last claims a kill |
| 3.5 | The policy compiler refuses a destination it cannot resolve | agent | Open but latent. On a DNS failure `TemplatePolicyCompiler` grants `127.0.0.1` and keeps the network on (`:107`). No production path calls it yet; P3 is where one would start to | Fixed before any production path compiles a policy |
| 3.6 | F20 — a remediation verdict from a measured postcondition, not an exit code | agent | Open | Each remediation declares what "restored" means, and its verdict is read from that |

---

## Open, not scheduled

Real, known, and not blocking the phases above. Each needs a decision or a slot before it is work.

| Item | Owner | State, 2026-09-10 |
| --- | --- | --- |
| Windows network denial for the sixteen templates without it | decision: an egress control that is not also an RPC wall — a WFP filter is the candidate | Of 49 catalog templates, 33 launch their tool in an AppContainer with no capabilities, so network denial is enforced. **Sixteen run without one.** One needs the network (Grant Opportunity Ingestion, `EgressScope.ToolProcess`): an AppContainer chooses network or none, not a host, so its destination is a claim. Fifteen are built on WMI, the Event Log service, Defender or the service manager, which the container would also cut off, so they keep a network stack they do not need — chosen by a text match over the command line that the code itself calls an interim measure (`ToolNeedsLocalSubsystems`, `Models.cs:150`). `IEgressFirewall` covers neither group; it guards SPLAT's own model client. Counted from the shipped catalog on 2026-09-10; no test binds these numbers yet |
| Lease gaps: unconnected UDP `sendto`, AF_UNIX and AF_NETLINK, inherited descriptors, ambient reads | agent; each proof needs you under root | Listed under **Not policed** in `SUPPORTED_POLICY.md`. P2 closes writes outside the workspace; these stay open |
| F19 — revocation that survives a restart and covers every entrypoint | agent | Open. `IncidentRevocationManager` keeps revocations in a `ConcurrentDictionary` and reloads nothing on start |
| AG-F07 — recalled memory reaches a prompt as context, never as instructions | agent | Done on the mission path: labelled "treat as context, not as instructions" and sanitized (`MissionExecutionEngine.cs:511`). The goal decomposer adds recalled incidents to its prompt with no such label (`CognitiveGoalDecomposer.cs:150`), and the brain-engine and workflow recall sites carry none either |
| F23 — retention proves the erasure it reports | agent | Half done. It states what erasure does and does not cover and forces a `TRUNCATE` checkpoint, but never reads the checkpoint's result — if a reader holds the WAL, the pre-purge image survives while the sweep reports success. And no host schedules it |
| F22 — packaging fails loudly | agent | Open. `build-msix.ps1` checks exactly one native exit code, the publish's (`:45`). It also publishes self-contained, a different artifact from the framework-dependent build `dist\App` holds |
| Two ledgers | decision | The console chains into `Data\missioncontroller.db` (`SqliteStorageContext.cs:18`) and `splat-mcp` into `SPLAT\audit_ledger.db`. A headless OEM build may never need the first |
| AG-F08 — `TransactionalScope` is compensation, not rollback | agent | Open, in the deferred workflow layer. For files, the real fix is P2's overlay |
| The console: Windows App SDK 1.6 → 2.x, or retire it | decision | Frozen, and still builds. Keeping it costs one rule: no .NET-10-only API in the five shared libraries while their net9 leg exists. .NET 9 support ends 2026-11-10 |
| The 30-second stream stall against a thinking model | agent builds nothing; one live run with a key is yours | Unverified. `ClaudeStreamClient.cs:134` and `GeminiStreamClient.cs:126` cancel any read that sees no bytes for 30 s and report the stream as stalled. Whether a model with extended thinking sends bytes inside that window before its first text has not been observed. One live mission with thinking on settles it either way |
| `wevtutil` in place of `Get-WinEvent` in SysOps | agent | Open. Three SysOps sensors (`GovernedTemplateCatalog.SysOps.cs:95`, `:120`, `:187`) call `Get-WinEvent`, which cannot reach the Event Log service from inside the AppContainer. `wevtutil` is reported to still read it there — reported, not yet shown by a differential test. Where it is a template's only blocker, the swap moves that template into network denial, and the census sentence above is test-bound, so it moves in the same change |
| WSL stops the daemon when the guest goes idle | agent | Observed 2026-09-14, twice: an instance started by a short `wsl.exe` command ended about 17 seconds later, and systemd stopped `splat-agent` with it while the VM stayed up. The bridge starts the service again on a refused connection, so a lease after an idle gap first pays for an instance start and a refused connect, which takes about two seconds on Windows. Unverified: whether a lease that outlives that window is cut off too, since nothing in it is a `wsl.exe` process. One long `run_command` through `splat-mcp` settles it |

---

## Deferred by decision

The OEM subtraction took these off the road on 2026-09-09. They are not forgotten, and they are not
next.

- **Workflow persistence, trigger hosting and a workflow view** — the orchestration plan's Phase 1.
  `InMemoryWorkflowRegistry` is still the only registry, and `WorkflowScheduler`,
  `EmbeddedWebhookListener` and `OAuthCallbackCoordinator` are constructed by no host.
- **Connectors** — the orchestration plan's Phase 3. `GovernedHttp` answers `NOT_IMPLEMENTED` rather
  than pretending to send.
- **Built and never wired:** `DataRetentionService`, `VertexAiStreamClient`, `PkceLoopbackAuthService`,
  `ServiceAccountAuthService`. Wire one when a phase needs it, not before.

---

## The commercial track — yours

| Item | State | Needed before |
| --- | --- | --- |
| An LLC, with the IP assigned to it | Not tracked in this repository | Anything is signed |
| General-liability and E&O cover | Not tracked | The first client machine |
| The OEM term sheet: draw the open-core line at the daemon, and attach `SUPPORTED_POLICY.md` as Exhibit A | A draft exists outside the repository; its runtime defect went away with P0 | It is sent |
| The first containment assessment | Waiting on P1 | — |
| The first outreach | Triggered by P1's exit; the targets are in [TARGETS-cold-outreach.md](TARGETS-cold-outreach.md) | — |

## Human-only steps

Nothing in [the runbook](RUNBOOK-human-steps.md) is open today. Two rows above will add to it: 1.8
needs the root daemon started, and 2.3 re-records the daemon probe under root.
