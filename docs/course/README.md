# SPLAT from the machine upward

A ten-week, build-along course in computer systems, cybersecurity and software repair, using MissionController/SPLAT as the specimen. Assume familiarity with variables, functions and a terminal; assume no prior operating-systems, Rust or security coursework. Budget **6–8 hours per week**: two 60-minute lessons, a three-hour lab, one hour of reading, and an optional two-hour extension.

The goal is to explain an action from bytes in memory to an operator-visible result, attach a small component at an existing interface, and repair one real defect with evidence. Each week combines how the program works, how its boundary can fail, and how to improve it.

This is an applied systems course. Logic gates, registers, instruction sets, caches, virtual memory, storage and GPU execution appear where they explain this software. Transistor fabrication, full CPU design, cache-coherence proofs and writing an operating system are outside ten weeks. WSL2 virtualization and BPF enforcement are separate mechanisms; a C# wrapper establishes neither.

## Start here

From the repository root in PowerShell:

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab
.\coursework\Run-Course.ps1 -Gate Links
~~~

The [lab](../../coursework/Splat.CourseLab/Program.cs) references the actual Core project. It runs in memory with a fixture executor, without model keys, a Linux daemon, or privileged workloads. A failed assertion produces a failing process exit. The [runner](../../coursework/Run-Course.ps1) selects this workstation's user-local .NET 10 SDK; use -DotNetPath to select another .NET 10 installation.

The source baseline is **0027e577b75a118f8ec1ad29ddc5d567782ce9a7**, inspected September 10, 2026. Core and several infrastructure projects have both .NET 9 and .NET 10 targets; the MCP application and existing test project target .NET 10 on Windows. The retained WinUI project still targets .NET 9. Recheck project files when following this course on a later revision.

Use the [source atlas](source-atlas.md) to find implementations by file and symbol. Use [repair tickets](repair-tickets.md) to choose current work. Older audits are historical case studies: several of their failures have already been repaired.

For focused C/Rust experiments in Antigravity, follow the [five-level native systems curriculum](native-systems-curriculum.md): device encoding and ABI, process admission, ring buffers, IPC, and BPF-LSM, followed by a live last-hop capstone.

## Schedule

| Week | Bottom-up layer and two lessons | Build or attach | Evidence to submit |
| --- | --- | --- | --- |
| [1](week-01.md) | Bits, CPU and instruction execution; compilation and runtime | Byte/argument round-trip | Byte table and build graph |
| [2](week-02.md) | Memory and ownership; ABI and native calls | C/Rust layout model | Offset table and ownership map |
| [3](week-03.md) | Processes and scheduling; Windows privilege boundaries | Fake process launcher contract | Launch timeline and deny tests |
| [4](week-04.md) | Linux cgroups and leases; kernel enforcement | Capability matrix at the lease seam | Map-key trace and evidence classification |
| [5](week-05.md) | Files and object identity; durable, verifiable storage | Temporary ledger/key-provider fixture | Tamper and vault-failure cases |
| [6](week-06.md) | IPC, networking and framing; identity and egress | Injected DNS resolver or bounded reader | Wire trace and negative cases |
| [7](week-07.md) | Async scheduling; cancellation, expiry and cleanup | Measured executor decorator | Concurrent traces and outcome table |
| [8](week-08.md) | Contracts and finite orchestration; model evidence and trust | Fake model/mission engine | Truth table and rejected-evidence test |
| [9](week-09.md) | Composition, UI and GPU; architectural repair decisions | Console composition wrapper | Dependency drawing and repair design |
| [10](week-10.md) | Repair and regression proof; packaging and release evidence | One focused production patch | Capstone patch, tests and limitations |

Every week ends with questions and answer checkpoints. Use them to explain the program aloud before advancing.

For complementary beginner skills, follow [what to learn next](learn-next.md): programming fluency, debugging, requirements, data ownership, recovery and communicating design decisions.

## Eight- and twelve-week options

| Duration | Explicit arrangement | Workload |
| --- | --- | --- |
| 8 weeks | Combine 1+2 and 8+9; keep 3, 4, 5, 6, 7 and 10 separate. Move GPU detail to reading. | About 8–10 hours/week; keep every core lab and the capstone. |
| 10 weeks | Follow the table. | About 6–8 hours/week. |
| 12 weeks | Follow weeks 1–9; week 10 becomes an instructor-led Linux integration lab; week 11 a storage/performance clinic; original week 10 becomes week 12. | About 6–8 hours/week. |

The extra Linux week uses the existing native probe scripts in a disposable, instructor-provisioned guest. Students record kernel, source hashes, control cases and policy refusals. They must distinguish a reachable daemon from active enforcement.

The extra performance week profiles a temporary ledger under concurrent append/read, records query plans, and compares measured wall time with CPU accounting. Repeat with one proposed index or transaction change and state the observed tradeoff. No speed claim is accepted without its workload and measurement.

## Two ways to build

**Build through the pieces:** re-create small mechanisms against local fixtures: argument encoding, a process-launch trace, a chained-log verifier, a frame parser, and a bounded mission runner. Keep intentionally faulty versions in coursework fixtures. Compare the fixture's guarantee with the production implementation before proposing a patch.

**Attach at an interface:** use ILeasedExecutor, IProcessLauncher, IAuditLedger, IModelStreamClient or IMissionExecutionEngine. The supplied [MeasuredLeasedExecutor](../../coursework/Splat.CourseLab/MeasuredLeasedExecutor.cs) is a completed example. Students add an ActivityListener in a teaching host and supply their real or fake inner executor through composition.

A C# interface fills much of the contract role a C header serves. For native structures, inspect the real C definitions and Rust repr(C) types together. Do not edit generated vmlinux.h or introduce a second production policy definition merely to teach layout.

## Assessment

| Component | Weight | Passing work |
| --- | --- | --- |
| Weekly source traces and explanations | 20% | Names callers, owners, data representations and effect order. |
| Labs and reproducible evidence | 35% | Commands, expected and actual results, and meaningful negative tests. |
| Cybersecurity case studies | 20% | Names attacker-controlled input, authority boundary, failure and regression invariant. |
| Final repair | 25% | Minimal patch, pre-fix failure, post-fix pass, integration boundary and remaining limitations. |

A total of 70% passes, but a capstone cannot pass if it hides unsupported enforcement, turns failure into success, or labels simulated results as live containment proof.

For every lab submit: source revision; changed files; command; fixture/input; expected result; actual result; and whether the result is **source-reviewed**, **fixture-tested**, **host-tested**, or **end-to-end tested**. Record unavailable prerequisites as unverified. Copying a committed evidence file is evidence review, not a fresh run.

## Teaching boundaries

Use temporary workspaces and databases for exercises. Live Linux enforcement is an advanced supervised option because it needs kernel support and a privileged daemon; the core course remains runnable without it. Tests that merely exercise mock transport cannot close that gate.

The coursework adds learning material, a runner and a contract-compatible observation wrapper. The listed production repairs are student assignments, not changes already made by this course. [Verification](verification.md) records what was actually run while preparing it.
