# The OEM subtraction — what to build in the 62 days that are left

Written 2026-09-09, against a strategy note that picked OEM/embedded licensing as the commercial
path and listed four engineering gaps to close before it is sellable.

> **The state of every item lives in [the roadmap](../ROADMAP.md).** This document is the argument
> for the order. When an item moves, update the roadmap; update this only when the argument does.

The positioning in that note is right, and the repo's own audits already agreed with it
(`2026-09-04-competition-and-scope.md`, `2026-09-05-antigravity-deep-audit.md`): SPLAT is an
execution substrate, not an orchestrator, and competing with n8n on connector breadth is a category
error. Nothing below re-argues that.

What follows is the part the note got wrong, the part it collapsed too generously, and the part it
left out entirely — which is the only one with a date attached.

---

## 1. Verified today, on this machine

Everything in this plan rests on claims that were re-run rather than recalled.

| Claim | How it was checked | Result |
| --- | --- | --- |
| 459 tests green | `dotnet test tests/MissionController.Tests` | **459 passed, 0 failed, 0 skipped**, exit 0, 29 s |
| Tree state | `git status --short --branch` | clean, `main`, in sync with `origin/main` at `7398609` |
| Linux substrate under root | `native/splat-agent/evidence/daemon-probe.json` | PASS, 15 checks, hash-bound to `lease_lsm.bpf.c` |
| The "last hop" | read `src/splat-mcp/Program.cs`, `McpServerHandler.cs` | **already wired** — see §2 |
| CLI surface | `grep -n "args\[" src/splat-mcp/*.cs` | **no matches** — `Main(string[] args)` never reads `args` |

---

## 2. Where the strategy note is wrong

**"Gap 1 — the last hop in `splat-mcp` is not wired."** False, and has been false since the wire
work landed. `Program.cs:103` constructs `WslLeasedExecutor`; `McpServerHandler` holds it as
`ILeasedExecutor` and `run_command` calls `ExecuteLeasedAsync` with a lease whose
`AllowedExecInodes` is the requested command and nothing else. The transport is a versioned
line-delimited JSON envelope over authenticated loopback TCP, and both halves have evidence files —
`wire-contract-probe.json` (arguments survive byte for byte) and `peer-auth-probe.json` (an
unauthenticated caller cannot execute).

What is *actually* missing there is narrower, and is documented in the executor's own constructor
remark: **AF_VSOCK**. Today the daemon authenticates a shared secret over loopback, which stops an
unprivileged process inside the guest and does **not** stop another Windows process running as the
same user. That is a real gap for a multi-user host, and it is not the one the note named.

**"Gap 4 — add ephemeral CoW scratch disks."** Already written, already refused, and the refusal is
the correct state. `native/splat-agent/src/cow.rs` holds working overlay mount code and a header
explaining why calling it would be a lie: the overlay mounts in the *daemon's* mount namespace, so
it is visible host-wide, and a merged directory handed to a child as its cwd is a starting point,
not a jail — the tool leaves it with one `cd /`. `SUPPORTED_POLICY.md` therefore lists
`overlayFs.enableCow` under **Refused**, so the daemon turns the field away rather than accepting it
and ignoring it. This is not a gap to open. It is a gap that is already honest, and is waiting on §3.

**What the note left out.** The runtime floor. .NET 9 leaves support on **2026-11-10 — 62 days from
today** — and .NET 8 expires the same day, so there is no LTS to retreat to. Windows App SDK 1.6
(the pin in `MissionController.UI`) has been out of support for over a year; 1.8 goes out **today**.
A term sheet whose §4 promises "compatibility builds for target OS kernels" on a runtime that is
unsupported inside the initial one-year term is not a document to send anyone.

---

## 3. The collapse: three of the four gaps are one piece of work

The note lists dynamic exec rights for agent-written code (gap 2) and CoW scratch (gap 4) as
separate items, and `SUPPORTED_POLICY.md` separately refuses `readOnlyFs`. All three are the same
missing capability:

> **the workload has no mount namespace of its own.**

`unshare(CLONE_NEWNS)` followed by `pivot_root`, inside the same `pre_exec` closure that already
performs the cgroup join and the privilege drop. That single change:

- makes `readOnlyFs: true` enforceable, so it can move out of **Refused**;
- makes the overlay in `cow.rs` a boundary instead of a suggestion, so `overlayFs.enableCow` can
  move out of **Refused**;
- gives a leased scratch directory that is the workload's *entire* filesystem view, which is the
  only correct way to let an agent execute code it just wrote;
- deletes the largest line in the **Not policed** table — "filesystem writes outside the workspace."

And it is the item to be most careful about, because that closure is async-signal-safe code in a
forked child of a multithreaded process. `cow.rs` already says so. Budget it as the hard one.

**Reject the note's proposed fix for gap 2.** "Inherit execution rights for files generated inside a
leased scratch directory" reintroduces exactly the hole the current design closes on purpose: it
lets the workload author its own permission. The comment in `McpServerHandler.ExecuteRunCommandAsync` records why
`AllowedExecInodes` is pinned to the requested command — an empty list meant the daemon assembled
its own, "which made the request its own authorization." The namespace fix keeps that property; the
inheritance fix trades it away.

---

## 4. The subtraction: choosing OEM deletes the UI from the critical path

This is the part worth more than any feature below it.

An OEM licensee embeds a headless engine. They do not want `MissionController.UI`, a SQLite workflow
registry, a webhook listener, or a canvas. They want a daemon, a wire contract, a policy vocabulary,
and a document stating exactly what is enforced. **So the OEM decision subtracts Phase 1 of the
2026-09-05 orchestration plan wholesale** — wiring, persistence, triggers, the one view.

Follow that through:

- No UI on the critical path → **no Windows App SDK on the critical path.**
- WinAppSDK 1.6 → 2.x was the expensive, four-major-version, XAML-breaking half of the runtime
  migration. Removing it turns Phase 0 from "budget real time for breakage" into a TFM bump across
  six non-UI projects that have no WinAppSDK dependency at all.
- The nine-week fuse stops being a crisis and becomes roughly two days of work.

`MissionController.UI` is not deleted, and — corrected 2026-09-09 after reading the reference graph
— it is not simply frozen either, because a naive freeze does not compile. The UI references `Core`,
`Infrastructure.Windows`, `.Network` and `.Data`; a `net9.0-windows10.0.19041.0` project cannot
reference a `net10.0` one. Moving those four breaks the UI build the same afternoon.

So the four libraries **multi-target**: `<TargetFrameworks>net9.0;net10.0</TargetFrameworks>` (and
`net9.0-windows;net10.0-windows` for `Infrastructure.Windows`). Executables and tests single-target
`net10.0-windows`. The UI keeps building against the net9 leg on WinAppSDK 1.6, ships nothing, and
gates nothing.

That costs one line per library — there is not a single `#if NET9_0` or TFM-conditional in the tree,
so both legs compile from the same source — and it buys back the decision instead of spending it.
The constraint it imposes is real and worth writing down: **no .NET-10-only API in the four shared
libraries** until the UI is either migrated or dropped, because the net9 leg has to keep compiling.
The net9 leg is unsupported after 2026-11-10, which is fine: nothing that ships runs on it.

---

## 5. Sequence

Dates are the ordering argument, not a commitment.

### P0 — the runtime floor, headless  ✅ DONE 2026-09-09

**Landed the same day it was written, and it was smaller than the estimate.** SDK `10.0.401`
installed beside `9.0.317`; eight `.csproj` files retargeted; **459/459 green on
`.NETCoreApp,Version=v10.0`**; and `MissionController.UI` still builds clean on the net9 leg, which
is the claim §4 rests on. Not one line of C# changed — the survey was right that there is no
TFM-conditional code in the tree.

Three things the build found that the plan did not:

- **A high-severity advisory was shipping.** `Microsoft.Data.Sqlite` 9.0.2 pulled
  `SQLitePCLRaw.lib.e_sqlite3` 2.1.10, which carries `GHSA-2m69-gcr7-jv3q` — surfaced as `NU1903`
  the moment the restore graph was disturbed. It reached both legs, so it shipped in `dist\App` too.
  This is F21 turning out to be a security item rather than a packaging one. Fixed by conditioning
  the version per TFM: 9.0.20 on net9, 10.0.12 on net10.
- **`System.Text.Json` was dead weight** on net10 (`NU1510`) — it is in the shared framework now.
  Removed from `splat-mcp`.
- **`System.IO.FileSystem.AccessControl` 5.0.0 was genuinely removable**, as suspected.
  `NtAclJailManager` compiles without it.

The build is now **zero errors, zero warnings** on both legs, which it was not before.

<details><summary>The steps as originally written</summary>

Surveyed 2026-09-09. There is no `global.json`, no `Directory.Build.props` and no
`Directory.Packages.props`; no `#if NET9_0` anywhere in `src` or `tests`; the reference graph is a
plain DAG. This is eight `.csproj` edits and five package bumps, not a migration.

1. **Install the .NET 10 SDK — the only blocking step, and it is not code.** Only `9.0.317` is
   present, in a *user-local* root (`%LOCALAPPDATA%\Microsoft\dotnet`), so install via
   `dotnet-install.ps1 -Channel 10.0 -InstallDir "$env:LOCALAPPDATA\Microsoft\dotnet"` rather than
   winget — a second dotnet root under Program Files would leave two `dotnet.exe` that disagree
   about which SDKs exist.
2. **Multi-target the four libraries** per §4: `Core`, `.Data`, `.Linux`, `.Network` →
   `net9.0;net10.0`; `.Infrastructure.Windows` → `net9.0-windows;net10.0-windows`.
3. **Single-target the executables and tests**: `splat-mcp`, `splat-bench`,
   `MissionController.Tests` → `net10.0-windows`.
4. **Bump the five framework-versioned packages** 9.0.2 → current 10.0.x: `Microsoft.Data.Sqlite`,
   `System.Security.Cryptography.ProtectedData`,
   `Microsoft.Extensions.DependencyInjection.Abstractions`,
   `Microsoft.Extensions.DependencyInjection` (UI only — leave it), `System.Text.Json`. Bump
   `Microsoft.NET.Test.Sdk` (17.12.0) far enough to know about `net10.0`.
5. **Try deleting `System.IO.FileSystem.AccessControl` 5.0.0.** `NtAclJailManager` uses
   `DirectorySecurity` and `FileSystemAccessRule`, which live in `System.Security.AccessControl`
   in-box on `net*-windows`; that package has been a deprecated compatibility shim since .NET 5.
   Remove it, build, and put it back only if something actually fails.
6. **Run the suite. 459 green on .NET 10 is the exit condition** — not "it builds."
7. F21 (`SQLitePCLRaw` native bundle) lands here, while the dependency graph is already open.

First, because everything after it would otherwise be written against a TFM that dies inside the
first OEM contract term, and would have to be ported twice.

</details>

**P1 is now the front of the queue**, and with the runtime floor behind it there is nothing blocking
it but work.

### P1 — installable and provable by a stranger (Sep 12 → Sep 26)

This is not "gap 3 of 4." For a solo operator with no network, a thing an engineer can run in ten
minutes **is the entire top of the OEM funnel.** No CTO signs a term sheet off a cold email; they
sign after their own engineer ran it and read `SUPPORTED_POLICY.md`.

- **Give `splat-mcp` a CLI.** `Main` currently ignores `args` entirely, so the
  `--workspace ./my-project` stanza in the strategy note does nothing today. Parse it, bind it to
  `WorkspaceGuard`'s root, and refuse to start without one rather than defaulting somewhere
  surprising. *Landed 2026-09-11 with one change: the flag is optional. Without it the file tools
  stay confined to SPLAT's own private folder, which fails safe rather than open, and the server
  names that folder on stderr; requiring it would have broken every existing launcher for no
  containment gain.*
- **`splat-mcp doctor`.** One command that reports kernel version, BPF-LSM availability, daemon
  binary and token state, and then prints what will and will not be enforced on *this* host — read
  out of the policy tables, never hardcoded. A host where the substrate is absent must say so and
  refuse the enforcing modes, in the same fail-closed spirit as `fail-closed-probe.json`.
- **Distribution.** A self-contained single-file `splat-mcp` per platform, published as a `dotnet
  tool` and an `npx` shim. No MSIX, no installer, no UI.
- **First-run provisioning.** Inherited from the retired `PLAN-substrate-completion.md`. Two of its
  other three gates closed: the gRPC/JSON ambiguity was settled by deleting `proto/`, and kernel
  evidence is machine-checked in `daemon-probe.json`. The third, Windows egress, is **not closed**
  — corrected twice: this bullet first recorded it as closed, then as closed for every tool that
  needs no network. Of the 49 catalog templates, 33 launch their tool network-denied in an
  AppContainer. Sixteen do not: one needs the network, and its destination stays a governance claim
  until a broker or WFP filter exists; fifteen are built on WMI, the Event Log service, Defender or
  the service manager, which the container would also cut off, so they keep a network stack they do
  not need. The state is tracked in [the roadmap](../ROADMAP.md). Provisioning never got built at
  all — `WslProvisioner` does not exist in the tree. Detect WSL, import the distro, health-check, and **fail loud with the specific
  missing piece**. The failure mode that matters is a user believing they have kernel containment
  when provisioning quietly failed, which is the same failure `doctor` exists to prevent.
- **F24 — one capability manifest.** CLI, MCP `tools/list`, `SUPPORTED_POLICY.md` and the tests all
  read the same file. The moment an outsider can run this, drift between those four becomes a
  credibility problem rather than a tidiness problem.

Exit condition: **a stranger with WSL2 adds one stanza to their MCP config, runs a command that is
denied by the kernel, and can point at the line in the policy document that predicted it.**

### P2 — the mount namespace (Sep 26 → Oct 24)

§3, in full. `unshare(CLONE_NEWNS)` + `pivot_root` in `pre_exec`; move `readOnlyFs` and
`overlayFs.enableCow` out of **Refused**; leased scratch execution for agent-authored code.

Evidence, or it did not happen: extend `probe-daemon.sh` and `daemon-probe.json` with a check that a
write outside the workspace fails, that a file created in scratch executes, that the same file
outside scratch does not, and that the scratch layer is gone after teardown. A control that is not
observed failing was never measured.

AF_VSOCK belongs here too if it fits — same file, same trust question.

### P3 — the per-mission run record (Oct 24 → Nov 14)

The 2026-09-05 plan put the verifiable run record at the *workflow* level, which required the
registry, the triggers and the UI that §4 just subtracted. **Rescope it to a single mission.** A
per-mission record needs none of that, and it is what an OEM licensee resells.

Per the earlier plan, this is assembly, not invention: `IMerkleProofEngine`,
`IComplianceArchiveExporter` and `SqliteChainedAuditLedger` already exist and already operate on the
`AuditLogEntry` rows a mission writes. What it emits per mission: the template and policy SHA-256,
the clamps **read back from the kernel object** rather than from the request, the egress rule and
whether it was enforced or merely declared, the BPF verdicts, the DLP redaction count, the exit
contract, and a Merkle proof binding the ledger rows to a root.

AG-F06 (bare-token DLP rules for AWS / GitHub / OpenAI / Stripe / JWT) lands here, because the run
record counts redactions and a counter that misses raw tokens is a false attestation.

**Do not design the schema from scratch.** `2026-09-04-roadmap.md` already carries a six-group
policy-and-evidence contract — request identity, effective permission, enforcement state, outcome,
cleanup, integrity — written before there was anything to attach it to. That table is the schema;
this phase is filling it in from things that already exist.

Exit condition, unchanged from the original: **someone who did not run the mission can verify from
the bundle alone what it was permitted to do and what it did.**

### Parallel, not sequenced — the commercial track

- **LLC and IP assignment.** A sole proprietorship cannot sign the term sheet's §5. This is
  paperwork, it is cheap, and it blocks signature rather than engineering — start it now, in
  parallel with P0.
- **Cold outreach.** `docs/TARGETS-cold-outreach.md` already names the tiers. The sending trigger is
  P1's exit condition, not P3's.

---

## 6. What pays before OEM does

The strategy note treats OEM licensing as the monetization plan. It is the *scaling* plan. It has a
gap at the front that no amount of engineering closes: an OEM licensee is a company that has already
decided local agent containment is worth paying for. In September 2026 that is a belief, not a
measurement — and it is now the largest unretired risk in this project, because the technical risk
already got retired and this one did not.

**Using SPLAT on our own work does not, by itself, make money.** The usual dogfooding argument fails
here for a specific reason: SPLAT's output is risk reduction, not speed. A tool that makes your own
work *safer on your own machine* gives you nothing you needed, and costs you setup. There is no
compounding loop in generic self-use.

The loop exists in exactly one shape: **paid engagements whose deliverable is the containment
evidence itself.** Then the client work and the P3 roadmap work are the same work.

- **"What can your coding agent actually reach?"** A fixed-scope assessment: instrument a real dev
  host, run the client's own agent configuration under a lease, and hand back a measured
  reachability report — what the agent touched, what it could have touched, and a governed config
  that closes the difference. Nobody else can produce this document, because producing it requires
  kernel-level observation of an agent's syscalls bound to a policy. `SUPPORTED_POLICY.md` is the
  credibility exhibit that gets the meeting.
- **A 30-day governed pilot.** `splat-mcp` on a handful of developer machines, run records handed
  over at the end, config handed over with it. This is P1's exit condition, sold.

Both need **P1 and nothing beyond it**. That reframes P1: it is not merely the top of the OEM
funnel, it is the first thing that can be invoiced. P2 and P3 make the engagements better; they do
not gate the first one.

**The trap, named so it can be avoided.** Services revenue is linear in one person's hours, and it
is comfortable, and it eats roadmaps — solo founders who fund product work with client work
routinely end up running a consultancy. So: fixed scope, fixed price, no retainers, no "while you're
in here, could you also…", and a hard cap of **two concurrent engagements**. Every engagement must
leave behind a reusable artifact — a template, a probe, a report generator — or it was a job rather
than a business.

**And do the LLC first.** It matters more here than it does for OEM: an assessment engagement puts
you on someone else's host. A sole proprietorship carries that personally. LLC, IP assignment, and a
basic general-liability/E&O policy before the first client machine, not after.

Acquisition interest (`docs/PITCH-Microsoft-CorpDev-Copilot-Safety.md`) is a byproduct of a traction
record, not a path. It becomes possible for the same reason OEM does, and not one day sooner.

---

## 7. Three defects in the term sheet

The draft is structurally sound. These three would be found by the first licensee's counsel.

**The open-core line is drawn in the wrong place.** §2 forbids standalone distribution and exposing
raw RPC interfaces, while the commercial plan puts `splat-mcp` under Apache 2.0. Those contradict:
`splat-mcp` *is* a raw client of the engine, and an Apache-2.0 grant cannot be clawed back by a
later OEM contract. Draw the line at the **daemon** — `splat-agent`, the BPF programs, the Windows
containment primitives — and keep the MCP server, the policy vocabulary and the wire contract open.
That is also the better commercial shape: the open half is what drives adoption, and it is useless
without the closed half.

**§4 promises maintenance on an unsupported runtime.** "Compatibility builds for target OS kernels,"
signed today against .NET 9, commits to a one-year term whose runtime is unsupported after week
nine. P0 fixes this, and P0 must land before the sheet is sent.

**The warranty disclaimer is a liability, and it should be an asset.** §6 disclaims that the engine
prevents all arbitrary execution — standard, and weak, because every vendor says it. Attach
`SUPPORTED_POLICY.md` as **Exhibit A**, incorporated by reference. It is the most commercially
unusual document in this repository: a security vendor contractually enumerating what it does *not*
enforce — UDP `sendto`, AF_UNIX, inherited descriptors, ambient reads — alongside what it does, with
a probe file and a source hash behind each claim. No competitor in this space will match that, and
it converts the disclaimer from boilerplate into the reason an engineer trusts the rest.

---

## 8. The fork, and how much smaller it got

The first draft of this document called the UI a hard either/or: freeze it or spend the nine weeks
on a four-major-version WinAppSDK migration. Reading the reference graph made that false in the
useful direction. Multi-targeting the four libraries (§4) keeps `MissionController.UI` compiling on
the net9 leg for one line per project, so the choice does not have to be spent now — it is deferred,
not taken.

What remains open is smaller and slower-burning: **at some point the net9 leg has to go**, because
holding it costs a real constraint (no .NET-10-only API in the shared libraries) and that constraint
gets more expensive the longer it runs. When it does, the UI either crosses the WinAppSDK 2.x break
or it is dropped. Nothing in P0–P3 forces that call, and it should not be made under deadline
pressure now, when the honest answer is that no OEM licensee and no assessment client will ever run
that surface.

The near-term recommendation is unchanged in substance: build headless, ship headless, keep the UI
alive at the cost of one line each, and revisit after P1 has produced either an invoice or a
licensee.
