# The OEM subtraction — what to build in the 62 days that are left

Written 2026-09-09, against a strategy note that picked OEM/embedded licensing as the commercial
path and listed four engineering gaps to close before it is sellable.

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
lets the workload author its own permission. The comment at `McpServerHandler.cs:601` records why
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

`MissionController.UI` is not deleted. It is **frozen** — left on `net9.0-windows` and WinAppSDK
1.6, excluded from the shipping configuration, and marked in its own `.csproj` as out of support and
not shipped. It stops gating anything. If it is ever revived, it is revived across the 2.x break
that was always going to be required.

---

## 5. Sequence

Dates are the ordering argument, not a commitment.

### P0 — the runtime floor, headless (Sep 9 → Sep 12)

1. Install the .NET 10 SDK. Only 9.0.317 is on this machine.
2. Retarget `MissionController.Core`, `.Infrastructure.Data`, `.Infrastructure.Linux`,
   `.Infrastructure.Network`, `.Infrastructure.Windows`, `splat-mcp`, `splat-bench` and the test
   project: `net9.0` → `net10.0`, `net9.0-windows` → `net10.0-windows`.
3. Run the suite. 459 green on .NET 10 is the exit condition.
4. Freeze `MissionController.UI` per §4. Do not retarget it. Do not touch WinAppSDK.
5. F21 (`SQLitePCLRaw` native bundle) lands here, while the dependency graph is already open.

First, because everything after it would otherwise be written against a TFM that dies inside the
first OEM contract term, and would have to be ported twice.

### P1 — installable and provable by a stranger (Sep 12 → Sep 26)

This is not "gap 3 of 4." For a solo operator with no network, a thing an engineer can run in ten
minutes **is the entire top of the OEM funnel.** No CTO signs a term sheet off a cold email; they
sign after their own engineer ran it and read `SUPPORTED_POLICY.md`.

- **Give `splat-mcp` a CLI.** `Main` currently ignores `args` entirely, so the
  `--workspace ./my-project` stanza in the strategy note does nothing today. Parse it, bind it to
  `WorkspaceGuard`'s root, and refuse to start without one rather than defaulting somewhere
  surprising.
- **`splat-mcp doctor`.** One command that reports kernel version, BPF-LSM availability, daemon
  binary and token state, and then prints what will and will not be enforced on *this* host — read
  out of the policy tables, never hardcoded. A host where the substrate is absent must say so and
  refuse the enforcing modes, in the same fail-closed spirit as `fail-closed-probe.json`.
- **Distribution.** A self-contained single-file `splat-mcp` per platform, published as a `dotnet
  tool` and an `npx` shim. No MSIX, no installer, no UI.
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

Exit condition, unchanged from the original: **someone who did not run the mission can verify from
the bundle alone what it was permitted to do and what it did.**

### Parallel, not sequenced — the commercial track

- **LLC and IP assignment.** A sole proprietorship cannot sign the term sheet's §5. This is
  paperwork, it is cheap, and it blocks signature rather than engineering — start it now, in
  parallel with P0.
- **Cold outreach.** `docs/TARGETS-cold-outreach.md` already names the tiers. The sending trigger is
  P1's exit condition, not P3's.

---

## 6. Three defects in the term sheet

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

## 7. The one fork

Everything above is safe to execute except one decision, and it is not mine.

**Freezing `MissionController.UI` is a real either/or.** It is nine views and a meaningful share of
the work in this tree, and §4 takes it off the road for the foreseeable future. Keeping it on the
critical path means a WinAppSDK 1.6 → 2.x migration across four major versions, in the same nine
weeks as the .NET 10 move, in service of a surface no OEM licensee will ever run.

The recommendation is to freeze it. The subtraction is what makes the deadline survivable, and it is
reversible — a frozen project is not a deleted one.
