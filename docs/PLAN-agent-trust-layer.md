# SPLAT agent trust layer — implementation plan for the substrate-over-surface pivot

**What this plan is.** [PLAN-kernel-substrate.md](PLAN-kernel-substrate.md) builds the missing
Layers 2–3 (canary → daemon → vsock → policy compiler). *This* plan productizes that substrate
into the pivot: SPLAT as the kernel sandbox + audit standard other agent runtimes plug into,
not a workflow-UI competitor. Phases here consume the substrate plan's outputs; nothing here
re-specifies them.

**Tree status verified 2026-08-29** (shared tree — re-verify before building on any of it):
- C# seams **exist and compile**: `ILeasedExecutor`, `ITemplatePolicyCompiler` in
  [Interfaces.cs](../src/MissionController.Core/Interfaces.cs); `WslLeasedExecutor`,
  `TemplatePolicyCompiler`, `WslSubstrateHealthChecker` in `MissionController.Infrastructure.Linux`
  (Debug artifacts present).
- Wire contract **exists**: [proto/splat_sandbox.proto](../proto/splat_sandbox.proto) —
  `ExecuteTool` (streamed chunks incl. `CHUNK_TYPE_VIOLATION`), `HealthCheck`, `RevokeLease`,
  `ResourceLimits`, `OverlayFsConfig`.
- Rust side is **still the single-shot canary** (`native/splat-canary/Cargo.toml` has no
  tokio/tonic). No resident daemon exists yet. Nothing kernel-side has run on this machine.
- Ledger seams exist (`IAuditLedger` + `SqliteChainedAuditLedger`, `IMerkleProofEngine`,
  `IComplianceArchiveExporter`, `RetentionPolicy`); verify which have implementations before
  Phase 4 — the Merkle engine implementation was not located in the last sweep.

**Dependency spine** (strict order; the de-risking sequence): substrate green → resident
daemon → MCP facade → audit chain → bench + open-core. Phases 3 and 5 can proceed in parallel
once Phase 1 lands; everything else is ordered.

---

## Phase 0 — Substrate green gate (delegated; BLOCKING for all phases below)

Complete substrate plan Phases 0–3: preflight all-green on the live kernel, canary printing
real `-EPERM` from all three hooks, resident daemon skeleton, one exec round-tripped from C#
over vsock **with measured p50/p99 latency**. Human-only steps (WSL install, `.wslconfig`,
`wsl --shutdown`) are listed there and unchanged.

**DoD:** the substrate plan's Phase 0–3 DoDs, plus the 15-second `-EPERM` asciinema captured.
No phase below starts on an unproven substrate — that is the whole point of the pivot.

---

## Phase 1 — `splatd`: from demo daemon to fail-closed service

Harden the Phase-0 daemon into the thing external tools can trust.

- **Fail-closed lifecycle.** Daemon death must never unleash a leased process: every leased
  cgroup gets `cgroup.kill` on lease-drop paths, and a supervisor (systemd unit in the guest,
  or host-side watchdog via `HealthCheck`) kills all leased cgroups if `splatd` dies
  uncleanly. Test with `kill -9` mid-mission.
- **Recovery.** On restart, enumerate orphaned lease cgroups and reap them; never re-adopt.
- **Versioned lease schema.** Add a schema/ABI version to the proto and the eBPF map layout
  now, before anything external speaks it — the lease format is the future standard, and
  unversioned standards rot instantly.
- **Egress honesty.** `socket_connect` sees IPs, not names. v1 egress control is IP/port
  (exactly what the proto declares). FQDN-level filtering is a later feature via
  lease-compile-time DNS resolution (TTL-pinned) or a guest DNS proxy — do not claim FQDN
  filtering before one of those exists.
- **Landlock spike (timeboxed, optional).** Landlock is already in the stock active LSM list —
  evaluate it as a degraded-mode fallback for machines where editing `lsm=` is unacceptable.
  Outcome is a one-page verdict, not a second enforcement path in v1.

**DoD:** `kill -9 splatd` during a mission leaves zero leased processes alive; restart is
clean; two concurrent missions hold independent leases; violation events carry mission id and
schema version.

---

## Phase 2 — `splat-mcp`: the universal facade (the distribution wedge)

An MCP server exposing `run_command`, `run_code`, `fs_read`, `fs_write` — every invocation
compiled to a `LeaseSpec` and executed through `ILeasedExecutor`.

- **It lives host-side, in C#.** A small console project (`src/splat-mcp`) referencing Core +
  Infrastructure.Linux, using the official `ModelContextProtocol` NuGet SDK over stdio
  (universal client support; streamable HTTP later). Guest-side placement is rejected: it
  would bypass the template registry, vault, and audit ledger that make the host the policy
  authority.
- **Default-deny per workspace.** A `.splat/policy.json` in the workspace root declares
  allowed roots, egress, and executables; `TemplatePolicyCompiler` turns it into the lease.
  No policy file → read-only scratch sandbox, no egress. An MCP call can never widen its own
  lease — widening is a human edit to the policy file.
- **Every call is a ledger row** (tool, lease intent, outcome, violations) through
  `IAuditLedger` — this is what makes Phase 4's "permitted vs. touched" report possible for
  third-party clients, not just SPLAT missions.
- **Violation surfacing.** A blocked action returns a structured tool result naming the hook
  and the denied target, so the calling agent (and its user) sees the `-EPERM` in-band.

**DoD:** a real Claude Code session with `splat` added as an MCP server runs a build command
sandboxed; a canary injection attempt (`curl` to an unleased IP, write outside the workspace)
returns the violation in the tool result and lands in the ledger; both captured as recordings.

---

## Phase 3 — Transactional scratchpads: branch → test → commit/rollback

Make OverlayFS rollback a first-class mission primitive, not plumbing.

- **Filesystem constraint to design around:** OverlayFS over drvfs/9p (`/mnt/c`) is not a
  supported lower layer. The workspace must be mirrored into guest ext4 (rsync into a
  per-mission dir, or a mounted VHDX) before overlay; on commit, export the upperdir delta
  back to the Windows workspace and record the delta manifest in the ledger.
- **Proto surface:** add scratch lifecycle to `splat_sandbox.proto` — commit/discard as
  explicit RPCs (or a mission-final disposition on `ExecuteTool` completion), plus a delta
  manifest message.
- **Speculative N-way execution:** N cgroups + N overlays over one lower; host-side selector
  commits exactly one winner, discards the rest. This is the capability no orchestrator has —
  it gets its own demo recording.

**DoD:** a mission that corrupts its scratch leaves the Windows workspace hash-identical
(verified by a before/after Merkle of the tree); a 3-way speculative run commits exactly one
branch; commit produces a ledger-recorded delta manifest.

---

## Phase 4 — Flight recorder: permitted vs. touched, provably

Bind kernel evidence to the ledger that already exists in the tree.

- Ingest lease intents (the compiled `LeaseSpec`) and the kernel violation stream into
  `SqliteChainedAuditLedger`, keyed by mission.
- **The report that sells it:** per-mission "declared vs. observed" — what the template/policy
  promised, what the kernel saw attempted, what was denied. v1 records intents + violations;
  sampled allow-auditing (logging permitted opens/connects too) is a follow-on flag, priced
  for its overhead.
- Complete the Merkle path: verify/implement `IMerkleProofEngine`, wire
  `ComplianceArchiveExporter` to emit a bundle (lease specs + events + chain heads + proofs)
  that an **independent verifier script** (no SPLAT dependency) can validate on a clean
  machine. Retention (`RetentionPolicy`) applies to the event stream without breaking chain
  verifiability — retention must prune in verifiable units, not arbitrary rows.
- **Language discipline:** SHA-256 hash chain + Merkle proofs = *tamper-evident*, never
  "tamper-proof"; on an attacker-owned host it evidences integrity, it does not guarantee it.

**DoD:** mutating any ledger row makes verification fail loudly; an exported bundle verifies
via the standalone script on a machine that has never seen SPLAT; the declared-vs-observed
report renders for a real mission.

---

## Phase 5 — Fleet: many agents, one responsive workstation

- Host-side mission scheduler over `ILeasedExecutor`: concurrency caps, queueing, priority,
  and a global kill-switch (revoke-all).
- Extend `ResourceLimits` with `cpu.weight` and io weight; enforce `cpu.max`,
  `memory.high/max`, `pids.max` per lease (fork-bomb containment test is mandatory).
- WSL2's global memory/CPU clamp (`.wslconfig` `memory=`, `processors=`) bounds the whole
  guest — a human-applied setting; document it as the fleet's outer wall.

**DoD:** ≥4 background missions run while a foreground mission's latency (measured, not
eyeballed) stays within an agreed envelope; a fork-bomb mission is clamped by `pids.max` and
revoked without affecting siblings.

---

## Phase 6 — SPLAT-Bench: the containment scorecard

- Harness runs *as a SPLAT mission itself* (dogfooding is the credibility claim): drive an
  agent with public prompt-injection corpora, targets are benign canaries only — exfil
  attempts point at loopback sinkholes, "secrets" are planted markers, no real payloads.
- **Metric: Containment Rate** — of the actions a compromised agent attempted outside its
  lease, how many did the kernel deny — plus a scratchpad-diff proof of zero side effects
  outside the lease. Explicitly *not* a detection/refusal metric; the model is allowed to
  fall for the injection. Bound the claim: SPLAT shrinks blast radius, it does not block
  injection.
- Output: versioned JSON scorecard + HTML page + asciinema per scenario; methodology doc
  published with the corpus list so results are reproducible by outsiders.

**DoD:** a clean-machine run reproduces the scorecard; at least one external-client scenario
(Claude Code via `splat-mcp`) is benchmarked end-to-end; every reported number traces to a
recorded run.

---

## Phase 7 — Open-core split + the lease-format spec

- **Public repo:** `splatd` + eBPF programs + proto + versioned LeaseSpec spec doc. Licensing
  decided deliberately: the BPF object is GPL-2.0 (kernel-helper requirement; the canary crate
  already declares it) — pick the userspace daemon license (Apache-2.0/MIT vs GPL) as an
  explicit business decision, not a default.
- **The spec doc is the moat artifact:** the portable lease format (declared exec/files/
  egress/limits → kernel maps) written so another runtime could emit it. If others emit
  leases, SPLAT owns a standard, not a feature.
- **Release engineering:** static musl builds, checksums + signed releases, CI proving the
  canary on a stock non-WSL kernel. Known risk: stock CI runners don't boot with `lsm=…,bpf` —
  plan a QEMU/self-hosted step for the enforcement test rather than skipping it.
- Commercial layer stays private: WinUI suite, fleet governance, compliance exporter,
  SIEM/EDR bridges, vault. Bench leaderboard publishes with this release — proof and product
  land together.

**DoD:** an outsider on plain Ubuntu, using only public release artifacts and the spec doc,
runs `splatd` + `splat-mcp` and reproduces a blocked canary.

---

## Phase 8 — Horizon (explicitly unscheduled): airgapped nodes

Headless `splatd` + local inference (Ollama/vLLM/llama.cpp) under zero-egress leases, with
offline attestation bundles. Real market (defense, trading, regulated R&D), but it is a
deployment story on top of Phases 1–7 — starting it earlier would be building the roof first.

---

## Cross-cutting rules (carry the substrate plan's discipline forward)

- **Measured numbers only.** Every latency/overhead/containment figure in any public artifact
  traces to a recorded run. The `<1ms` class of claim stays dead until measured.
- **Honest language.** "In-kernel (BPF-LSM) enforcement inside a Hyper-V-isolated guest," not
  "hardware-enforced syscalls." "Tamper-evident," not "tamper-proof." "Bounds blast radius,"
  not "blocks prompt injection." IP/port egress until FQDN filtering actually exists.
- **Human-only steps** are unchanged from [AGENT-BUILD-BRIEF.md](AGENT-BUILD-BRIEF.md): WSL
  install/OOBE, `.wslconfig`/`wsl.conf`, elevation, passwords, `wsl --shutdown`.
- **Shared tree.** A second agent works this repo concurrently — re-read files immediately
  before editing and prefer `Edit` over `Write` so collisions surface as failed matches.
- **Benign canaries only.** The bench and every demo prove a boundary holding; nothing in
  this plan builds real exfiltration, real payloads, or evasion.
