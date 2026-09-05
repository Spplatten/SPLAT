# SPLAT remediation waves

Working plan derived from the four reports in this directory. The audits say *what* is broken and
*why*; this says **which wave it lands in and who owns the file while it does**.

Two agents edit `C:\C_AGENT_BUILDER` concurrently. Most of the friction so far has not been
disagreement, it has been two sessions writing the same file minutes apart. So every wave below
names an owner and a file set, and the rule is: **do not edit a file listed under the other owner's
active wave.** Report the finding instead.

Finding IDs: `Fnn` from [clinical audit](2026-09-04-clinical-audit.md), `AG-Fnn` from
[antigravity deep audit](2026-09-05-antigravity-deep-audit.md). Sequencing rationale is in the
[roadmap](2026-09-04-roadmap.md); positioning in [competition and scope](2026-09-04-competition-and-scope.md).

---

## Wave 1 — Truthful execution and identity (done)

| Finding | Change | Commit |
| --- | --- | --- |
| — | Workflow engine reports node failure, one execution id, injection refused at the binder | `461001b` |
| F16 (part) | `GovernedHttp` and `OAuthExchange` stop claiming work they never did | `461001b` |
| F02 / AG-F02 | Ledger verifies the payload an auditor reads, not just the commitment | `379f86b` |
| F03 | Unkeyed verification no longer accepted once a key is configured | `379f86b` |
| F01 / AG-F03 | MCP resolves identity at the dispatch gate, before any executor or filesystem call | `379f86b` |

Each fix is proven differentially: the attack test fails against the parent commit and passes after,
with a negative control asserting the legitimate path still works.

## Wave 1b — Windows containment (in flight, other session)

| Finding | Change | Files — do not edit |
| --- | --- | --- |
| AG-F01 / F18 | Loopback `:5678` auth gate | `Triggers/EmbeddedWebhookListener.cs` |
| F12 | AppContainer selection must exempt templates whose sensors need WMI/EventLog RPC | `Models.cs`, `GovernedTemplateCatalog.*.cs`, `SensorAppContainer.cs` |
| — | Containment differential tests, documented test count | `SensorNetworkContainmentTests.cs`, `README.md`, `TUTORIAL.md`, `SPLAT-Field-Guide.html` |

**Open review note on the in-flight gate:** `IsAuthorized` returns `true` when no token is
configured, so a host without `SPLAT_API_KEY` set is exactly as open as before the fix. A loopback
execution endpoint should mint an ephemeral token at startup and fail closed when it has none.
Token comparison should also be `CryptographicOperations.FixedTimeEquals`, not `string.Equals`.
The OAuth callback route cannot carry a bearer header — a browser redirect lands there — so its
protection has to be the `state` nonce (AG-F05), which is currently accepted and discarded.

---

## Wave 2 — Failure is not evidence

The single highest-value remaining wave, because every downstream claim inherits it: a failed run
must not become accepted evidence, indexed memory, or a successful tool result.

| Finding | Change | Owner |
| --- | --- | --- |
| F13 | `MissionExecutionEngine` stops on nonzero exit and timeout instead of logging and continuing | contended — assign |
| F13 | `QualityIslandEngine` result is not published or indexed when `IsSuccess` is false | free |
| F13 | `SandboxedRemediationEngine` verdict comes from a postcondition, not from exit code alone | free |
| F16 | `AgentReasoning` with no model client fails instead of emitting `Status: VERIFIED` | free |
| F16 | A workflow whose only node is unimplemented reports failure, not `Success=true` | free |
| F14 | Raw stdout/stderr is sanitized before it leaves through MCP, not only before the model call | contended — assign |

Exit gate: force a tool failure, a timeout, malformed model output and an exhausted quality island;
assert an unsuccessful terminal result and zero accepted-memory insertions in each.

## Wave 3 — Linux fail-closed and lease isolation

All Rust, no C# contention. Largest wave; can run fully in parallel with Wave 2.

| Finding | Change |
| --- | --- |
| F04 | No execution when BPF open/load/attach or map write fails; health reports observed state, not hardcoded `true` |
| F05 | Expiry keeps the workload denied, then kills and reaps the cgroup before removing policy |
| F06 | Policy keys include mission/cgroup identity, so concurrent leases cannot borrow each other's permissions |
| F09 | The provisioned cgroup carries the accepted limits, read back, and fails closed |
| F07 | The bridge peer is authenticated; caller-supplied policy is not the authorization source |
| F08 | Publish the actual supported syscall/protocol matrix and refuse policy outside it |

Exit gate: concurrent A/B leases prove non-interference; a child and grandchild that outlive the
parent leave no survivors within the agreed bound.

## Wave 4 — Boundaries and the wire contract

| Finding | Change |
| --- | --- |
| F10 | MCP filesystem confinement is handle-based and race-resistant, not a path-prefix string compare |
| F11 | One versioned wire contract: explicit `argv`, policy hash, effective permissions, terminal outcome |
| AG-F06 | DLP gains bare-token rules (AWS, GitHub, OpenAI, Stripe, JWT) — today only `key=value` shapes redact |
| AG-F07 | Recalled memory is wrapped in untrusted delimiters before it reaches a prompt |
| F15 / F17 | The workflow builder either registers and runs the graph it draws, or stops advertising that it does |

## Wave 5 — Release reality

| Finding | Change |
| --- | --- |
| F21 | Replace the affected `SQLitePCLRaw` native bundle; plan the Windows App SDK 1.6 exit |
| F22 | Packaging fails on missing assets, missing signing tools and nonzero native exit codes |
| F19 | Revocation survives restart and is consulted by every entrypoint |
| F23 | Retention inspects checkpoint results and states what erasure does and does not cover |
| F24 | One capability manifest that UI, MCP descriptions, docs and tests all read from |

Positioning corrections from the competition audit — the ROI arithmetic, the "every mainstream
approach" and "every cloud sandbox" claims, the unsupported 90% — can land in any wave; they are
independent of the code.

---

## The ordering argument

Wave 2 before Wave 3. A kernel boundary that cannot be bypassed is worth little while the layer
above it reports a failed run as a success — the strongest containment in the world still hands the
operator a confident wrong answer. Truthful results are also the cheapest wave and the one that
makes every later gate measurable.

Wave 4's `F15/F17` is the decision the competition audit keeps circling: SPLAT will not beat n8n on
breadth, and the workflow layer as built bypasses the mission engine it exists to protect. The
smaller, more defensible shape is a DAG scheduler *over* `IMissionExecutionEngine`, where each node
is a complete 1:1:1 mission that keeps its jail, egress pin, DLP pass and ledger row. That is a
subtraction, and it should be decided before more nodes are added.
