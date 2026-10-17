# Agent contracts at the MCP boundary

Implementation: `AgentManifestImporter`, `AgentManifestApproval`, `McpServerHandler.Agent`, and
`EXECUTE_BOUND` in the daemon. Regression coverage: `AgentManifestBindingTests` and
`WslLeasedExecutorWireTests`. Live evidence is written by `native/splat-agent/probe-agent-manifest.py`;
an implementation or test build alone does not establish a deployed enforcement result.

After reviewing an agent manifest, import it with `splat-mcp import-agent <file>`. This saves its
templates, Project Studio stages and approval record in one insert-only transaction. The result
names the agent and the SHA-256 of its compiled contract, including executable, arguments, limits,
network authority and any execution policy. The desktop's **Save agent** uses the same importer.

Start the external agent's MCP endpoint with `splat-mcp --agent <id> --agent-version <sha256>`.
Use the same SPLAT data directory/database used for import. The host checks saved templates against
the approved version and holds a private snapshot for its lifetime. Catalog or registry changes
require a newly reviewed import under a new agent ID; they cannot silently widen an active session.

`tools/list` exposes the manifest's tool names. Calls accept declared string `parameters` and
optional `traceId`/`clientName` metadata. Executables, arguments, workspace, network, duration and
execution policy come from the approved template. Generic tools, nested orchestration and the
managed service's raw-lease method are refused on a bound endpoint. Authentication and revocation
remain ahead of effects. Each admitted call records its actor, agent, version, tool and mission.

Managed services can pin `AgentId` and `AgentVersion` in their administrator-owned configuration.
The approval must exist in the service's private database. Delegate only the bound endpoint to
that agent; separately granting it an unrestricted endpoint or the daemon credential grants separate
authority. This does not change the documented same-Windows-owner or guest-root trust boundary.

Agent calls use `EXECUTE_BOUND`, which requires an enforcing daemon and outcome signing even
without an optional Landlock/seccomp contract. Old daemons reject this operation. Outcome v2
signs the policy hash and invocation identity, and the bridge verifies their exact values before
accepting success or confirmed drain (`BoundLeaseReceiptTests`). Outcome v1 remains readable
for legacy unbound calls and does not carry those additional assurances.

The [local A2A adapter](A2A-TEMPLATE-BRIDGE.md) uses the same approved binding and per-call lease.
Its own authentication, task ownership and replay journal are separate from MCP tool discovery.

## Editions

The binding and enforcement code is shared by Community and Corporate. This work adds no package
dependencies or weaker edition-specific enforcement paths. Community distribution remains AGPL-3.0;
Corporate distribution uses the separate commercial agreement described in `COMMERCIAL.md`.
An AGPL-labelled Community artifact is not a Corporate package. Commercial packaging must carry its
actual commercial grant and the required third-party notices; this feature does not supply or replace
that agreement. The live probe records the exact artifact tested and does not certify licensing.

## Live proof

Build the self-contained Community artifact into a separate output directory with
`packaging/publish-splat-mcp.ps1`. The manifest probe takes that directory's `splat-mcp.exe` and
`splat-agent`, the example `guest-identity.contract.json`, and a local client-artifact directory.
It imports a fresh agent and tests discovery, successful reads, refused generic routes, version
mismatch, a denied file, a denied syscall, a denied executable grant and an inconsistent network
contract. Network-contract refusal is admission evidence, not a runtime socket-denial measurement.

The root runner refuses active leases, temporarily runs the tested daemon, restores the original
service and verifies its binary identity and enforcing health. When idle BPF pins must be retired,
the exact installed hash is required. Obtain approval for that temporary service/pin transition.
`probe-lease-isolation.py` separately exercises sibling isolation, capacity, expiry, disconnect,
pipelining, spawn failure and crash recovery against the same daemon. Neither probe establishes a
clean-machine installer result or managed cross-account deployment proof.

## Verification recorded 2026-10-14

The [published-host proof](../native/splat-agent/evidence/agent-manifest-probe.json) recorded 50/50
checks. The [matching isolation proof](../native/splat-agent/evidence/lease-isolation-agent-bridge.json)
passes 51/51, including sibling signal/workspace/proc denial, distinct UIDs 200000 and 200001,
identity exhaustion without fallback, and disconnect cleanup. Rechecking the recorded compiled
inputs and native sources at that checkpoint found no mismatches across 254 recorded entries.
The later A2A adapter changes managed inputs; that older host proof does not prove the new A2A
host. Its separate runner and evidence are described in `A2A-TEMPLATE-BRIDGE.md`.

The tested Community host SHA-256 is
`5b3599e1c32d8fe95b5c82aa4434129ddd69f6287766a7efe5e8b1221aee89fa`;
the tested daemon SHA-256 is
`870ad87ee3f5d9ba0077fb710583c9c6649798e22d08a89c2ac4d4c60e4adbeb`.
Its build manifest labels the artifact `AGPL-3.0-only`. No Corporate artifact was produced or
certified by this proof.

A separate [resident-service check](../dist/agent-bridge-proof-results/resident-audit-2cc43f2d511f4e8d84e6ad45083e2e5c/resident-audit.json)
at 15:56:25 UTC passes 15/15 checks without restarting the service or changing pins or policy.
The running `/opt/splat/splat-agent` matches the tested daemon, its pin directory is
`6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1`, and authenticated health reports
enforcement before and after the call, with zero active leases afterward. The approved tool ran
successfully with an installed execution policy, private UID and removed workspace. The earlier
old-binary/new-pin startup mismatch is not the state observed in this check. This local audit file
and its client transcript are retained under `dist`; they are not shipped repository evidence.

| Report claim | Checked result and qualification |
| --- | --- |
| Importer and contract digest | Confirmed by the resident check: the unchanged example yields `87233c3a40d58514e45920da8092fc23744e0a69f1d75dce6264c70f1b63678f`; a duplicate import is refused. The digest covers the compiled contract and therefore depends on the catalog definitions as well as the input manifest. |
| Bound endpoint and version refusal | Confirmed: only `read_guest_identity` is advertised, `run_command` is refused, and an incorrect version exits 2 before dispatch. The wider live proof covers the other generic/nested routes. |
| Every refusal commits an audit anchor | Qualify: `AGENT_TOOL_REFUSED` is committed to the configured ledger before the policy-error result. The response anchor references the existing chain head; it is not a separate committed anchor row. Anchor retrieval can return `anchorError`. The resident check matched the refusal and response anchor to SQLite; its isolated database was `registry.db`, not the default `audit_ledger.db`. |
| Landlock/seccomp are unpoliced | Incorrect: these are kernel-enforced controls whose denials do not appear in the BPF ring-buffer telemetry. Disallowed syscalls normally return `EPERM`; Landlock file denial normally returns `EACCES`. |
| Offline networking is denied at admission | An offline policy declaring network syscalls is refused at admission. An installed explicit policy denies omitted syscalls at runtime. The 50-check MCP proof measures the former; the kernel component test measures socket denial. Network-enabled policies retain BPF IPv4 endpoint checks; no per-FQDN Landlock policy is implemented. |
| AF_UNIX remains open | This is a baseline lease limitation. Explicit execution policies reject creation of AF_UNIX/AF_NETLINK sockets, including when IPv4 networking is enabled. This does not establish complete IPC isolation or close inherited descriptors. |

The exact three-class test set (`AgentManifestBindingTests`, `AgentManifestCompilerTests`,
`WslLeasedExecutorWireTests`) was rerun: **71 passed, 0 failed** in
`tests/MissionController.Tests/TestResults/agent-binding-double-check.trx`. The test project and
WinUI project each built with zero warnings/errors; this is not a claim that a whole-solution build
was run. The broader recorded run in `agent-binding-regression.trx` was **992 passed, 7 failed** out
of 999. Two bundle tests and the isolated catalog test subsequently passed after correcting the
PowerShell module environment. Three live-model tests reporting HTTP 400 and the stale corpus
coverage failure remain unresolved; the full suite is not reported green.

The implemented bridge maps reviewed catalog bindings and explicit grants to leases, Landlock and
generated seccomp classic BPF. Arbitrary tool-schema-to-syscall inference and generated Rust/eBPF-LSM
per tool remain outside scope. Outcome v2 adds a guest signature over policy and invocation identity;
it is not hardware-backed attestation of an honest guest or kernel. The A2A document tracks the
separate source-bound proof for this newer format; the October 14 v1 checkpoint above is historical.
