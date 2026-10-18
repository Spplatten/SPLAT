# A2A requests bound to approved template leases

The local adapter is implemented in `src/splat-mcp/A2aServer.cs`, `A2aBridge.cs`,
`A2aConfiguration.cs` and `A2aTaskStore.cs`. It exposes an authenticated HTTPS endpoint for
the [A2A 1.0 JSON-RPC binding](https://a2a-protocol.org/latest/specification/), with a required
SPLAT extension. It delegates each accepted skill to the existing manifest-bound MCP handler.
The approved template fixes the command, parameters, resources, network and optional execution
policy; the requesting agent supplies no replacement execution authority.

This is a local profile with synthetic interoperability coverage, not a claim of complete A2A
conformance or compatibility with every agent SDK. `A2aBridgeTests` exercises authentication,
caller grants, task isolation, replay, recovery, revocation, capacity, cancellation and HTTPS.
`A2aPublishedProofTests` is an explicitly enabled packaged-host proof against the installed daemon.
An ordinary test run skips that live proof; a skip is not an enforcement result.

## Start an approved receiver

1. Review and import an agent using `splat-mcp import-agent <manifest.json>`. Retain its returned
   `agentId` and `contractSha256`. The receiver uses that same database through `SPLAT_DB_PATH`.
2. Provide a current PFX certificate with its private key and a SAN for `127.0.0.1`. Clients must
   validate its certificate chain or explicitly pin its certificate. No trust-store change or
   plaintext HTTP fallback is performed by SPLAT. If the PFX is password-protected, supply
   `SPLAT_A2A_CERT_PASSWORD` to the host process.
3. Save the configuration below under operator-controlled permissions, using the actual imported
   ID, hash and certificate path. Give each caller a separately generated random credential of
   at least 32 bytes, encoded as hex or unpadded base64url. Store only its lowercase SHA-256 digest
   in the configuration. Deliver the credential to its intended agent through your secret store.
4. Start `splat-mcp a2a --configuration <configuration.json>`.

| Configuration field | Meaning |
| --- | --- |
| `schemaVersion` | `1` |
| `agentId`, `agentVersion` | Imported agent ID and exact compiled-contract SHA-256 |
| `port` | Local HTTPS port, 1024–65535; listener is fixed to IPv4 loopback |
| `certificateFile` | Absolute path to the operator's PFX |
| `callers` | Explicit array of caller grants, at most 64 |
| `callers[].tenantId`, `callers[].callerId` | Stable operator-assigned identity; not taken from messages |
| `callers[].tokenSha256` | SHA-256 of the ASCII bearer credential, 64 lowercase hex characters |
| `callers[].skills` | Explicit subset of the approved manifest's tool names |
| `callers[].expiresUtc` | Credential expiry as a UTC ISO 8601 timestamp |
| `callers[].requireDelegation` | Require a verified delegation for every new task; enable for worker-only credentials |
| `callers[].maxConcurrentTasks`, `maxRetainedTasks` | Per-principal bounds; defaults divide host capacity across configured callers, with a minimum of one |
| `delegationKeyFile` | Optional absolute path to the operator's P-256 private PEM; required to issue grants |
| `delegationIssuers` | Explicit `{agentId, contractSha256, publicKey}` trust pins; public key is base64 SPKI P-256 |
| `maxConcurrentTasks` | Defaults to 4, at most 16 |
| `maxTasks` | Durable task capacity, defaults to 512, at most 4096 |

Unknown/duplicate fields, duplicate credentials or principals, unavailable approval, mismatched
version and grants outside the manifest refuse startup. Only one host per agent and database may
run at once. Configuration and approvals are snapshots; changes require a controlled restart.
The existing `SPLAT_LEDGER_KEY_FILE` and `SPLAT_RUN_RECORD_KEY_FILE` settings also apply. Without
a ledger key the chain is unkeyed, as in the standard MCP host.

Windows TLS loads the PFX into a temporary user-key container because Schannel does not support
the ephemeral-key path used for standalone signing. Normal disposal removes that container;
the host does not install a certificate authority. This requirement is covered by the real
HTTPS test, rather than inferred from certificate creation alone.

## Wire contract

All requests, including `GET /.well-known/agent-card.json`, require `Authorization: Bearer`.
The returned card exposes only that caller's skills and the approved contract version.
`POST /a2a` requires `Content-Type: application/json`, `A2A-Version: 1.0` and
`A2A-Extensions: urn:splat:a2a:template-lease:v1`.

An example request for the reviewed guest-identity manifest is:

```json
{
  "jsonrpc": "2.0",
  "id": "request-1",
  "method": "SendMessage",
  "params": {
    "message": {
      "messageId": "agent-a-request-1",
      "role": "ROLE_USER",
      "parts": [{"data": {"skill": "read_guest_identity", "parameters": {}}}]
    },
    "configuration": {"returnImmediately": false}
  }
}
```

Each message creates one task. Declared template parameters must be strings. Optional
`data.parentTaskId` requires `data.delegationToken` and must match its signed parent. A parent ID
alone is refused. Natural-language instructions, file parts, remote artifact URLs, command
overrides, arbitrary tenant fields and task continuations are rejected.

`SendMessage` returns `result.task`. With `returnImmediately: true`, poll `GetTask` using
`params.id`. `ListTasks` scopes results to the authenticated tenant and caller before filtering
or pagination; it sorts by most recent update and omits artifacts unless `includeArtifacts` is
true. `CancelTask` accepts the owner's task ID. Streaming, push notifications, extended cards,
gRPC, REST and multi-turn task continuation are outside this first profile.

## Guarantees and limits

- Admission is logged and saved before execution. The fixed agent/version and each caller's skill
  grant are checked independently. The bound handler requires an enforcing lease; an execution
  policy additionally requires its installation acknowledgement.
- Task IDs, request fingerprints and results persist in SQLite. Exact retries of a message ID by
  the same principal return the original task, including after restart. A different message with
  that ID is refused. Fingerprints currently include the message's exact JSON representation;
  preserve it when retrying. This is at-most-once admission for retained IDs, not exactly-once
  external effects. A different ID can request another permitted effect.
- Interrupted tasks become failed with an unconfirmed outcome; they are never automatically
  re-executed. Durable capacity exhaustion refuses new tasks instead of evicting replay records.
  Per-caller running and retained-task limits are enforced before admission. Operator-managed
  retention remains unfinished; exhaustion never silently evicts replay records.
- Task/result access is scoped to both tenant and caller, including list filters and cancellation.
  Existing incident revocation checks refresh persistent state before each access. Active tasks
  also check caller/issuer revocation and expiry every 500 ms; an unreadable store cancels work.
  Cancellation and the bounded native lease are still required to stop an admitted process. There is no
  federated identity, OAuth delegation or automatic credential rotation in this profile.
- Cancellation sends an authenticated control frame and waits for the daemon's signed drained
  outcome. Only a verified receipt for this invocation sets `workloadTerminationConfirmed=true`;
  transport failure leaves it false. A canceled status alone is not termination evidence.
- The audit chain connects A2A task/caller/version to the bound tool's trace and lease result.
  Bound calls require outcome v2, signing the execution-policy hash, effective native-policy hash,
  receiver contract, authenticated tenant/caller, task, requesting agent/contract, parent and token
  digest. `BoundLeaseReceiptTests` covers cross-invocation, signature and field tampering. This is
  a guest-key signature, not remote attestation of a trusted kernel or honest guest root.
- Request bodies are capped at 64 KiB, result storage at 512 KiB per task, and concurrent HTTP
  connections at 64. The endpoint accepts only loopback host headers and rejects browser Origin
  headers. It is not a remote ingress server or a defense against its privileged Windows owner.
- A poisoned requester cannot expand the declared grant through this endpoint. Misuse of data or
  actions already permitted by the grant still needs application authorization. The remote agent's
  own execution, prompt-injection detection and semantic correctness are outside this boundary.

## Signed delegation

An authenticated parent-task owner calls the SPLAT extension `splat/DelegateTask` with
`parentTaskId`, `audience`, `audienceVersion`, `callerId` and `skill`. The host signs only the
authority actually admitted for that parent, with its original expiry and a maximum depth of four.
The recipient passes the returned `delegationToken` in its structured `SendMessage` data.
Configure `requireDelegation=true` on the worker principal: a separately granted unrestricted
credential remains separate authority and must not be given to that worker.

The receiver verifies P-256/SHA-256, pinned issuer contract/key, exact receiver contract, tenant,
caller, skill, expiry and parent. It intersects executable paths, freshly resolved host/IP pins,
ports, resources, duration, syscalls and file grants with its own approved template. It unions
protected paths and preserves read-only restrictions. Missing required authority refuses admission.
SQLite consumes each nonce atomically with task insertion. An exact retry returns the same task;
a new message ID cannot reuse that token, including after restart. `A2aDelegationTests` and
`LeaseAuthorityTests` exercise narrowing and durable replay refusal.

This is a SPLAT extension, not generic OAuth delegation or an A2A-standard capability token.
Immediate issuers can be revoked as `a2a-agent:<agentId>@<contractSha256>`. Transitive federated
revocation, cross-machine trust provisioning and public remote ingress remain outside this profile.

## Community and Corporate

Both editions use the same adapter and containment path. The adapter adds the ASP.NET Core shared
framework and no third-party A2A SDK. The existing publisher labels its output `AGPL-3.0-only`;
that output is a Community artifact. A Corporate distribution requires the separate grant in
`COMMERCIAL.md` and its own correct package metadata and dependency notices. This feature does
not convert a Community binary into a Corporate release, and the proof is not licensing clearance.

## Reproduce the live proof

Build the test project first using the repository's .NET 10 SDK, and publish a separate proof
artifact with `packaging/publish-splat-mcp.ps1 -OutputDir <proof-directory>`. Select it with
`SPLAT_A2A_PROOF_EXE=<proof-directory>/splat-mcp.exe`, then run the built test project with
`--no-build --filter FullyQualifiedName~A2aPublishedProofTests`.

The runner requires an already enforcing, idle resident daemon whose running binary matches the
package. It preserves the service and BPF pins, uses isolated databases and expiring random
credentials, and records both allowed public guest reads and a narrower contract's Landlock denial.
It also checks wrong-version startup, poisoned/overriding requests, cross-tenant reads/cancellation,
retry and restart behavior, audit correlation and unchanged enforcing service identity afterward.
Diagnostics are retained under `dist/a2a-proof-results`. Set `SPLAT_RECORD_A2A_EVIDENCE=1` to record
a successful source-bound result in `native/splat-agent/evidence/a2a-bridge-probe.json`.

## Verification recorded 2026-10-17

The [authority proof](../native/splat-agent/evidence/a2a-authority-probe.json) recorded **114/114
passing checks** in the run started at 15:57:58 UTC, with [signed receipts and task observations](../native/splat-agent/evidence/a2a-authority-details.json).
It exercised published Community host SHA-256
`d35b71b9e35170edbf1dfd76a27af1e499d837c2689c6452a928c84de7a6fbe1` and daemon SHA-256
`1a340b116c7b90b441058bd8e201fa22592860f8d559bbf1efafba0c1ad67743` against their recorded compiled
source inventory. The three RARE sensors completed using real public Apple data. Two local HTTPS
agents demonstrated signed narrowing, wrong/missing grant refusal and durable replay refusal.
Cancellation and a revocation written by another process both produced a verified signed drain.
The runner restored the original installed service and checked enforcement afterward; it did
not deploy the new daemon permanently. It made **zero model API requests**.

The RARE-specific attack cases refused generic tools, forged caller/tenant/command/network policy,
duplicate and poisoned parameters, and a parent ID without delegation. Other callers and tenants
could not read, cancel or list the victim's task artifacts. Repeated requests returned the original
task. A deliberately substituted hostile Python body, run directly under the RARE reviews lease,
received kernel `EPERM` for both a shell exec and loopback connection. That last probe measures a
hypothetical compromised runtime below A2A; the endpoint itself never accepts caller-supplied code.
These cases do not prove that a model resists every prompt injection or that public federation is safe.

To reproduce this approved temporary-service workflow, build the tests and publish the package,
then run `native/splat-agent/probe-a2a-authority.py` with explicit `--daemon`, `--mcp-exe`,
`--manifest`, `--client-root`, `--dotnet`, `--test-project` and `--output` paths. The runner refuses
active leases and validates any `--retire-idle-pins` source hash before replacement. It restores
the original service on failure as well as success. Do not point the old resident-daemon proof
above at a different installed binary.

The private Semantic Kernel governance compatibility suite recorded **10 passed, 0 failed** in
`private/enterprise-proof/SemanticKernelGovernance/TestResults/rare-a2a-sk-governance.trx`, after
a zero-warning build. This checks compatibility of the private adapter; it does not establish a
Corporate distribution or remove the commercial licensing and dependency gates.

The 2026-10-17 full managed suite recorded **1,083 passed, 3 failed, 6 skipped** out of 1,092 in
`tests/MissionController.Tests/TestResults/rare-break-full-20261017.trx` (3m7s). The failures were
DNS cache observation, missing RARE recordings and Field Guide publication. Four model-request
tests and two opt-in published proofs were skipped; the
new published authority proof was run separately and passed. Native component tests recorded
**97 passed, 0 failed, 10 ignored** out of 107; ignored privileged checks are not runtime proof.
The complete solution built with zero warnings/errors on 2026-10-17. The local A2A, RARE sensor,
receipt and archive regressions passed 55/55 in `rare-break-component-20261017.trx`.

The attempted three-template Anthropic run on 2026-10-17 was refused by automatic approval review
before execution because it requires separate explicit permission. The Windows elevation launch
was canceled, so no new elevated DNS result exists. Neither event is a passed test.

## RARE model recordings verified 2026-10-18

The operator explicitly authorized only `source-consumer-catalog`, `source-consumer-reviews` and
`source-consumer-offers` to send their filtered public Apple data and routine mission metadata to
`api.anthropic.com`. The scoped corpus test passed in `rare-live-corpus-20261018.trx` (1m59s),
recording one actual `claude-haiku-4-5` answer per template through the real Linux lease and replaying
each against its live verdict. The reviews and offers used app ID `570060128`.

The reviewed [fixtures](../tests/MissionController.Tests/Fixtures/Missions/) retain mission IDs
`971e77f1-fcfd-4e3b-90dc-998b1133b9ea` (catalog), `e80517a6-6a55-4e66-818e-49b4309f606b`
(offers) and `3d531b79-2e17-4bde-92ce-5c1c878656bd` (reviews), with their genuine template/prompt
hashes, model answers and verdicts. One review title's personal first name and school name were
replaced with same-width synthetic text; neither appeared in the answer. No expectations were
blessed. Coverage, privacy, offline replay and corpus adversarial gates passed **9/9** in
`tests/MissionController.Tests/TestResults/rare-corpus-validation-20261018.trx`.

The test project built with zero warnings/errors. With all provider-consent flags disabled, the
full managed suite recorded **1,084 passed, 2 failed, 6 skipped** out of 1,092 in
`tests/MissionController.Tests/TestResults/rare-corpus-full-20261018.trx` (2m46s). The two failures
are unchanged: DNS cache observation was unavailable and the published Field Guide is stale.
Four provider tests and two opt-in published proofs were skipped; skips are not passes.

This closes current-definition recording coverage for the 61 shipped templates. It does not
establish factual accuracy: the accepted catalog answer reports 16 topics/144 apps against a
capture of 17 cohorts/157 apps; the review answer miscounts ratings and misattributes citations;
the offer answer infers billing variants without displayed terms and omits required offer citations.
Each fixture's note preserves these limitations. This recording pass does not establish live
prompt-injection resistance or approve the analyses for RARE publication.

Windows DNS cache observation still needs elevation, and the generated Field Guide must actually
be republished before its publication record can change. The earlier failed runs remain historical
evidence; the three-recording permission does not authorize other templates or host telemetry.

## Historical verification recorded 2026-10-14

The [packaged proof](../native/splat-agent/evidence/a2a-bridge-probe.json) recorded **52/52 passing
checks** at 20:43 UTC. It exercised the published Community host with SHA-256
`da65d66d24b54f88228e47217b88534a0be595bf97040ec691d99a058ca94800` and the resident daemon with
SHA-256 `870ad87ee3f5d9ba0077fb710583c9c6649798e22d08a89c2ac4d4c60e4adbeb`. Compiled source hashes
matched before and after the run. The positive lease used UID 200000, acknowledged its execution
policy and removed its workspace. Removing the `/proc/meminfo` grant in a separately approved
contract produced a workload permission denial inside an enforcing lease. The daemon PID and
binary remained unchanged; authenticated health reported enforcement and zero active leases afterward.

The test project built with zero warnings/errors. Focused A2A, manifest, daemon-wire and
documentation regressions recorded **112 passed, 0 failed, 1 skipped** in
`tests/MissionController.Tests/TestResults/a2a-bridge-regression.trx`. The skipped packaged proof
was then explicitly run and passed in `a2a-published-proof.trx`; it is the source of the 52 checks
above. These results do not establish a green full suite, a Corporate package, remote federation,
or a verified cancellation drain.

The subsequent full run recorded **1016 passed, 5 failed, 1 skipped** out of 1022 in
`a2a-full-regression.trx`. Three live-model checks received HTTP 400 with the provider's
insufficient-credit error. The corpus gate reports nine stale template recordings. The Windows
DNS containment test could not find its unconfined control in the DNS Client cache; the same
control failure reproduced in isolation in `a2a-dns-control-recheck.trx`. That check establishes
neither a DNS containment pass nor a breach. No assertion or recording was weakened to make
this feature appear release-ready.

A later funded-key check on 2026-10-14 passed the fixed synthetic prompt in
`live-key-funded-synthetic.trx` (one passed; first byte 4.3 seconds, 216 characters in 5.1 seconds).
That resolves the key/reachability check only. The two host-telemetry reruns were blocked before
execution by automatic approval review, and the operator then declined further Anthropic
transfers. They remain unproven with the funded key. The earlier full-suite HTTP 400 responses
do not establish that Anthropic never received the submitted host telemetry or retained none.

`LiveAnthropicFactAttribute` now makes all four Anthropic tests explicit opt-ins, with separate
consent for host telemetry and corpus recording. `LiveAnthropicConsentTests` checks the gates
without external requests; a stored key alone enables no live test. The corpus coverage and DNS
control failures remain unresolved, and skipped external tests do not close those evidence gaps.

The local consent-gate and provider-stub regression recorded **34 passed, 0 failed, 4 skipped** in
`anthropic-consent-gates.trx`, with all external-request opt-ins unset. All four real-provider
tests were skipped during discovery. The build recorded zero warnings/errors. This verifies
the default test gate without sending a new request to Anthropic; it does not change the scope
or licensing of the packaged A2A proof above.
