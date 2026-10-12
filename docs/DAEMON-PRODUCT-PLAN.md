# The Rust daemon as a product

Decision, 2026-10-10: keep the daemon as the enforcement product that desktop, MCP and future
platform clients share. A thin Rust client is a future integration surface; it is not a reason to
rewrite the existing mission engine. Commercial packaging and licensing remain product decisions.

## Existing foundation and its limit

The four hooks are `bprm_check_security`, `file_open`, `socket_connect` and `socket_sendmsg` in
[`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c). The committed
[`daemon-probe.json`](../native/splat-agent/evidence/daemon-probe.json) records PASS on 2026-10-06
against BPF source `6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1`.
That evidence covers its recorded controls, not the future features below. The policy limits in
[`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) remain part of the contract.

Roadmap 5.0 shares lifecycle operations through [`MissionController.Host`](../src/MissionController.Host).
The desktop can request a lease through [`ManagedBridgeClient`](../src/MissionController.Host/ManagedBridgeClient.cs)
without receiving the service's guest token. Eight public source sensors now use the Linux launcher
and its compiled IPv4 destinations. Their TLS client verifies the publisher's certificate and
refuses redirects; this is sensor behavior, not general hostname enforcement against arbitrary code.
Live desktop mount, managed deployment and current source recordings remain acceptance work.

## Delivery order and acceptance

| Priority | Planned capability | Implementation boundary | Evidence needed before the claim ships |
| --- | --- | --- | --- |
| 1 / 5.2 | One step receives one platform credential | An authenticated private secret-delivery channel binds a grant to its caller, mission, step, destination and expiry. No secret in command arguments, ordinary protocol traces, model context, ledger or exported record. Start children with an explicit environment. Drain the workload before closing descriptors and removing scratch. | Positive authorized request; wrong caller, wrong step and sibling lease denied; environment and `/proc` inspection; stdout/stderr and export leakage controls; cancellation, timeout, spawn failure and daemon restart cleanup. Record remaining memory-copy and privileged-observer limits. |
| 2 / 5.7 | One approval runs several platforms concurrently | Authorize the complete plan, then give each step its own lease, credential grant and destination. Bound concurrency; bind every signed child outcome, failure and cancellation to one parent record. | Seven concurrent platform fixtures, cross-lease secret denial, partial failure, cancel-all, restart and missing-child detection; independent verification of the aggregate record. Existing concurrent policy isolation is not proof of this orchestration or of secret isolation. |
| 3 | Enforce hostnames behind shared CDN addresses | A daemon-owned HTTP gateway authorizes the hostname and establishes upstream TLS itself. Kernel policy permits only the gateway for these workloads. Generic CONNECT tunnels and caller-controlled upstream resolution cannot bypass the check. | Two hostnames sharing one IP: allowed name succeeds, other name fails. Reject mismatched Host/SNI, redirects, direct-IP sockets, DNS rebinding and alternate ports; tie requests to a live lease and record gateway refusals. |
| 4 | Execute local inference inside a lease | Inventory the model's files, runtime, GPU devices and IPC first. Grant the minimum required resources and use an offline model artifact. Model execution is a separate workload capability with its own policy. | Real inference on the supported guest/GPU combination; resource limits; denied network and file controls; cancellation and device/IPC escape-path review. Current lease evidence does not establish GPU confinement. |
| 5 | License the daemon for Linux hosts | Package a service, a versioned protocol and a small client API. Separate the operator from the service principal, authorize callers and scope policy per tenant. Validate BPF-LSM, cgroup v2, privileges and libraries on each supported distribution. | Fresh-host install, upgrade and rollback; cross-account and cross-tenant denial; service lifecycle and recovery; signed outcomes with a trusted key identity; a published compatibility matrix. A standard Linux kernel alone is not sufficient. |

Local deletion ends SPLAT's access to a supplied secret; it does not revoke a long-lived credential
at its provider or prove that every memory copy disappeared. Prefer provider-scoped, short-lived
tokens when available. A permitted destination can still receive data, so secrets and output
handling require proof alongside network restrictions. Product comparisons require testing the
specific competing deployment; this plan makes no blanket claim about n8n or Zapier.

The current [`WorkflowExecutionEngine`](../src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs)
iterates a topological order sequentially, and `GovernedHttp` is still a stub. Priority 2 therefore
depends on priority 1 and the platform work in roadmap 5.5/5.6. Priority 3 can be developed alongside
those integrations. Priority 4 is a separate proof effort, not a prerequisite for the first product.

## Identity is a release gate

Protocol 3 authenticates possession of a shared secret. It does not identify a Windows user.
The managed service adds OS-authenticated named-pipe admission and an operator policy, but roadmap
2.4 stays open until the separate-account deployment, owner positive control, cross-account denial,
service lifecycle and keyed ledger pass on the packaged artifact. See
[`THREAT-MODEL.md`](THREAT-MODEL.md) and [`probe-managed-bridge.ps1`](../packaging/probe-managed-bridge.ps1),
whose header gives the gate's three runs: the admitted owner, an unadmitted account, and an elevated
`splat-mcp audit --managed` that reads the keyed ledger the owner is denied.
Changing the guest socket transport cannot supply that identity boundary.

A Linux service requires its own caller authorization and tenant model; the Windows pipe does not
transfer that proof to a cloud deployment. A hostile local administrator is outside the separate
service-account boundary. Preserve these limits in the commercial exhibit.
