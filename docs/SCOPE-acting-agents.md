# Scope — SPLAT that acts

**Written 2026-10-09.** This is a scope, not a claim. Where something below **exists**, it names the
file or the evidence that shows it; everything else is planned, and the state of each piece lives in
[roadmap P5](ROADMAP.md). Read [`THREAT-MODEL.md`](THREAT-MODEL.md) before building any of it.

---

## 1. What SPLAT is for

SPLAT was designed for AI orchestration: an agent that sets up an app on Meta, TikTok or X and wires
its webhooks, or changes a codebase and proves its tests still pass, with one approval for the whole
job. Containment is the reason that is safe to allow. It is not the product on its own.

A lease is worth what it costs only when the agent inside it can change something. An agent that only
reads can be audited by reading its script. So the measure of this scope is whether one person can
press one button, approve one plan, and get real work done on systems they own, with a signed
record of exactly what changed.

## 2. How it got here

The acting half was never built. It was simulated, and then the simulation was made honest.

- `dev-app-provisioner-bot` printed *"Network handshake simulated. Webhook HMAC secret generated in
  secure memory."* No secret was generated and nothing was provisioned. Commit `575b79b` made it a
  configuration reviewer that says it contacts nothing.
- `marketing-social-campaign-publisher` promised to schedule posts and echoed its parameters. The same
  commit made it a draft composer that says no platform was called.
- The workflow engine's `OAuthExchange` node throws *"a fabricated token must not enter the credential
  vault"*, and `GovernedHttp` returns `[GOVERNED_HTTP:NOT_IMPLEMENTED] No request was sent`
  ([`WorkflowExecutionEngine.cs`](../src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs)).

Every one of those corrections was right. Taken together, they removed every action and kept every
read, because reads are the easiest thing to prove. The engineering went into containment, which is
real and proven, so the cage is finished and nothing inside it does anything.

## 3. What already exists

| Piece | State | Evidence |
| --- | --- | --- |
| Writable sandbox the host never sees | **Exists, proven under root** | `cow_overlay_in_child`, `cow_host_unchanged`, `cow_no_host_mount`, `cow_concurrent_isolation`, `cow_scratch_removed` in [`daemon-probe.json`](../native/splat-agent/evidence/daemon-probe.json) |
| Running what the agent wrote, and nothing else | **Exists, proven under root** | `scratch_exec_inside`, `scratch_exec_outside_denied`, `scratch_exec_other_lease_denied`, same file |
| One destination per lease, held by the kernel | **Exists, proven under root** | `egress_permitted_destination_allowed`, `egress_unleased_destination_blocked`, `egress_denied_when_network_off`, `undeclared_egress_refused`, same file. The allow-list is IPv4 addresses and ports; IPv6 is refused outright, and a DNS lookup is a destination like any other ([`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)) |
| One host per request from SPLAT's own process | **Exists** | [`EgressFirewallHandler`](../src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs), a `DelegatingHandler` scoped per call with `BeginScope(fqdn)`. It guards the console's calls to the model provider. It is a check inside the process that also holds the vault, not a kernel boundary |
| A credential store | **Exists** | [`DpapiCredentialVault`](../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs) behind `ICredentialVault` |
| An action contract with proof | **Exists, one declared** | `RemediationAction` in [`Models.cs`](../src/MissionController.Core/Models.cs): fix, rollback, a validation command with expected output for each, risk level; [`SandboxedRemediationEngine`](../src/MissionController.Infrastructure.Windows/Remediation/SandboxedRemediationEngine.cs) refuses any step that declares no postcondition. One template declares one: `sysops-time-sync` starts W32Time, pinned by `ExactlyOneTemplateInTheCatalog_DeclaresARemediation`. An unelevated console cannot run it, because W32Time grants start only to SYSTEM, administrators and its own service identity (§5 of the first-remediation handoff, moved out of the repository on 2026-10-14) |
| A model that chooses the next step | **Exists** | [`GovernedInvestigationLoop`](../src/MissionController.Core/GovernedInvestigationLoop.cs): five-step ceiling, no repeats, catalogue-only selection, proposed values screened and every drop written to the ledger |
| A signed record of what happened | **Exists** | Guest-signed lease outcomes (roadmap 2.5), the hash-chained ledger, the run-record bundle and its verifiers |

## 4. Where each part runs

Read from the code on 2026-10-09, not from a design.

**The desktop app is the host.** The console (`MissionController.UI`) and `splat-mcp` are two doors
onto one engine. Both build `MissionExecutionEngine` over the same catalogue, ledger and lease
selector ([`App.xaml.cs`](../src/MissionController.UI/App.xaml.cs),
[`Program.cs`](../src/splat-mcp/Program.cs)). The console is where a person picks the work, approves
it and reads the record. `splat-mcp` is how an outside agent, such as Claude Code, asks the same
engine for the same things.

**The model is never inside a lease, because it is not on this machine.** A mission runs its tool in a
sandbox, scrubs the output, and only then sends it to the model provider over HTTPS
([`MissionExecutionEngine.cs`](../src/MissionController.Core/MissionExecutionEngine.cs): the launch,
then the credential and DLP scrub, then the model). A lease holds processes on this computer, and
Claude and Gemini run in their providers' data centres. Through `splat-mcp` the model is the outside
agent calling in, which is outside for the same reason. The only way to put a model inside a lease is
to run a local one there.

**Every tool runs in a sandbox, and twelve run under the kernel lease.** Of 61 templates, 12 run
their tool in the WSL2 guest under the eBPF lease: the four Linux readers and, since 2026-10-10, the
eight web probes below. The other 49 run on Windows under a restricted token, a locked-down folder
and a job object (counted by evaluating `GovernedTemplateCatalog.All`). By what they do:

- **41 read Windows itself**: services, event logs, the registry, Defender, the network stack. They
  stay on Windows. The eBPF program polices the guest's Linux kernel, which belongs to a separate
  virtual machine, so it cannot see a Windows process, let alone contain one. Starting
  `powershell.exe` from inside the guest does not change that, because WSL interop starts it on
  Windows, outside the lease. Never route a Windows tool through the guest and call it leased.
- **8 fetch public data from one web API each** (grants.gov, BLS, EIA, Census, Wikimedia,
  rareresources.net) and read nothing on Windows. On Windows their destination was a declaration,
  because an AppContainer offers network or none, not a host. On 2026-10-10 they moved under the
  lease: each runs a Python sensor whose publisher's IPv4 addresses are compiled into the lease and
  handed to it, so it needs no DNS
  ([`LeasedWebProbe`](../src/MissionController.Infrastructure.Data/Catalog/LeasedWebProbe.cs)). None
  has run under a real lease yet.
- **3 fetch Apple's public catalog for RARE from Windows**: the consumer catalog, review and offer
  sensors. Their destination is declared and recorded, not pinned, so they are the next candidates
  for the lease.
- **5 work from their parameters and touch nothing.** Two are the actors made honest in §2, two are
  grants assessments, and one is `web-autonomous-site-deploy`. Its description still says it checks
  out, builds and deploys a site, while its tool prints its parameters and three version numbers.
  These are the first candidates to become real actions, under the lease.

**Every action runs under the lease.** Nothing an action does needs Windows. An HTTPS request to a
platform and a change to a checkout are both Linux work. So acting templates run in the guest, where
the kernel pins the step's egress to the platform's addresses, the scratch layer keeps the host
untouched and is deleted when the lease ends, and the guest signs the outcome. The pin is on
addresses, not names. A platform served from a shared front end shares its addresses with that
front end's other customers, and roadmap 5.1 records which platforms that applies to.

**A secret lives for one leased step.** The host reads it from the vault and hands it into the lease
for the one step that needs it, and it is deleted with the lease's scratch. The model names the
secret and never holds it. That keeps it out of the provider's logs, out of a hash-chained ledger
that cannot forget, and away from instructions planted in the platform responses the model reads.

**Two things are missing before any of that is true.**

- **The daemon has no channel for a secret.** `EXECUTE_TOOL` carries argv, which other processes in
  the guest can read and which the run facts record after a pattern scrub, a backstop rather than a
  guarantee. The leased child also inherits the daemon's own
  environment, because the daemon sets neither an environment nor stdin for it
  ([`main.rs`](../native/splat-agent/src/main.rs)). Roadmap 5.2.
- **The console owns its substrate in code, not yet in use.** Until 2026-10-10, provisioning and
  `doctor` lived only in `splat-mcp`, and the console used whichever daemon answered on
  `127.0.0.1:50051`. They now live in [`MissionController.Host`](../src/MissionController.Host), the
  console's Kernel Lease page checks, mounts and unmounts through them, and where a managed
  configuration exists the console leases through the bridge's pipe instead, refusing rather than
  falling back when the bridge is down
  ([`ManagedBridgeClient.cs`](../src/MissionController.Host/ManagedBridgeClient.cs)). What remains is
  live: nobody has mounted from the console, and no managed bridge has run. The community installer
  already ships the console, the daemon and a SPLAT-owned Linux image together
  ([`splat-community.iss`](../packaging/splat-community.iss)). Roadmap 5.0.

## 5. Two kinds of action

**External.** One HTTPS request to one platform, made from inside a lease whose egress the kernel
pins to that platform: register a webhook, update a subscription, rotate a secret. It keeps
`RemediationAction`'s contract. It has a postcondition, which is a read-back that must agree (the
subscription is listed, the handshake passed), and a rollback that is measured the same way. An
action whose request succeeds while the read-back disagrees is `PostconditionFailed`.

**Workspace.** A change to a codebase. The agent works in a copy-on-write layer over a checkout, edits
anything, and runs the project's own tests there as the postcondition. The output is the diff,
signed into the run record. The real checkout is untouched until a person applies the diff. The agent
never writes to the host, so it never needs the host's privileges. That also avoids the elevation
problem the first-remediation handoff ran into (moved out of the repository on 2026-10-14), for this whole
category of work.

The one-button webhook job uses both kinds. A workspace change writes the receiver code, which is the
endpoint that answers each platform's verification handshake and checks its signatures. The person
applies it and it deploys. Then one external action per platform registers that endpoint, and each
postcondition confirms the platform verified it and lists the subscription.

## 6. Rules every action keeps

1. **A secret lives for one leased step, and the model only names it.** The model proposes *what* to
   send: the callback URL, the fields, and the name of the secret in the vault. The host hands the
   secret into the lease for that step, and it is deleted with the lease's scratch. It stays out of
   the model's context, the ledger and the run record, and DLP is a backstop for this, not the
   mechanism.
2. **One platform per step, pinned by the kernel.** The Meta step's lease reaches Meta's addresses
   and nothing else, and it holds only Meta's secret, so it has no X secret to send. This is the
   1:1:1 rule the catalogue already declares, applied to actions and enforced by the lease.
3. **Nothing is done without saying what done means.** No postcondition, no request: the refusal that
   `SandboxedRemediationEngine` already enforces.
4. **One approval per plan.** The person sees every external write and every diff before any of
   them runs, and approves once. Seven platforms do not mean seven prompts.
5. **One record per run.** Every request, with secrets redacted, every read-back and every diff goes
   into the same signed run record, so the job can be verified afterwards by someone who was not
   there.

## 7. Platforms — a hypothesis, not a finding

The table below has not been checked against current platform documentation. Roadmap 5.1 replaces
every cell with a link to the platform's own docs before any template for that platform is built.

| Platform | Create the developer app by API | Register a webhook by API | Verification | Payload signature |
| --- | --- | --- | --- | --- |
| GitHub | not needed for repository webhooks | likely | ping event | `X-Hub-Signature-256` |
| Stripe | not needed | likely | none | `Stripe-Signature` |
| Meta | unlikely; App Dashboard | likely, per app | `hub.challenge` echo | `X-Hub-Signature-256` |
| X | unlikely; developer portal | likely, paid tier | CRC: HMAC of a token | to verify |
| TikTok | unlikely; developer portal | to verify | to verify | to verify |
| YouTube | not needed for WebSub | likely | `hub.challenge` echo | optional |
| Slack | possibly, through app manifests | through the manifest | `url_verification` | `X-Slack-Signature` |

The pattern this predicts is the most important thing in this scope. **Creating the developer app is
probably a one-time manual step on most social platforms.** Everything after that, meaning registering,
verifying, rotating and proving the webhooks, is probably automatable. So the realistic one-button job
is: you create each app once and put its credentials in the vault once, and from then on one button
registers, verifies and proves every webhook at once, and can be pressed again to rotate or recover.

## 8. Order of work, and what is yours

**First, the substrate.** The console owns its guest (5.0), and the daemon gets a channel for a secret
and gives the leased child a cleared environment (5.2). Every acting template depends on both.

**Then GitHub.** It is free, fully programmatic, and you already have it. It proves the whole chain:
receiver code by workspace change, registration by external action, handshake as postcondition, and
the signed record. Then **Meta**, the first social platform. Its developer apps are free, and test
mode works with your own accounts. **X** needs a paid API tier for webhooks, so it waits on that
decision. **TikTok** waits on 5.1.

Yours, and only yours:

- Create each developer app in its portal, where the platform does not allow it by API.
- Put each app's credentials into the vault once, through Settings. Never on a command line.
- Pay for any paid tier, such as X, and go through App Review for production permissions where a
  platform requires it, such as Meta.
- Approve each plan before it runs.
- Run the root proof after the daemon learns to carry a secret. Agent routes to the root daemon are
  refused, so that proof is yours, as every root proof has been.
- Decide whether P5 goes ahead of P2 to P4 in the roadmap. It sits after them by position only. The
  argument for the current order is the OEM plan, and this scope is an argument for changing it.

## 9. What this does not do

- It does not create developer apps on platforms that do not allow it. The table predicts that is most
  of them.
- It does not make a guest root honest. A signed outcome proves the guest said it, not that it is
  true. That is the boundary [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)
  already states.
- It does not remove the human from the loop. One approval per plan is the design, and a version
  that acts on external accounts without one is out of scope.
