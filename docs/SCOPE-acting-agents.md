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
| One egress host per request | **Exists** | [`EgressFirewallHandler`](../src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs), a `DelegatingHandler` scoped per call with `BeginScope(fqdn)` |
| A credential store | **Exists** | [`DpapiCredentialVault`](../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs) behind `ICredentialVault` |
| An action contract with proof | **Exists, unused** | `RemediationAction` in [`Models.cs`](../src/MissionController.Core/Models.cs): fix, rollback, a validation command with expected output for each, risk level; [`SandboxedRemediationEngine`](../src/MissionController.Infrastructure.Windows/Remediation/SandboxedRemediationEngine.cs) refuses any step that declares no postcondition. No template declares one: `GovernedTemplateCatalog.Template(...)` passes `Array.Empty<RemediationAction>()` and takes no remediation argument |
| A model that chooses the next step | **Exists** | [`GovernedInvestigationLoop`](../src/MissionController.Core/GovernedInvestigationLoop.cs): five-step ceiling, no repeats, catalogue-only selection, proposed values screened and every drop written to the ledger |
| A signed record of what happened | **Exists** | Guest-signed lease outcomes (roadmap 2.5), the hash-chained ledger, the run-record bundle and its verifiers |

## 4. Two kinds of action

**External.** One HTTPS request to one platform: register a webhook, update a subscription, rotate a
secret. It is `RemediationAction` with a request where the executable was. It has a postcondition,
which is a read-back that must agree (the subscription is listed, the handshake passed), and a
rollback that is measured the same way. An action whose request succeeds while the read-back
disagrees is `PostconditionFailed`.

**Workspace.** A change to a codebase. The agent works in a copy-on-write layer over a checkout, edits
anything, and runs the project's own tests there as the postcondition. The output is the diff,
signed into the run record. The real checkout is untouched until a person applies the diff. The agent
never writes to the host, so it never needs the host's privileges. That also avoids the elevation
problem [`HANDOFF-first-remediation.md`](HANDOFF-first-remediation.md) ran into, for this whole
category of work.

The one-button webhook job uses both kinds. A workspace change writes the receiver code, which is the
endpoint that answers each platform's verification handshake and checks its signatures. The person
applies it and it deploys. Then one external action per platform registers that endpoint, and each
postcondition confirms the platform verified it and lists the subscription.

## 5. Rules every action keeps

1. **The model never sees a secret.** It proposes *what* to send: the callback URL, the fields. The
   host attaches the credential afterwards, from the vault, by name. Secrets stay out of the model's
   context, the ledger and the run record, and DLP is a backstop for this, not the mechanism.
2. **One platform per step, one host per step.** The Meta step can reach Meta's API and nothing else,
   so it cannot send X's secret anywhere. This is the 1:1:1 rule the catalogue already enforces,
   applied to actions instead of reads.
3. **Nothing is done without saying what done means.** No postcondition, no request: the refusal that
   `SandboxedRemediationEngine` already enforces.
4. **One approval per plan.** The person sees every external write and every diff before any of
   them runs, and approves once. Seven platforms do not mean seven prompts.
5. **One record per run.** Every request, with secrets redacted, every read-back and every diff goes
   into the same signed run record, so the job can be verified afterwards by someone who was not
   there.

## 6. Platforms — a hypothesis, not a finding

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

## 7. Order of work, and what is yours

**First, GitHub.** It is free, fully programmatic, and you already have it. It proves the whole chain:
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
- Decide whether P5 goes ahead of P2 to P4 in the roadmap. It sits after them by position only. The
  argument for the current order is the OEM plan, and this scope is an argument for changing it.

## 8. What this does not do

- It does not create developer apps on platforms that do not allow it. The table predicts that is most
  of them.
- It does not make a guest root honest. A signed outcome proves the guest said it, not that it is
  true. That is the boundary [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)
  already states.
- It does not remove the human from the loop. One approval per plan is the design, and a version
  that acts on external accounts without one is out of scope.
