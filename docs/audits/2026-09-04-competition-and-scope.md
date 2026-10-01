# SPLAT competition and scope audit

> **Broken links are deliberate, 2026-09-09.** The contradiction table below cites
> `PLAN-agent-trust-layer.md` and `PLAN-versatility-paths.md`, both removed on 2026-09-09 once the
> work they planned had shipped (the MCP facade, the synthesiser, the daemon, the transport
> decision). Rewriting the citations would falsify the record of what actually conflicted at the
> time, so they stand. `git log --diff-filter=D` finds the files; the decisions they forced are in
> [the OEM subtraction plan](2026-09-09-oem-subtraction-plan.md).

Research date: 2026-09-04 America/New_York / 2026-09-05 UTC. Repository base `461001b` plus the inspected working tree. Read with the [technical findings](2026-09-04-clinical-audit.md) and [delivery plan](2026-09-04-roadmap.md).

**Recommendation: position SPLAT as a constrained execution and evidence layer beneath existing automation platforms. Do not make replacing n8n the next release goal.** The potential differentiator is approved native actions on managed Windows endpoints, with verifiable policy enforcement and execution outcomes. This is a product hypothesis; the current security findings prevent presenting it as an established moat.

This comparison uses current official documentation, not hands-on competitor benchmarks. A documented enterprise feature may require a particular edition/configuration. Absence from the sampled sources is not proof a competitor lacks a capability. No competitor was installed, purchased or security-tested during this audit.

## Competitive landscape

| Platform | Category and deployment | Documented capability relevant to SPLAT | Competitive implication |
| --- | --- | --- | --- |
| **n8n** | Visual automation and AI orchestration; self-hosted deployment supported | Separate external Code-node task runners; hardening guidance for non-root, read-only roots and AppArmor; human approval for AI tools; external MCP tool connections | Broad workflow/connector surface already exists. SPLAT could provide restricted endpoint execution as a tool. Describing n8n as only prompt filtering is inaccurate. [Task runners](https://docs.n8n.io/deploy/host-n8n/configure-n8n/set-up-task-runners), [hardening](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security/harden-task-runners), [human review](https://docs.n8n.io/build/integrate-ai/ai-examples/human-in-the-loop-for-tools), [MCP client](https://docs.n8n.io/integrations/builtin/cluster-nodes/sub-nodes/n8n-nodes-langchain.toolmcp). |
| **Windmill** | Script, flow and application platform with self-hosted workers | Optional NSJAIL filesystem/network/resource isolation, worker separation and AI sandbox execution | Closest workflow-plus-execution comparison in this sample. Configuration matters; compare actual enabled isolation and Windows deployment effort. [Security](https://www.windmill.dev/docs/misc/security), [AI sandboxes](https://www.windmill.dev/docs/core_concepts/ai_sandbox), [workers](https://www.windmill.dev/docs/core_concepts/worker_groups). |
| **Activepieces** | Flow automation; self-hosted deployment | V8 code isolation, Linux namespace isolation, combined mode and an unsandboxed mode; separate network security controls | Real isolation options with different runtime/privilege constraints. SPLAT must distinguish native-tool capabilities and enforceable policy, not claim competitors have no containment. [Execution modes](https://www.activepieces.com/docs/install/architecture/sandboxing), [network security](https://www.activepieces.com/docs/install/architecture/network-security). |
| **LangGraph** | Stateful agent orchestration library/runtime | Checkpoints, persistence, durable execution and human interrupts | Natural integration target. These workflow guarantees are separate from kernel containment of arbitrary native tools. Rebuilding its orchestration primitives requires a specific unmet need. [Overview](https://docs.langchain.com/oss/python/langgraph/overview), [persistence](https://docs.langchain.com/oss/python/langgraph/persistence). |
| **Temporal** | Durable application/workflow execution; managed or self-hosted service | Event-history-based execution recovery with application code running on workers | Reliability benchmark and possible caller, not an arbitrary-code sandbox. SPLAT activities would need explicit idempotency, cancellation and compensation semantics. [Execution model](https://docs.temporal.io/temporal). |
| **E2B** | Agent sandbox execution platform | Firecracker microVM execution; enterprise BYOC/on-prem options and self-hosting; SDK timeout/network controls | Direct execution competitor. Customer-owned deployment is already available; local deployment alone is not unique. [Platform](https://e2b.dev/), [enterprise deployment](https://e2b.dev/enterprise), [SDK](https://e2b.dev/docs/sdk-reference/python-sdk/v2.9.1/sandbox_async). |
| **Daytona** | Agent sandbox lifecycle and execution infrastructure | CIDR/domain egress restrictions, block-all network mode, runtime network-policy updates, proxy-injected secrets and customer-owned runners in custom regions | Current competitors offer finer controls than “an unrestricted box.” Secret brokering and lifecycle behavior deserve direct comparison. Customer-owned runners alone do not establish a fully offline control plane. [Network policy](https://www.daytona.io/docs/en/network-limits/), [secrets](https://www.daytona.io/docs/en/secrets/), [regions](https://www.daytona.io/docs/en/regions/). |
| **Tetragon** | Linux eBPF runtime observation and enforcement | In-kernel return override/signals, blocking policies and standalone operation outside Kubernetes | A real enforcement alternative or component. Mission issuance, isolation between leases, usability and verifiable outcomes must add value beyond these existing primitives. [Policy actions](https://tetragon.io/docs/concepts/tracing-policy/selectors/), [enforcement](https://tetragon.io/docs/getting-started/enforcement/), [standalone FAQ](https://tetragon.io/docs/installation/faq/). |

These are three different comparison groups: workflow products (n8n/Windmill/Activepieces), orchestration infrastructure (LangGraph/Temporal), and execution/enforcement products (E2B/Daytona/Tetragon). SPLAT currently spans all three without completing the contract between them.

## n8n comparison by user task

| User task | SPLAT evidence today | Decision |
| --- | --- | --- |
| Connect business applications and trigger an automation | A keyword synthesizer and trigger classes exist; the visible UI does not register or run those graphs; HTTP/OAuth nodes are incomplete | Use an established workflow platform for the connector/control surface. Do not advertise connector breadth from template names. |
| Run an approved local Windows diagnostic | Native launcher, restricted token, Job Objects and catalog are implemented; 33/49 templates select AppContainer under the present predicate | This is the clearest initial product surface, subject to the technical audit's policy and result fixes. |
| Execute untrusted generated code | Linux hooks have historical canary proof; end-to-end authorization, expiry, map isolation, privilege and argument handling have release blockers | Finish one narrow supported path before claiming stronger safety than a hardened competitor deployment. |
| Resume after interruption and avoid duplicate effects | In-memory workflow registry and timers; no demonstrated durable workflow recovery/idempotency | Delegate durable orchestration; define action idempotency on the SPLAT adapter. |
| Require human approval for a sensitive action | Some interactive remediation flows exist; no uniform immutable approval-to-execution policy contract | Bind approval to exact action/arguments/policy and enforce it at the execution boundary. n8n already documents AI-tool human review. |
| Produce defensible execution evidence | Ledger/evidence infrastructure exists; payload verification and HMAC downgrade defects remain | Independently verifiable evidence could differentiate after the defects and key lifecycle are resolved. |
| Operate with customer-controlled data | Local state and Windows execution are useful; live model analysis still uses provider endpoints | State exactly which data remains local and which is sent to model/SIEM/MCP destinations. Competitors also offer self-hosting or customer-owned deployment. |

`src/splat-mcp/Program.cs:135-140` exposes standard input/output. The documented n8n MCP Client Tool uses a remote endpoint, so an MCP implementation alone does not establish plug-and-play n8n integration. Build a reviewed authenticated transport adapter or custom node. Bind each invocation to a user/service principal, a workspace, an approved policy, an idempotency key and an auditable outcome. Do not expose the privileged guest daemon directly to an orchestrator.

## Positioning corrections

The following README claims should be retired or narrowed after this audit:

- **“Every mainstream approach” runs at the agent's privilege:** contradicted by documented external task runners, NSJAIL, namespace/V8 isolation, microVMs and kernel enforcement.
- **“Every cloud sandbox” requires third-party infrastructure:** contradicted by E2B BYOC/on-prem/self-hosting and other customer-owned deployment options.
- **Task-level containment is unique:** unsupported by a repeatable comparison; per-script and per-sandbox controls exist. The stronger test is whether SPLAT correctly binds a human-approved capability to one execution with no cross-mission widening.
- **“90%” of claims are aspirational:** no dataset or measurement is supplied. Remove the number.
- **“Zero leak,” general guaranteed rollback and enterprise readiness:** the technical audit finds concrete contrary paths. Replace absolutes with supported-capability and proof tables.

A defensible proposed message is: **“SPLAT lets automation platforms request approved actions on managed Windows endpoints, with explicit permissions and inspectable execution evidence.”** Add stronger isolation claims only for a version/platform/policy combination with passing adversarial evidence. This wording is a suggested direction, not a declaration that the current implementation meets it.

## Scope contradictions and decisions

| Existing contract | Current implementation or conflicting plan | Recommended decision |
| --- | --- | --- |
| `scope.md:3-14`: Windows IT/SysOps appliance | `docs/PLAN-agent-trust-layer.md:1-7`: general substrate; `IDEAS.md:42-72`: technicians, fleet, MSP and sovereign buyers | Choose managed Windows endpoint automation teams as the initial buyer hypothesis. Keep the local diagnostic console as a reference client. |
| `scope.md:27-28`: at most six sequential stages, no dynamic loops | `AgentBrainEngine.cs:178-185`: bounded reasoning loop; `GovernedCrewEngine.cs:269-284`: manager dispatch loop; default crew iteration ceiling is 10 | Replace the obsolete prohibition with explicit cumulative tool/time/spend/mutation budgets, or remove the broader loops from that product tier. Bounded is not the same as absent. |
| `scope.md:107-110`: no installed background daemon | Privileged Rust daemon and WSL/kernel provisioning | Separate an administrator-provisioned substrate from non-elevated operator use; document each support tier and prerequisite. |
| `scope.md:112-115,132`: complete zero-leak and outside-jail denial | Partial Windows network coverage, ordinary user filesystem rights and limited Linux hooks | Define permissions by runtime and fail closed when the requested boundary is unavailable. |
| `scope.md:134`: every out-of-band audit edit/deletion detected | Unchecked displayed payload, unkeyed compatibility fallback and no independently retained tail checkpoint | Replace “immutable” with the exact integrity property after repair, including who holds the verification key/checkpoint. |
| `scope.md:118,135`: signed non-admin enterprise deployment | Self-signed packaging fallback, LocalMachine trust import, Program Files ZIP target and unverified clean-machine install | Specify IT provisioning versus ordinary-user installation/execution. Do not equate a build with a deployment proof. |
| `PLAN-agent-trust-layer.md:29-37`: vsock before later phases | `PLAN-versatility-paths.md:143-149` ships MCP over JSON/TCP first; substrate-completion plan allows either | Choose one transport/version and its authentication threat model. Use measured requirements to decide whether vsock is necessary. |
| Strict 1:1:1 templates | `PLAN-versatility-paths.md:114-120` also proposes a broader workspace envelope | Two named modes with separate policies and evidence; a broad developer lease cannot inherit the strict template claim. |
| General transactional execution | `PLAN-versatility-paths.md:123-135` mainly describes file branching/commit | Define workspace-file transactionality. Remote HTTP actions and external database changes require separate idempotency/compensation, not a filesystem rollback promise. |
| Public/open-core substrate plan | README proprietary notice; Python package declares MIT; no single clear component distribution contract | Reconcile component licenses, contribution rules, supported binaries and commercial boundary before ecosystem distribution. This is a scope observation, not a legal conclusion. |

The roadmap should have one authoritative status record with capability, owner, prerequisites, supported platform, current evidence, next gate and superseded-plan links. A future item must not coexist as “shipped” in a pitch and “roadmap” in an engineering document.

## Economics correction

The idea ledger moved to the untracked `private/IDEAS.md` on 2026-10-01, so the line numbers below
no longer resolve in this tree. The figures stay: a finding whose subject has been taken away is not
a finding, and the correction is the reason this audit is kept.

`IDEAS.md:105` described 3,000 endpoints, 600 tickets resolved monthly and $25 saved per ticket. Those assumptions give **600 × $25 × 12 = $180,000 annual gross benefit**.

At the document's own `IDEAS.md:50` price of $5-$12 per endpoint/month, annual license cost is **$180,000-$432,000**. Net savings before model, deployment, infrastructure and support cost are therefore **$0 to -$252,000**, not over $150,000. Break-even is **600-1,440 avoided tickets per month**, before those extra costs.

These are arithmetic consequences of the repository's assumptions, not market prices or measured savings. Validate avoided work, not merely completed model runs. Record technician minutes, repeat incidents, failed automations, support burden and all-in cost against the existing workflow. Do not set final pricing until pilots establish value and willingness to pay.

## Build, integrate, defer

**Build now:** one authorized execution API, explicit supported policies, fail-closed lifecycle, per-mission isolation, complete result states, credential brokering, verifiable receipts and a maintainable Windows installation path.

**Integrate:** one n8n connection and one local MCP client; use established orchestration for connector management, schedules, durable state and human workflow where appropriate. Consider LangGraph/Temporal adapters only for a concrete customer flow.

**Defer:** a generic visual editor, broad connector marketplace, recursive swarms, speculative N-way generation, MSP multitenancy, fleet dashboards, billing gateway and a sovereign edition. Each expands the trusted surface before the basic execution contract is proven.

**Validate differentiation:** run the same approved diagnostic/coding job against SPLAT and a hardened Windmill deployment, and compare the sandbox branch with E2B/Daytona in an eligible deployment mode. Measure permission granularity, data location, setup privileges, exact failure behavior, cancellation, escape probes, evidence portability, startup overhead and all-in operational effort. Publish configuration and unsupported cases alongside results; do not compare default SPLAT claims against deliberately unhardened competitors.

After two integration prototypes and five buyer interviews, narrow back to governed Windows diagnostics if customers cannot identify a missing capability versus those alternatives or cannot deploy the required substrate. More features do not resolve an invalid buyer or installation assumption.
