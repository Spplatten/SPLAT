<!-- PROSPECT-FACING. Every claim here must trace to committed evidence or a named source file.
     The latency figure below is measured by src/splat-bench and recorded under its evidence/ dir;
     re-measure rather than re-estimate. Competitor numbers stay out: this project has never run
     E2B, Modal or Docker, and checkable claims about named competitors we have not benchmarked are
     the fastest way to lose a technical reader. -->

# Kernel-Enforced Containment for AI Agents
### Platten Industries — SPLAT (Sandboxed Process Lease & Agent Telemetry)

**The problem.** Agents that run commands need real access to be useful. Prompt injection means an
agent's judgement can be hijacked by the content it reads. Every safety approach that depends on the
agent behaving fails at exactly that moment, because behaviour is what got compromised.

**The approach.** Stop trying to keep the agent well-behaved. Contain it. Each job gets a *lease*:
one model, one pre-approved tool, one allowed destination — declared in advance and enforced by the
operating system, not by the agent's cooperation. On the Linux lease the kernel enforces the
destination itself. On Windows the operating system enforces whether a tool reaches the network at
all (33 of 49 catalog tools get none), not where it goes.

---

## What makes SPLAT different (and what doesn't)

Three concrete properties separate SPLAT from anything else in the agent security space:

1. **The unit of containment is a task, not a box.** Cloud sandboxes (E2B, Modal, Daytona, Fly) hand an
   agent an entire microVM; isolation is real, but the unit of containment is "the machine." Falco and
   Tetragon do eBPF enforcement, but their unit is a persistent cluster workload and their operator is a
   security team writing deployment manifests. SPLAT's unit is **one mission**: *this model, this binary,
   this destination, for this many seconds*. That is a capability grant, not a perimeter. Enforcing at
   that granularity requires a policy compiler, a dynamic lease lifecycle, and an in-kernel hook—most teams
   stop at the container.
2. **It runs on the box the agent is already on, on an unmodified kernel.** This is the sharpest commercial
   wedge. Every cloud sandbox requires shipping workloads and private data to someone else's infrastructure—a
   non-starter for the exact buyers who most need containment: health systems, defense, finance, and anyone
   with data that cannot leave the host. SPLAT contains an agent locally on stock WSL2 (`6.18.33.2`), native
   BTF, with no custom kernel and no kernel fork. That is a deployment story cloud sandboxes structurally
   cannot tell.
3. **The evidence discipline is itself the differentiator.** In an early security market where 90% of claims
   are aspirational, SPLAT makes every claim load-bearing:
   - Automated tests (`DocumentationDriftTests`) fail the build in both directions if the documentation
     undersells proven capability *or* oversells unproven capability.
   - Proof records are cryptographically pinned to the SHA-256 digest of the exact BPF source that generated
     them; a proof cannot outlive its code.
   - When [`src/splat-bench`](../src/splat-bench) benchmarked real containment overhead and retired the
     inherited `<1ms` marketing figure by recording **4.12 ms p50 / 9.88 ms p95**, the project published the
     worse measured numbers rather than preserving marketing optics.

**What is not the moat:** The Windows half (Job Objects, restricted tokens with `USE_FOR_DENY_ONLY` on the
admin SID, Medium integrity drops, ACL jails) is essentially the Chromium sandbox architecture, well-trodden
since 2008. It is competently executed and asserted against `whoami` inside the sandbox, but it is standard
defense-in-depth, not the defensible moat. The moat is the Linux capability lease enforced by BPF-LSM on an
unmodified kernel.

**What SPLAT is (and what it is not):** SPLAT is an execution containment substrate, not a generic RPA bot builder or web scraper. It does not spawn browser-puppeteering agents to click through third-party SaaS consoles (e.g. TikTok or Meta advertising setups) or scrape private inboxes. Granting an AI unconstrained web navigation and high-privilege credentials creates the exact blast radius SPLAT is designed to eliminate. Instead, SPLAT executes rigidly leased 1:1:1 diagnostic and audit tools locally, or serves as the host-level containment boundary (`splat-mcp`) for external agent runtimes.

---

## What is proven, with receipts

A machine-checked canary run on a **stock, unmodified WSL2 kernel** (`6.18.33.2-microsoft-standard-WSL2`
— no custom kernel, no fork) recorded a BPF-LSM lease refusing three operations at the kernel boundary
while permitting the one the job was licensed to do:

| Hook | Operation attempted | Result |
| :--- | :--- | :--- |
| `file_open` | `cat` reading `/etc/shadow` | `-EPERM` from the kernel |
| `socket_connect` | `curl` to an unleased address | `-EPERM` from the kernel |
| `bprm_check_security` | `sh` executing an unleased binary | `-EPERM` from the kernel |
| — | the leased destination | **permitted** |

The harness computes its own verdict and exits non-zero on a bad run, so this is not a screenshot or a
hand-written log. The evidence file records the kernel release, each violation with pid and inode, and
the **SHA-256 of the BPF source that produced them** — so the proof cannot outlive the code it tested.

**Root privilege did not defeat it.** In a separate run the lease daemon spawned a tool as **uid 0**;
the kernel still refused it `/etc/shadow`, and still refused an allow-listed `/bin/sh` its exec of an
unleased binary.

**And it holds end-to-end through the daemon's own protocol.** A second recorded run drove the daemon
over its JSON protocol and returned PASS on every check: the permitted tool ran, the protected inode
was refused and never leaked, an unleased second exec was blocked, the leased destination was allowed
while an unleased one was refused, egress was denied with networking off, and every request completed.

**The documentation cannot drift away from the evidence.** An automated test fails the build if the
docs claim the substrate is pending while passing evidence exists, *and* fails if they drop the
qualification when it does not — in both directions. 578 automated tests passed on 2026-09-18.

---

## What is NOT proven — stated plainly

- **~~The last hop.~~** Recorded on 2026-09-11: a `run_command` from an MCP client travelled the
  bridge into the daemon and the kernel refused an undeclared exec and an out-of-lease connect,
  with the permitted command and endpoint as controls. What is still *not* demonstrated is a
  **governed mission** on that path — the console never routes one through the daemon.
- **The audit ledger is unkeyed by default.** Editing a historical row breaks the hash chain
  verifiably. Unkeyed, it does **not** stop anyone with write access from recomputing the chain.
  Since 2026-09-18 the operator can key it with a file they keep. Keyed, nobody without that file can
  rewrite it unnoticed; deleting the newest entries is caught only by a saved audit anchor.
- **Latency is now measured, and it is not sub-millisecond.** On Windows `10.0.26200`, over 50
  alternating iterations, the governed path added **4.12 ms at p50 and 9.88 ms at p95** over the same
  tool run bare. About 2.4 ms of that is the locks; the rest is process creation both paths pay. Any
  older sub-millisecond figure you may have seen from us was an estimate, and it was wrong.

The shipped Windows path — job-object clamps, restricted token, ACL-jailed workspace, secret scrubbing
before egress, and the chained audit ledger — is what runs the governed diagnostic and investigation
agents today.

---

## Why this is worth thirty minutes

If you are deploying agents that execute code on machines you care about, the question is not whether
your agent is well-behaved. It is what it can still reach on its worst day. We can answer that against
your actual deployment, and show you a kernel refusing the thing you assumed was already blocked.

**Contact:** Platten Industries · spplatten@gmail.com
