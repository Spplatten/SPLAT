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
operating system, not by the agent's cooperation or by our own front end.

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
qualification when it does not — in both directions. 347 automated tests currently pass.

---

## What is NOT proven — stated plainly

- **The last hop.** The C# bridge now round-trips a real tool to the daemon and returns its output,
  with four wire tests pinning the behaviour. What has *not* been demonstrated is a request
  originating from the MCP tools — `run_command` / `run_code` — travelling that path. Treat those
  two tools as uncontained until one does.
- **The audit ledger is unkeyed.** Editing a historical row breaks the hash chain verifiably. It does
  **not** stop a determined local administrator from deleting the tail and recomputing. This is
  integrity against accident and casual editing, not against an adversary with write access.
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
