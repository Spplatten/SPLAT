<!-- PROSPECT-FACING. Every claim here must trace to committed evidence or a named source file.
     Deliberately excludes the latency figures and competitor comparison in
     SPLAT-Enterprise-Executive-Brief.md: no benchmark harness exists in this repo, so those
     numbers are unmeasured and a technical reader can call them. Do not reintroduce them
     without a committed benchmark. -->

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

**The documentation cannot drift away from the evidence.** An automated test fails the build if the
docs claim the substrate is pending while passing evidence exists, *and* fails if they drop the
qualification when it does not — in both directions. 343 automated tests currently pass.

---

## What is NOT proven — stated plainly

- **The last hop.** No request has yet travelled from the MCP tools through the bridge into the lease
  daemon. Until one does, treat the general-purpose `run_command` / `run_code` path as uncontained.
- **The audit ledger is unkeyed.** Editing a historical row breaks the hash chain verifiably. It does
  **not** stop a determined local administrator from deleting the tail and recomputing. This is
  integrity against accident and casual editing, not against an adversary with write access.
- **No latency benchmark exists yet.** Any performance number you have seen from us is an estimate,
  not a measurement.

The shipped Windows path — job-object clamps, restricted token, ACL-jailed workspace, secret scrubbing
before egress, and the chained audit ledger — is what runs the governed diagnostic and investigation
agents today.

---

## Why this is worth thirty minutes

If you are deploying agents that execute code on machines you care about, the question is not whether
your agent is well-behaved. It is what it can still reach on its worst day. We can answer that against
your actual deployment, and show you a kernel refusing the thing you assumed was already blocked.

**Contact:** Platten Industries · spplatten@gmail.com
