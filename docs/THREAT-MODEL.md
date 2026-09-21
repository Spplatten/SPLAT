# What SPLAT defends against, tier by tier

Written 2026-09-21, because its absence had a cost. Network denial had been applied to every
catalog template it could be applied to, and nobody had asked what it was defending against or what
it took away. It takes away a great deal: measured, it changed the answer of 21 of the 33 templates
it was applied to. That is what a control costs when it is chosen by what is available rather than
by what is being defended.

The rule this page exists to enforce: **a control goes where it changes an outcome an adversary
could otherwise cause, and its cost to the work is measured before it ships.**

---

## The three tiers

SPLAT runs code on the operator's machine in three quite different ways, and they do not share a
threat model.

### Tier A — catalog sensor missions

One of the 49 templates runs one fixed tool. The executable path and the shape of the command line
are written in the template; a model never supplies either. Parameters are scalars bound by
`GovernedArgumentBinder`, which refuses spaces, shell metacharacters and anything that does not open
with an alphanumeric, typed per field (number, host, bare, quoted).

**The adversary:** a model that has been prompt-injected — by the tool's own output, by recalled
memory, or by the operator's own words.

**What it can do:** choose which template runs, and choose scalar values that survive the binder —
a hostname, a port, a count.

**What it cannot do:** change the command's shape, add an argument, or run a different binary. This
is the load-bearing control of the whole tier, and it is not a sandbox at all; it is the fact that
the command was written in advance.

| Control | What it defends against here | What it costs |
| --- | --- | --- |
| Fixed command + argument binder | The injected model turning a sensor into an arbitrary command | Nothing. Every shipped template's arguments already fit the policy |
| ACL jail (own directory, inheritance stripped) | A tool writing where the next mission or the operator would read it | Nothing measured |
| Job object caps: memory, CPU, 32 processes, kill-on-close | A runaway or fork-bombing tool | Nothing measured |
| Restricted token, Administrators deny-only, Medium integrity | A tool using the operator's admin rights | Three templates need rights it removes — see the open defects below. That is the cost, and it is the right side to fail on |
| DLP on the output path | Secrets in tool output reaching the model provider | A scan budget, and false positives are possible |
| Chained ledger | An operator or a process denying what was run | Nothing |
| **Network denial (AppContainer, no capabilities, Low integrity)** | A tool binary exfiltrating, or a model-chosen hostname used as a signal through `ping` or `nslookup` | **Measured: it changed the answer of 21 of 33 templates.** It is not a socket control; it is a capability sandbox that also removes RPC to system services and drops integrity |

**The decision, 2026-09-21:** network denial applies only to templates where it has been measured to
change nothing — twelve of them today, named in the catalog and held there by
`NetworkToolsUnderDenialTests`. The others keep the local plumbing their job needs.

That leaves a narrow channel open: an injected model picks a template whose scalar is a hostname and
uses `ping` or `nslookup` to signal a host it chose. Low bandwidth, no payload beyond the name
itself. Closing it properly needs a socket-layer filter — a WFP filter keyed on the workload's own
SID denies sockets without touching RPC or integrity. That is the roadmap's standing candidate and
this is the evidence that it is load-bearing rather than a refinement.

### Tier B — MCP tools an outside AI drives

`run_command` and `run_code` take a command from another AI entirely. Nothing about the command was
written in advance, so nothing in tier A's reasoning transfers: **every limit here has to be
enforced, not designed around.**

That is what the Linux lease is for. The daemon compiles the lease and a BPF-LSM hook vetoes
`execve`, `open` and `connect` in the kernel, for a workload running as `nobody` in its own mount
namespace. `CapabilityManifest.Lease` states, row by row, what is enforced by the kernel, what by
the daemon, what is refused outright and what is not policed — and a test fails if a row is not also
in the substrate's own `SUPPORTED_POLICY.md`.

`fs_read` and `fs_write` are a check inside SPLAT's own process against the workspace root. Real, and
the manifest says in words that it is a user-space boundary and not a kernel one, because a client
deciding what to trust must not read it as the lease.

### Tier C — the one template that dials out

`grants-opportunity-ingestion` reads public funding notices. Its destination is declared in the
template, written to the ledger, and compiled into the Linux lease. On Windows it is an audited
promise, not an enforced wall: an AppContainer chooses network or no network, never a destination.
The template is built so that the promise breaking is survivable — no credential, read-only, and it
files nothing.

---

## What SPLAT does not defend against

Stating these is the point of the page.

- **The operator.** Anyone who can run the app can run any template, and whoever holds the ledger key
  can rewrite the chain. The key is deliberately the operator's.
- **A malicious template.** A template is a command someone wrote; the binder constrains its
  parameters, not its author. The catalog is the trust boundary.
- **The model provider.** Scrubbed tool output leaves the machine. DLP reduces what is in it; it does
  not keep it home.
- **A tool binary that is already compromised.** Tier A runs Microsoft's own binaries with fixed
  arguments. If one of those is subverted, nothing here notices.
- **Windows destination pinning.** Until a WFP filter exists, "one approved destination" is enforced
  on Linux and audited on Windows.

---

## Open defects this page's measurements found

Both are pinned by tests so they can only shrink.

- **Eight templates produce no usable evidence even outside any container** (`CatalogProducesEvidenceTests`).
  Two call `wmic`, which Windows 11 has removed. One passes `klist` arguments it answers with its
  usage text. Three need rights the restricted token deliberately removes — the Security event log
  and `gpresult` want elevation — which is the privilege drop working, and means those templates ask
  for something the tier cannot give. One exits outside its own contract with good evidence in hand.
- **Twenty-one templates were degraded by network denial** (`NetworkToolsUnderDenialTests`). Fixed by
  the re-tiering above; the test now holds every denied template to answering the same inside the
  container as outside it.
