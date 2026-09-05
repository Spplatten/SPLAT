<!-- DERIVED FILE. The source of truth is docs/SPLAT-Field-Guide.html; edit that first, then mirror
     the wording here and republish the artifact it names. See that file's header for why. -->

# The SPLAT Field Guide

*A plain-English guide to SPLAT — no jargon required. Engineers wanted: the [README](../README.md) has the full technical story.*

SPLAT is a Windows app that puts AI helpers to work on your computer — inside **locked rooms the operating system enforces**, so even a misbehaving AI can't touch what you didn't hand it.

---

## Part 1 — Why "just trust the AI" doesn't work

AI assistants have become good enough to actually *do* things: run diagnostics, dig through logs, fix settings, build and publish things. That's genuinely useful — and genuinely dangerous, because to do work on your computer, an AI needs the same thing any worker needs: access.

Think of it like hiring a contractor to fix your kitchen sink. Today's common approach to AI safety amounts to a sticky note on the bedroom door that says *"please don't go in here."* The contractor is polite, so it usually works. But "usually" is carrying a lot of weight — because AI agents can be tricked.

The trick has a name: **prompt injection**. If your AI helper reads a web page, an email, or a file that contains hidden instructions — like someone slipping your contractor a forged note that says *"the homeowner said to also grab the jewelry"* — the AI can be talked into doing things you never asked for. Every safety approach that relies on the AI's good behavior fails at exactly this moment, because the AI's behavior is the thing that got hijacked.

> **SPLAT's answer: stop trying to keep the AI polite. Lock the doors.** It doesn't claim to know when an AI has gone wrong — it makes sure that whatever the AI has become, it physically cannot act outside the small, fenced job it was given.

Engineers call this *blast-radius containment*. You don't prevent every spark; you make sure a spark can't burn down more than one small, fireproof room. And crucially, the locks aren't run by the AI or even by SPLAT's own front end — they're enforced by Windows itself, at a level the AI can't reach, let alone argue with.

## Part 2 — The big idea: agents don't get trust, they get a lease

The core concept in SPLAT is the **lease**. When an AI agent gets a job, it doesn't receive the keys to your computer — it receives something more like a visitor badge at a secure facility: valid for one task, for a limited time, opening exactly one workshop door, with a hard cap on how much power and material it can use. When the task ends, the badge dies.

Every job in SPLAT follows a strict rule the project calls **1:1:1** — one task template gets exactly *one* AI model, *one* pre-approved tool it may run, and *one* internet address it may talk to. Not "a browser." Not "the internet." One tool, one destination, spelled out in advance. Anything else is refused automatically — not by policy, but by plumbing.

One leased job, from the outside in:

```
┌─ Ring 5 · THE LEDGER — every action written to a tamper-evident logbook ──┐
│ ┌─ Ring 4 · ONE PHONE LINE — outbound traffic to exactly one address ──┐  │
│ │ ┌─ Ring 3 · THE CENSOR — passwords & secrets scrubbed before exit ─┐ │  │
│ │ │ ┌─ Ring 2 · THE VISITOR BADGE — admin rights stripped ─────────┐ │ │  │
│ │ │ │ ┌─ Ring 1 · THE ROOM — fenced folder, RAM & CPU caps ──────┐ │ │ │  │
│ │ │ │ │            THE AGENT'S TOOL                              │ │ │ │  │
│ │ │ │ │  (started frozen — locks attach before it ever runs)    │ │ │ │  │
│ │ │ │ └──────────────────────────────────────────────────────────┘ │ │ │  │
│ │ │ └──────────────────────────────────────────────────────────────┘ │ │  │
│ │ └──────────────────────────────────────────────────────────────────┘ │  │
│ └──────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

The rings aren't SPLAT asking nicely — rings 1, 2 and 5 are enforced by the Windows kernel's own object system, and the tool is spawned *suspended* (frozen) so every ring is locked in place before it ever wakes up.

## Part 3 — Meet your agent squad

SPLAT ships with a squad of specialist agents — each one a bundle of a reasoning AI, one dedicated tool, and one approved destination, pre-configured for a specific kind of problem. The four you'll meet first:

| Agent | Specialty | What it does for you |
| :--- | :--- | :--- |
| 🌐 **Atlas-Net** | Network | Chases down Wi-Fi drops, slow internet, DNS delays, and strange programs listening on your network. |
| 🛡️ **Sentinel-SecOps** | Security | Hunts brute-force login attacks and surges of failed sign-ins that suggest someone's trying to get in. |
| 💾 **Titan-SysOps** | Storage | Watches disk space, finds bloated caches and clutter, and points at what's safe to clean up. |
| 🔒 **Aegis-Endpoint** | Compliance | Checks that Microsoft Defender is on, virus signatures are fresh, and secure connections are configured right. |

Behind them sits a catalog of **40+ specialists** covering networking, identity, endpoint security, system operations, and compliance — plus a newer *Autonomous Operations* wing with agents that build and deploy websites, draft multi-platform marketing campaigns, and vet grant eligibility before drafting the application paperwork — all under the same leash as everyone else. For bigger jobs, **Project Studio** chains up to six agents in a fixed order, and even the notes they pass to each other are filtered for secrets first. No free-for-all swarms, no infinite loops — by design.

### Wait — is SPLAT an agent builder, or a containment zone?

If you came here looking for an AI bot that opens a browser, logs into TikTok Ads Manager to configure OAuth callbacks, or connects to your personal email to scrape your inbox, you will quickly notice **SPLAT does not do that** — and that is entirely by design.

Those tasks belong to **Robotic Process Automation (RPA)** — unconstrained bots that navigate arbitrary websites, handle high-privilege credentials, and trigger irreversible cloud actions. In SPLAT's worldview, handing an AI free-roaming browser access and private credentials is an unacceptable security hazard: the moment that bot encounters prompt injection (in an email or a web page), an attacker can hijack it to steal tokens or exfiltrate data.

> **SPLAT is an execution containment substrate and governance zone.** It does not send bots wandering across the web; it locks down execution on your machine.

- **How SPLAT runs native tasks:** When a specialist runs a task (such as inspecting local event logs, diagnosing network drops, or auditing OAuth configurations), it runs a single pre-vetted tool inside an OS-enforced sandbox. Privileges are stripped, filesystem access is jailed, DLP scrubs secrets, and network egress is locked to one pre-declared destination. It audits, diagnoses, and drafts — it never roams the web unchecked.
- **Locked rooms for external agents:** If you use external general agents (like Claude Code, Cursor, or LangGraph) that need to run commands or manipulate files, they plug into SPLAT via `splat-mcp`. The external agent provides the reasoning; SPLAT provides the bouncer, ensuring out-of-bounds actions die before touching your system.

## Part 4 — What actually happens when you press the button

Say you open SPLAT and type: *"My internet keeps cutting out during video calls."* Here's the whole journey, in order:

1. **The Brain reads your goal.** SPLAT's reasoning layer — the Agent Brain — takes your plain-English sentence and breaks it into concrete, testable questions: is it Wi-Fi? DNS? Something hogging the connection?
2. **It checks its memory.** A local memory index (stored on your machine, not in the cloud) recalls similar past incidents — "this looks like the DNS problem from March" — to aim the investigation.
3. **It forms hypotheses and picks specialists.** Each suspicion becomes a hypothesis assigned to a matching specialist template — likely Atlas-Net here. Each hypothesis will be confirmed or refuted with real evidence, never vibes.
4. **The tool starts frozen.** The specialist's one allowed tool is launched *suspended* — created but not yet running — while the sandbox clamps on: memory and CPU caps, admin rights stripped, folder jail sealed. Only then is it thawed.
5. **Evidence is gathered inside the rings.** The tool runs its diagnostic and produces raw output. It can't wander the filesystem, can't gulp your RAM, and can't call anywhere except its one approved address.
6. **The censor scrubs the output.** Before one byte leaves your machine, a data-loss-prevention filter masks passwords, keys, tokens, email addresses, card and social-security patterns — in memory, before transmission.
7. **The AI reasons over clean evidence.** The scrubbed evidence travels down the single approved line to the reasoning model (Claude or Gemini — whichever key you connected), which interprets it and streams its thinking back live.
8. **You get a verdict in plain English.** A clear status — healthy, warning, or critical — with findings that cite the actual evidence, plus suggested one-click fixes. Risky fixes come with a rollback: an undo button, not just an apology.
9. **Everything lands in the ledger.** Every step — every command, argument, and result — is sealed into a cryptographic logbook. More on why that matters below.

## Part 5 — A map of the app, screen by screen

| Screen | What you use it for |
| :--- | :--- |
| **Quick Diagnostician** | The home screen. Big friendly tiles for one-click checkups, plus a box where you type any problem in your own words and let the Brain run with it. |
| **Welcome** | The three-step setup wizard: meet the squad, paste one AI key, launch. Takes about two minutes. |
| **Live Mission Monitor** | Watch missions run in real time — the agent's reasoning streams in as it works. |
| **Template Catalog** | Browse all 40+ specialists, see exactly what tool and destination each one is allowed, and launch them directly. |
| **Project Studio** | Chain up to six agents into a staged project — investigate, then verify, then summarize — with filtered hand-offs between stages. |
| **Security Audit** | Read the tamper-evident ledger: every action ever taken, verifiable, in one place. |
| **Memory** | Search past incidents by meaning, not keywords — "that time the printer broke" finds the right mission. |
| **Jail Inspector** | Look inside the sandboxes themselves: see the fenced folders and locks each mission ran under. |
| **Settings** | Manage your AI keys (encrypted by Windows), providers, and app preferences. |

## Part 6 — A logbook nobody can quietly edit

Every action in SPLAT — every command an agent ran, every argument it used, every fix it applied — is written to an audit ledger. But it's not an ordinary log file, because ordinary log files can be edited after the fact.

SPLAT's ledger works like a logbook where every page's ink is chemically bonded to the page before it. Each entry includes a cryptographic fingerprint of the previous entry, forming a chain. Change any historical record — even one character — and every fingerprint after it stops matching. The tampering doesn't just fail; it *announces itself*, mathematically, to anyone who checks.

That's the difference between "we log everything" and "we can **prove** nobody rewrote history." If you ever need to answer *what exactly did the AI do to my machine?* — the answer is in the ledger, and the ledger can't lie to you.

## Part 7 — Straight talk: what's real today, and what isn't yet

SPLAT's documentation makes a point of never blurring the line between built and planned. This guide keeps that promise.

- ✅ **Working today** — The Windows containment system: frozen starts, resource clamps, stripped privileges, folder jails. The governance layer: the 1:1:1 rule, the secret-scrubbing censor, the one-line-out firewall, the tamper-evident ledger, local memory. The full app, the 40+ agent catalog, and a connector (`splat-mcp`) that lets other AI tools — like Claude Code, or a Python agent built with LangGraph — borrow SPLAT's locked rooms. Backed by 350 automated tests, all passing.
- 🔶 **Being built** — The Linux-side deep containment: a guard that lives inside the Linux kernel itself (BPF-LSM) and vetoes forbidden actions before they happen. **The proof run is now on record.** On a stock Microsoft kernel, the guard let through the one thing the job was allowed to do and refused the other three outright: reading the password file, calling an unapproved address, and running an unapproved program. The refusals came from the kernel, not from SPLAT asking nicely. The service that routes work to that guard now runs too: a tool it started with full root privileges was still refused the password file, by the kernel rather than by SPLAT's say-so. What is *not* yet true is that the app's own missions travel that road — the Windows side has not been connected to it yet, so today it is proven, and not yet plumbed in.
- ⬜ **Planned** — Faster host-to-sandbox plumbing (VSOCK), fully automatic setup of the Linux sandbox, and deeper multi-step autonomy — which agents only earn in places where kernel-level enforcement is switched on.

One consequence of that gap is worth stating plainly, because it's new. The grant-discovery agent is the first specialist whose tool reaches the internet rather than only reading your own machine. Its one approved destination is declared in the template, written into the ledger, and compiled into the Linux kernel guard described above — but on Windows today, the locks that clamp memory, strip privileges and fence folders do **not** filter network sockets. So on Windows that destination is an audited promise rather than an enforced wall. That agent is therefore built to be harmless if the promise were ever broken: it presents no password or key, it only reads public funding notices, and it files nothing. Every grant agent stops at a draft for you to review — none of them can submit an application.

## Part 8 — Your first five minutes

SPLAT runs on Windows 11. On first launch, the Welcome wizard walks you through three steps: meet the agent squad, connect one AI key, go.

The one thing you need is an API key from Anthropic (starts with `sk-ant-`) or Google Gemini (starts with `AIza`) — that's the reasoning brain your agents will think with. Paste it once; SPLAT verifies it live, figures out which provider it belongs to, and locks it in Windows' own encrypted vault (DPAPI). It never sits on disk in readable form.

Then head to the Quick Diagnostician: tap a tile for a one-click checkup, or type what's bothering you — *"my laptop fan won't stop"*, *"is someone trying to log into my PC?"* — and watch the squad go to work. Every finding comes back in plain English, every suggested fix has a clearly labeled risk level, and anything risky ships with an undo.

And if you're the type who wants to see the machinery: the Live Mission Monitor shows the reasoning as it streams, the Jail Inspector shows the locked rooms, and the Security Audit screen shows the receipts. Nothing in SPLAT is a black box — that's rather the point.

## Part 9 — Plugging other AIs into the same cage

SPLAT's locked rooms aren't just for SPLAT's own agents. Any AI framework that speaks MCP — Claude Code, Microsoft Copilot, or a Python agent built with LangGraph — can send its work through the `splat-mcp` connector. The outside AI keeps its own brain and its own plan; SPLAT stays the bouncer. If a manipulated agent asks for something outside its lease, it isn't SPLAT's *opinion* that says no — it's the same containment every native agent lives under.

Two receipts make this partnership auditable rather than just safe:

- **The case number (trace id).** An outside framework can hand SPLAT its own trace id with any request. SPLAT writes it into the tamper-evident ledger — *after* the work ran, so the entry records the outcome too. Later, an auditor holding the outside tool's trace can find the exact kernel-side record of what really executed. Two notebooks, one case number.
- **The wax seal (audit anchor).** Every answer comes back stamped with the fingerprint of the ledger's newest page. Because each page's fingerprint is bonded to the page before it, that one stamp vouches for *everything* the request did. An outside agent that saves the stamp with its own checkpoint can prove, forever, which history its answer was built on — and nobody can quietly rewrite that history underneath it.

For Python folks, there's a ready-made kit: the `splat-langgraph` package (in `src/splat-langgraph-py`) turns SPLAT's whole toolset — commands, diagnostics, investigations, the Brain, the crews — into LangGraph tools, forwarding the case number and catching the wax seal automatically.

## Appendix — Little glossary

| Term | Meaning |
| :--- | :--- |
| **Agent** | An AI worker with a job description: one reasoning model, one tool, one allowed destination. |
| **Mission** | One agent doing one job once, inside its lease, from launch to plain-English verdict. |
| **Template** | The recipe an agent is built from — which model, which tool, which destination, which questions it answers. |
| **Lease** | The time-boxed, capped permission slip a mission runs under. Expires when the job ends. |
| **Sandbox / jail** | The locked room: a fenced folder plus hard limits on memory, CPU, and privileges, enforced by Windows. |
| **Prompt injection** | Tricking an AI by hiding instructions in something it reads. The forged note slipped to your contractor. |
| **DLP (the censor)** | Data-loss prevention: the filter that masks passwords, keys, and personal numbers before anything leaves your machine. |
| **Egress firewall** | The single approved phone line. Any attempt to call anywhere else is refused. |
| **Audit ledger** | The chained, tamper-evident logbook of everything every agent ever did. |
| **Remediation** | A suggested fix, run in its own sandbox, with a rollback (undo) for anything that changes state. |
| **Kernel** | The deepest layer of an operating system. When enforcement lives there, programs above it — including AIs — can't opt out. |
| **MCP** | Model Context Protocol — the standard plug that lets outside AI tools request work through SPLAT's containment instead of running loose. |
| **Trace id** | A case number an outside AI framework hands over with a request, written into the ledger so both sides' records join on one value. |
| **Audit anchor** | The wax seal on every answer: the ledger's newest fingerprint, which vouches for the entire chain of records beneath it. |

---

*SPLAT · © Platten Industries. This guide reflects the app as of August 2026.*
