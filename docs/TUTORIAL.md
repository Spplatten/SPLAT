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

Every job in SPLAT follows a strict rule the project calls **1:1:1** — one task template gets exactly *one* AI model, *one* pre-approved tool it may run, and at most *one* internet address it may talk to. Not "a browser." Not "the internet." One tool, one destination, spelled out in advance. For two-thirds of the tools the plumbing allows no network at all; Part 7 is exact about the rest.

One leased job, from the outside in:

```
┌─ Ring 5 · THE LEDGER — every action written to a tamper-evident logbook ──┐
│ ┌─ Ring 4 · THE PHONE — none for most tools; the rest are unpinned ────┐  │
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

Most of the rings aren't SPLAT asking nicely — rings 1 and 2 are enforced by the Windows kernel's own object system, and so is ring 4 where a tool gets no network at all; the censor and the logbook are SPLAT's own code. The tool is spawned *suspended* (frozen) so every ring is locked in place before it ever wakes up.

## Part 3 — Meet your agent squad

SPLAT ships with a squad of specialist agents — each one a bundle of a reasoning AI, one dedicated tool, and one approved destination, pre-configured for a specific kind of problem. The four you'll meet first:

| Agent | Specialty | What it does for you |
| :--- | :--- | :--- |
| 🌐 **Atlas-Net** | Network | Chases down Wi-Fi drops, slow internet, DNS delays, and strange programs listening on your network. |
| 🛡️ **Sentinel-SecOps** | Security | Hunts brute-force login attacks and surges of failed sign-ins that suggest someone's trying to get in. |
| 💾 **Titan-SysOps** | Storage | Watches disk space, finds bloated caches and clutter, and points at what's safe to clean up. |
| 🔒 **Aegis-Endpoint** | Compliance | Checks that Microsoft Defender is on, virus signatures are fresh, and secure connections are configured right. |

Behind them sits a catalog of **49 specialists** covering networking, identity, endpoint security, system operations, and compliance — plus a newer *Autonomous Operations* wing with agents that build and deploy websites, draft multi-platform marketing campaigns, and vet grant eligibility before drafting the application paperwork — all under the same leash as everyone else. For bigger jobs, **Project Studio** chains up to six agents in a fixed order, and even the notes they pass to each other are filtered for secrets first. No free-for-all swarms, no infinite loops — by design.

### Wait — is SPLAT an agent builder, or a containment zone?

If you came here looking for an AI bot that opens a browser, logs into TikTok Ads Manager to configure OAuth callbacks, or connects to your personal email to scrape your inbox, you will quickly notice **SPLAT does not do that** — and that is entirely by design.

Those tasks belong to **Robotic Process Automation (RPA)** — unconstrained bots that navigate arbitrary websites, handle high-privilege credentials, and trigger irreversible cloud actions. In SPLAT's worldview, handing an AI free-roaming browser access and private credentials is an unacceptable security hazard: the moment that bot encounters prompt injection (in an email or a web page), an attacker can hijack it to steal tokens or exfiltrate data.

> **SPLAT is an execution containment substrate and governance zone.** It does not send bots wandering across the web; it locks down execution on your machine.

- **How SPLAT runs native tasks:** When a specialist runs a task (such as inspecting local event logs, diagnosing network drops, or auditing OAuth configurations), it runs a single pre-vetted tool inside an OS-enforced sandbox. Privileges are stripped, each tool works in its own fenced folder, DLP scrubs secrets, and about two-thirds of the specialists run with no network at all — the glossary entry for network denial says which ones do not, and why. It audits, diagnoses, and drafts — it never roams the web unchecked.
- **Locked rooms for external agents:** If you use external general agents (like Claude Code, Cursor, or LangGraph) that need to run commands or manipulate files, they plug into SPLAT via `splat-mcp`. The external agent provides the reasoning; SPLAT provides the bouncer, ensuring out-of-bounds actions die before touching your system.

## Part 4 — What actually happens when you press the button

Say you open SPLAT and type: *"My internet keeps cutting out during video calls."* Here's the whole journey, in order:

1. **The Brain reads your goal.** SPLAT's reasoning layer — the Agent Brain — takes your plain-English sentence and breaks it into concrete, testable questions: is it Wi-Fi? DNS? Something hogging the connection?
2. **It checks its memory.** A local memory index (stored on your machine, not in the cloud) recalls similar past incidents — "this looks like the DNS problem from March" — to aim the investigation.
3. **It forms hypotheses and picks specialists.** Each suspicion becomes a hypothesis assigned to a matching specialist template — likely Atlas-Net here. Each hypothesis will be confirmed or refuted with real evidence, never vibes.
4. **The tool starts frozen.** The specialist's one allowed tool is launched *suspended* — created but not yet running — while the sandbox clamps on: memory and CPU caps, admin rights stripped, folder jail sealed. Only then is it thawed.
5. **Evidence is gathered inside the rings.** The tool runs its diagnostic and produces raw output, under hard caps on memory and CPU. Two-thirds of the tools also run with no network and no access to your own files; the rest run with your ordinary, non-admin rights, which is why each is one pre-vetted tool rather than anything an AI asks for.
6. **The censor scrubs the output.** Before one byte leaves your machine, a data-loss-prevention filter masks passwords, keys, tokens, email addresses, card and social-security patterns — in memory, before transmission.
7. **The AI reasons over clean evidence.** The scrubbed evidence travels down the single approved line to the reasoning model (Claude or Gemini — whichever key you connected), which interprets it and streams its thinking back live.
8. **You get a verdict in plain English.** A clear status — healthy, warning, or critical — with findings that cite the actual evidence. A template can also offer fixes. Each is labeled with its risk and runs only when you click it, and only if it says how to check that it worked: the verdict is that check's answer, not the program's own say-so. A fix can carry an undo, checked the same way, though nothing yet requires a risky fix to have one. None of the templates that ship today offers a fix yet.
9. **Everything lands in the ledger.** Every step — every command, argument, and result — is sealed into a cryptographic logbook. More on why that matters below.

## Part 5 — A map of the app, screen by screen

| Screen | What you use it for |
| :--- | :--- |
| **Quick Diagnostician** | The home screen. Big friendly tiles for one-click checkups, plus a box where you type any problem in your own words and let the Brain run with it. |
| **Welcome** | The three-step setup wizard: meet the squad, paste one AI key, launch. Takes about two minutes. |
| **Live Mission Monitor** | Watch missions run in real time — the agent's reasoning streams in as it works. |
| **Template Catalog** | Browse all 49 specialists, see exactly what tool and destination each one is allowed, and launch them directly. |
| **Project Studio** | Chain up to six agents into a staged project — investigate, then verify, then summarize — with filtered hand-offs between stages. |
| **Security Audit** | Read the tamper-evident ledger: every action ever taken, verifiable, in one place. |
| **Memory** | Search past incidents by the words they share — "printer broke" finds the missions that mention printers. |
| **Jail Inspector** | Look inside the sandboxes themselves: see the fenced folders and locks each mission ran under. |
| **Settings** | Manage your AI keys (encrypted by Windows), providers, and app preferences. |

## Part 6 — A logbook built to show tampering

Every action in SPLAT — every command an agent ran, every argument it used, every fix it applied — is written to an audit ledger. But it's not an ordinary log file, because ordinary log files can be edited after the fact.

SPLAT's ledger works like a logbook where every page's ink is chemically bonded to the page before it. Each entry includes a cryptographic fingerprint of the previous entry, forming a chain. Change any historical record — even one character — and every fingerprint after it stops matching. There is a catch worth knowing: someone who can edit the logbook file could also redo every fingerprint after their change, and the chain alone would not notice. That is what a key is for. Give SPLAT a key — a small secret file that you keep — and every fingerprint is made with it, so nobody without that file can redo them. Setting one up is a single command in the runbook. Keep the file where only you can reach it, because whoever holds it holds that power too.

With a key, that's the difference between "we log everything" and "we can **prove** nobody without the key rewrote history." If you ever need to answer *what exactly did the AI do to my machine?* — the answer is in the ledger. The one thing even a keyed chain can't see on its own is its newest pages being torn out, and the wax seal on every answer (Part 9) is what catches that.

There is a second kind of receipt, for one job at a time. Ask for a **run record** and SPLAT writes a small folder about that one job: what it was allowed to do — the exact tool and command line, the fenced folder it worked in, whether it had a phone at all — what it did, and every logbook page it wrote, each with a proof that it belongs with the others. Two scripts come in the folder, and either one checks the whole thing on a machine that has never heard of SPLAT. Make a signing key once (the runbook's step 1.6) and the folder is signed with it, so whoever you hand it to can tell your records from someone else's; without a key the folder says plainly that it is unsigned, which means it shows its own pages agree and nothing about who wrote them.

## Part 7 — Straight talk: what's real today, and what isn't yet

SPLAT's documentation makes a point of never blurring the line between built and planned. This guide keeps that promise.

- ✅ **Working today** — The Windows containment system: frozen starts, resource clamps, stripped privileges, folder jails. The governance layer: the 1:1:1 rule, the secret-scrubbing censor, the one-line-out firewall, the tamper-evident ledger, local memory. The full app, the 49-agent catalog, and a connector (`splat-mcp`) that lets other AI tools — like Claude Code, or a Python agent built with LangGraph — borrow SPLAT's locked rooms, and that sets up the Linux guard itself with one command. Backed by 638 automated tests, all passing.
- 🔶 **Being built** — The Linux-side deep containment: a guard that lives inside the Linux kernel itself (BPF-LSM) and vetoes forbidden actions before they happen. **The proof run is now on record.** On a stock Microsoft kernel, the guard let through the one thing the job was allowed to do and refused the other three outright: reading the password file, calling an unapproved address, and running an unapproved program. The refusals came from the kernel, not from SPLAT asking nicely. The service that routes work to that guard now runs too. It runs each tool as an ordinary user with no special rights, and a file that user could otherwise read was still refused, by the kernel rather than by SPLAT's say-so. And the road in from outside is now on record too: a command sent by another AI tool through the connector travelled into that guard and was refused there, while the one command it was allowed to run went through in the same session. What is *not* yet true is that the app's **own** missions travel that road — the operator console still never routes one through the guard.
- ⬜ **Planned** — Faster host-to-sandbox plumbing (VSOCK) and deeper multi-step autonomy — which agents only earn in places where kernel-level enforcement is switched on.

One consequence of that gap is worth stating plainly, because it's new. The grant-discovery agent is the first specialist whose tool reaches the internet rather than only reading your own machine. Its one approved destination is declared in the template, written into the ledger, and compiled into the Linux kernel guard described above. On Windows the enforcement is coarser, and it is worth being exact about how, because the honest version is neither "locked" nor "wide open": of the 49 agents in the catalog, 33 launch their tool with no network access whatsoever. That wall is real and the operating system holds it shut, not SPLAT's good intentions. The remaining sixteen keep a network connection, and for those Windows enforces *whether* a tool may reach the network but never *where* it may go. Fifteen of the sixteen are there for an unglamorous reason: the same lock that cuts the network also blinds Windows' own diagnostic plumbing, so an agent that reads your event log has to keep a connection it never uses. The sixteenth is the grant agent, which genuinely wants the internet — so on Windows its one approved destination is an audited promise rather than an enforced wall. That agent is therefore built to be harmless if the promise were ever broken: it presents no password or key, it only reads public funding notices, and it files nothing. Every grant agent stops at a draft for you to review — none of them can submit an application.

## Part 8 — Your first five minutes

SPLAT runs on Windows 11. On first launch, the Welcome wizard walks you through three steps: meet the agent squad, connect one AI key, go.

The one thing you need is an API key from Anthropic (starts with `sk-ant-`) or Google Gemini (starts with `AIza`) — that's the reasoning brain your agents will think with. Paste it once; SPLAT verifies it live, figures out which provider it belongs to, and locks it in Windows' own encrypted vault (DPAPI). It never sits on disk in readable form. One wrinkle worth knowing, because the error message is not obvious: an Anthropic key made at the organisation level rather than inside a workspace is refused with "this API key is not scoped to a workspace", and SPLAT shows that refusal word for word rather than inventing an answer. Make the key inside a workspace and it works.

Then head to the Quick Diagnostician: tap a tile for a one-click checkup, or type what's bothering you — *"my laptop fan won't stop"*, *"is someone trying to log into my PC?"* — and watch the squad go to work. Every finding comes back in plain English, every suggested fix has a clearly labeled risk level, and nothing runs until you click it.

And if you're the type who wants to see the machinery: the Live Mission Monitor shows the reasoning as it streams, the Jail Inspector shows the locked rooms, and the Security Audit screen shows the receipts. Nothing in SPLAT is a black box — that's rather the point.

## Part 9 — Plugging other AIs into the same cage

SPLAT's locked rooms aren't just for SPLAT's own agents. Any AI framework that speaks MCP — Claude Code, Microsoft Copilot, or a Python agent built with LangGraph — can send its work through the `splat-mcp` connector. The outside AI keeps its own brain and its own plan; SPLAT stays the bouncer. If a manipulated agent asks for something outside its lease, it isn't SPLAT's *opinion* that says no — it's the same containment every native agent lives under.

### Getting it onto your machine

**It is one file.** `splat-mcp.exe` ships self-contained: the machine running it needs no runtime installed, the database engine the logbook uses is packed inside the executable rather than laid beside it, and so is the Linux guard itself. `splat-mcp provision --apply` puts that guard in place inside WSL — no programming tools to install, no copy of the source code — and names the two steps it will not take for you: installing WSL, and restarting it. It is published with a SHA-256 fingerprint, so you can check that the file you downloaded is the file that was built.

**Ask the machine what it can actually enforce, before you trust it with anything.** `splat-mcp doctor` reports what this particular host will and will not hold: which kernel it is running, whether the in-kernel guard is loaded, whether the lease daemon answers, and whether it holds the token needed to speak to it. It serves nothing and creates nothing — it is a question, not a command — and it reports success *only* when a lease would genuinely reach the kernel. A machine that cannot contain anything says so out loud, instead of quietly serving tools that imply otherwise.

**You draw the fences, not the visiting AI.** Two options set the whole perimeter, and both belong to whoever starts the connector:

| Option | What it decides |
| :--- | :--- |
| `--workspace <dir>` | The single directory the file tools may read or write. It has to exist already: the connector never creates it for you, because a fence you can conjure with a typo is not a fence. Left out, those tools are confined to a default directory instead — never to the whole disk. |
| `--egress <a.b.c.d:port,...>` | The complete list of addresses the command tools may connect to. A visiting agent may ask for some of them, and is never given the rest. **Left out, those tools get no network at all** — the quiet default is the closed one. |

That last point is the argument of this whole guide in one line. The visiting AI never names the addresses it may reach. **The person starting the connector does**, before the agent has said a word — and an agent that asks for anything else is refused by the same plumbing that refuses SPLAT's own specialists.

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
| **Network denial** | Stronger than the phone line: no phone at all. The tool runs in a Windows AppContainer with no network permission, so it cannot dial *any* number — not even by skipping the phone book and punching in an address directly. About two-thirds of the specialists get this. The rest are still given a phone: the one that genuinely reads a public grants database, which Windows cannot yet stop from dialling elsewhere (it is read-only and carries no password), and the ones that read Windows' own event logs, management data or Defender status — the wall that takes the phone away would cut those off too, so for now they keep a phone they do not need. |
| **Run record** | The receipts for one job, in a folder you can hand to someone else: what that job was allowed to do, what it did, its logbook pages with proofs, and scripts that check them. Signed once you have made a signing key, and honest about being unsigned until then. |
| **Audit ledger** | The chained, tamper-evident logbook of everything every agent ever did. |
| **Remediation** | A fix a template can offer, run in its own sandbox. It runs only if it says how to check that it worked, and it can carry a rollback (undo), checked the same way, though nothing yet requires one. The shipped templates offer none yet. |
| **Kernel** | The deepest layer of an operating system. When enforcement lives there, programs above it — including AIs — can't opt out. |
| **MCP** | Model Context Protocol — the standard plug that lets outside AI tools request work through SPLAT's containment instead of running loose. |
| **Trace id** | A case number an outside AI framework hands over with a request, written into the ledger so both sides' records join on one value. |
| **Audit anchor** | The wax seal on every answer: the ledger's newest fingerprint, which vouches for the entire chain of records beneath it. |

---

*SPLAT · © Platten Industries. This guide reflects the app as of September 2026.*
