# SPLAT demo tape — shot list

A ~3:35 screen-recorded tape that answers "what is this" for two audiences at once: an engineer
skimming a portfolio, and a reader who has to grade it. Captions carry the argument, so it plays
silent; a voiceover can be laid over the same cut without re-recording anything.

**Every number and every line of terminal output quoted below was read out of this tree, not
written from memory.** Where an act depends on a run the operator has to start, it says so. The
source of each fact is linked so the tape can be re-cut when the evidence moves.

- Target: 1920×1080, 30 fps, no audio track.
- Cards are generated: `packaging\..\demo\record-demo.ps1 -Cards`.
- Captures are driven by the same script: `-Capture <id>`.
- Final cut: `-Assemble`.

---

## Before you record

1. **The tree must be clean and `dist\App` must be current.** `dist\App` is a publish output; a
   stale one shows a catalog that still lists templates this repository has retired, and a demo
   that shows a retracted claim is worse than no demo. Republish with
   `packaging\build-client-dist.ps1 -InstallToApp`, which refuses to run while the console is open
   and only replaces `dist\App` after its gates pass.
2. **The daemon should be the installed unit, active.** `wsl -u root systemctl is-active splat-agent`.
3. **Shorten the prompt and hide host recon.** The tape will show this machine's hostname, user name
   and paths. `function prompt { "PS> " }` in the recording shell, and keep the window title
   generic. This matters more if the tape is ever attached to the public repository than if it goes
   to one reader.
4. **One window, 1920×1080, taskbar hidden.** `gdigrab` captures a window by title; anything
   overlapping it lands in the frame.

---

## Act 0 — Cold open · 0:00–0:12

**Card `00-open`.** Black, then one line.

> Agents don't get trust.
> They get a lease.
>
> SPLAT — Sandboxed Process Lease & Agent Telemetry

Hold the last half-second on a frozen frame of the red `-EPERM` line from Act 3. The hook is the
refusal; the explanation can wait.

---

## Act 1 — The problem · 0:12–0:42

Three cards, ~10 s each. No terminal yet.

**Card `01-beside`**
> Every mainstream defence for "safe" agent execution — prompt rules, regex guards, wrapper APIs —
> runs *beside* the agent, at the agent's own privilege.

**Card `02-around`**
> A hijacked agent routes around a guard it shares privilege with.
> Prompt injection is not a bug with a patch. It is what happens when untrusted text and
> instructions share a channel.

**Card `03-below`**
> So the boundary goes *below* the agent.
> In the kernel, where the agent cannot reach it.

---

## Act 2 — What a lease is · 0:42–1:12

**Card `04-lease`**
> A lease names **this binary, this destination, this many seconds**.
> An exec or a `connect()` outside it returns `-EPERM` from the kernel —
> not from a wrapper the agent shares privilege with.

**Card `05-unit`**
> A container's unit is a machine. A lease's unit is one task.
> `docker run` hands the workload a box. A lease hands it a sentence.

**Capture `06-policy`** — ~8 s. Scroll
[`native/splat-agent/SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) in an editor.

> Caption: *This file predicts the refusal before it happens — and enumerates what a lease does
> not enforce at all.*

That second clause is the point of the shot. Do not cut it.

---

## Act 3 — The proof · 1:12–2:12 (the longest act; this is the tape)

**Capture `07-reprove`** — the operator runs this in their own terminal. The permission classifier
refuses an agent every route to a root daemon, so this act cannot be automated:

```
powershell -ExecutionPolicy Bypass -File packaging\reprove-substrate.ps1
```

It builds the daemon from the tree, runs both probes against it, puts the installed service back,
and exits 0 only when both verdicts are PASS against the hash of the kernel program that ships.
Let the build scroll at speed — that texture is worth eight seconds — then slow down for the
output.

**Freeze and zoom on these three lines** from
[`last-hop-probe.json`](../native/splat-agent/evidence/last-hop-probe.json) (recorded
2026-10-01T13:58:35Z):

```
-EPERM: Hook=Exec    Comm=sh    denied execution of unleased binary (inode 1633)
-EPERM: Hook=Connect Comm=curl  denied outbound network connection to unapproved IPv4 1.1.1.1
"verdict": "PASS"
```

> Caption 1: *A `run_command` from an MCP client travelled the C# bridge into the kernel. The
> command the lease permitted ran — as `nobody`. The second exec and the outbound connection died
> there.*

> Caption 2: *Kernel `6.18.33.2-microsoft-standard-WSL2`. Stock WSL2 with native BTF and
> `CONFIG_BPF_LSM=y`. No custom kernel, no fork, no cloud round trip.*

> Caption 3: *BPF source `496cc634`. The build stays red until this probe is re-run against the
> source that ships, so the claim cannot outlive the code.*

That third caption is the one an engineer will rewind for.

---

## Act 4 — The run record · 2:12–2:50

**Capture `08-console`** — launch `dist\App\MissionController.UI.exe`, run one catalog mission end
to end, then open the ledger view and verify the record.

> Caption 1: *Every action a governed mission takes is written to a hash-chained ledger.*

> Caption 2: *The chain is keyed from a file the operator holds. Without that file a rewrite is
> undetectable — and `doctor` says so, out loud, on every host where the key is missing.*

The second caption is the commercial wedge and the integrity move in one sentence. A product video
would cut it. Keep it.

---

## Act 5 — A stranger can run it · 2:50–3:10

**Card `09-install`** — show the MCP stanza, then

```
splat-mcp.exe doctor
```

> Caption: *Met on a second machine on 2026-09-18: the published executable on a Windows 11 Home
> install that had never seen SPLAT provisioned itself to enforcing, passed the same probe, and
> survived a restart. That run found two defects this machine never showed.*

---

## Act 6 — What this does not establish · 3:10–3:35

**Card `10-limits`.** Plain type, no motion. This act is why the rest is believable.

> One engineer. No second reviewer has read this code and no auditor has assessed it.
> Caller identity on the bridge trusts a secret, not the peer.
> Scratch-specific execution authorization: open.
> The live test corpus is incomplete, and the badge says so.
> Claims in this repository have been withdrawn after passing once.

**Card `11-close`**
> Every claim is bound to a probe you can run on your own host.
> The build fails when the prose and the evidence disagree.
>
> github.com/Spplatten/SPLAT · AGPL-3.0 · Platten Industries

---

## Cut notes

- **Do not add music under Act 3.** The output is the content; scoring it reads as a product ad and
  costs the tape its credibility with exactly the audience it is for.
- **Caption timing:** leave each caption on screen long enough to be read twice. The terminal
  output underneath does not need to be read at all — it needs to be *seen to be real*.
- **If Act 3 cannot be run live,** cut to the JSON evidence file on screen instead and say in the
  caption that it is a recorded run, with its date. Never imply a live run that did not happen.
- **Length discipline:** Acts 1 and 2 are the first thing to cut if the tape runs long. Act 3 and
  Act 6 are load-bearing and are cut last.
