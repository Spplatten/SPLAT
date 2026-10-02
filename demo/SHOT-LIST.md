# SPLAT demo tape — shot list

A tape that answers "what is this" for two audiences at once: an engineer skimming a portfolio,
and a reader who has to grade it. Captions carry the argument, so it plays silent; a voiceover can
be laid over the same cut without re-recording anything.

**Footage leads.** The first cut of this tape opened with five cards of argument before anything
happened on screen, and was correctly called a slide deck. The rule now: nothing is asserted on a
card before the viewer has seen the thing it describes. Cards are captions, not the spine.

**Every number below was read out of this tree, not written from memory.** Where an act depends on
a run only the operator can start, it says so.

- 1920×1080, 30 fps, no audio track.
- `.\demo\record-demo.ps1 -Cards` renders the cards.
- `.\demo\record-demo.ps1 -Terminal <id> -From <transcript>` renders a terminal replay.
- `.\demo\record-demo.ps1 -Capture <id> -WindowTitle '<title>' -Seconds <n>` grabs a window.
- `.\demo\record-demo.ps1 -Assemble` cuts it together and names anything still missing.

---

## The cut

| # | id | Source | Len | What is on screen |
| --- | --- | --- | --- | --- |
| 1 | `01-hook` | replay | 8s | The recorded last-hop probe: three `-EPERM` lines and `PASS` |
| 2 | `02-title` | card | 10s | Agents don't get trust. They get a lease. |
| 3 | `03-problem` | card | 12s | Guards run beside the agent, at its privilege |
| 4 | `04-lease` | card | 13s | What a lease names |
| 5 | `05-doctor` | replay | 7s | `splat-mcp doctor` on this host: enforcement live |
| 6 | `06-console` | **capture** | ~45s | The console running a governed mission, and its ledger |
| 7 | `07-drift` | **capture** | ~30s | Edit a claim, watch the suite refuse it |
| 8 | `08-install` | card | 15s | One MCP stanza; met on a second machine |
| 9 | `09-limits` | card | 20s | What this does not establish |
| 10 | `10-close` | card | 13s | Run the probes yourself |

Generated length is 1:38. With both captures the tape lands near 2:55, roughly 40% real footage.

---

## Replays vs captures

A **replay** (`-Terminal`) renders a committed transcript under `demo\transcripts\` as a clip. The
text is real output from a real run; rendering it rather than screen-grabbing a console keeps the
operator's home directory out of the frame, makes it legible at 1080p, and lets it re-render when
the output changes. It is still a replay, and **a caption must say so.** Never cut a replay in a
way that implies a live run.

A **capture** (`-Capture`) is a real window, recorded live. The two acts below are captures on
purpose: they are the ones where seeing it happen is the whole point.

Re-capture a transcript when the tool's output changes:

```
.\dist\splat-mcp.exe doctor > demo\transcripts\doctor.txt
```

then re-wrap it to 140 columns and redact `$env:USERPROFILE` before rendering — the renderer does
neither for you.

---

## Act 1 · `01-hook` — the cold open

[`last-hop-probe.json`](../native/splat-agent/evidence/last-hop-probe.json), recorded
2026-10-01T13:58:35Z against BPF source `496cc634`, kernel `6.18.33.2-microsoft-standard-WSL2`.
No card first. The refusal is the hook.

> Caption: *Recorded run, 2026-10-01. A `run_command` from an MCP client travelled the C# bridge
> into the kernel. The permitted command ran, as `nobody`. The second exec and the connection to
> 1.1.1.1 died there.*

---

## Act 5 · `05-doctor` — this host, now

`splat-mcp doctor` exits 0: BPF-LSM on the boot line, daemon reachable, token accepted,
enforcement live, lease ceiling held by the guest.

> Caption: *The same command on any host prints what that host will and will not enforce — including
> the rows it marks `--`: an unkeyed ledger, unsigned run records, and what a lease does not police
> at all.*

Those `--` rows are the reason this act is in the tape. Do not crop them out.

---

## Act 6 · `06-console` — **capture, ~45s**

The console running one governed mission end to end, then the ledger.

**Before recording, `dist\App` must be republished** — it is a publish output, and a stale one
shows a catalog still listing templates this repository has retired. A demo that shows a retracted
claim is worse than no demo.

```
powershell -ExecutionPolicy Bypass -File packaging\build-client-dist.ps1 -InstallToApp
```

Then:

```
.\demo\record-demo.ps1 -Capture 06-console -WindowTitle '<exact console title>' -Seconds 45
```

Shot order inside the act: pick a template, run it, let the findings land, open the ledger, verify
the record. Do not narrate the UI — the captions do that.

> Caption 1: *Every action a governed mission takes is written to a hash-chained ledger.*

> Caption 2: *The chain is keyed from a file the operator holds. Without it a rewrite is
> undetectable — and `doctor` says so, out loud, on every host where the key is missing.*

---

## Act 7 · `07-drift` — **capture, ~30s**

The thesis made visible, and the single best thirty seconds available: edit a claim in `README.md`
so it oversells, run the suite, watch `DocumentationDriftTests` refuse it, revert, watch it pass.

```
.\demo\record-demo.ps1 -Capture 07-drift -WindowTitle '<terminal title>' -Seconds 30
```

> Caption: *The documentation is not prose next to the code. It is checked against the evidence
> files, and a claim the probes do not support fails the build.*

Run this one on a clean tree. A peer agent is currently editing `README.md`,
`GovernedTemplateCatalog.cs`, `DerivedTemplateGuard.cs` and `TemplateRegistryExpansionTests.cs`;
reverting your demo edit on top of someone else's in-flight work is how you lose theirs.

---

## Optional · a live `reprove-substrate` run

Stronger than Act 1's replay, and it demotes the replay to a supporting shot. This cannot be
automated — the permission classifier refuses an agent every route to a root daemon, which
`reprove-substrate.ps1` states in its own header. In your terminal, with the capture running:

```
powershell -ExecutionPolicy Bypass -File packaging\reprove-substrate.ps1
```

It builds the daemon from the tree, runs both probes, restores the installed service, and exits 0
only when both verdicts are PASS against the hash of the kernel program that ships. Let the build
scroll at speed, then hold on the verdict.

---

## Cut notes

- **Shorten the prompt before any capture.** `function prompt { "PS> " }`. The tape otherwise shows
  this machine's hostname, user and paths — tolerable for one reader, not for anything hung off the
  public repository.
- **No music under Act 1 or Act 7.** Scoring the evidence reads as an ad and costs the tape its
  credibility with exactly the audience it is for.
- **Captions stay up long enough to read twice.** The terminal underneath does not need to be read
  — it needs to be seen to be real.
- **Cut order if it runs long:** `03-problem`, then `04-lease`, then `08-install`. Acts 1, 6, 7 and
  `09-limits` are load-bearing and are cut last.
