<!-- Read this before changing anything in this repository. It is written for people and for the AI
     agents that work this tree, and it holds what the code cannot say about itself: why the
     project is shaped this way, the rules it holds itself to, the words it uses, and the traps that
     have already cost someone an afternoon. Dated facts carry their date; the live plan and the
     README's status table outrank anything here. -->

# Context

## What SPLAT is

SPLAT — Sandboxed Process Lease & Agent Telemetry — contains AI agents **below** the agent. A
mission gets one pre-approved tool, run once, under limits the operating system enforces — a Win32
job object and restricted token on Windows, a BPF-LSM capability lease in the kernel on Linux — with
its output scrubbed before it leaves the process and every step sealed into a tamper-evident ledger.

It is **blast-radius containment, not detection.** SPLAT does not try to tell whether an agent has
been prompt-injected; it bounds what the agent can do, whatever it has become. A defence that runs
at the agent's own privilege fails at the moment the agent is compromised, so the defences that
count are the ones the agent cannot reach. The unit of containment is one mission — *this tool,
this destination, for this many seconds* — not a machine.

## Where it stands

As of 2026-09-10. [The live plan](audits/2026-09-09-oem-subtraction-plan.md) is the source; this is
the short form.

- **Commercial path:** license the daemon and the containment primitives to companies building
  agent platforms. The first revenue is expected from paid containment assessments, which need
  nothing beyond P1.
- **P0, the runtime floor — done 2026-09-09.** The shipping tree is on .NET 10.
- **P1, installable and provable by a stranger — next.** A `splat-mcp` CLI and `doctor` command,
  single-file distribution, first-run WSL provisioning, and one capability manifest read by the
  CLI, `tools/list`, SUPPORTED_POLICY and the tests (F24).
- **P2, the workload's own mount namespace** — which unblocks `readOnlyFs`, copy-on-write scratch
  and running code an agent just wrote. AF_VSOCK too, if it fits.
- **P3, the per-mission run record** — a bundle from which someone who did not run a mission can
  verify what it was permitted to do and what it did.
- **The WinUI console is off the critical path.** It stays on `net9.0-windows10.0.19041.0` and
  Windows App SDK 1.6, still builds, and ships nothing. Because it references four of the shared
  libraries, those multi-target — so **no .NET-10-only API may appear in Core, Data, Linux,
  Network or Windows while that leg lives.** .NET 9 leaves support on 2026-11-10.

## The rules this repository holds itself to

The code and the tests enforce most of these; review enforces the rest.

1. **A claim is only as good as its evidence.** Kernel proofs are JSON files carrying the SHA-256
   of the source they exercised. `DocumentationDriftTests` fails the build when the README claims
   more than the evidence supports *and* when it claims less, and stops accepting a proof when its
   source changes. A measurement that came back worse than the marketing is published as measured.
2. **Say which layer enforces it.** Every boundary is a kernel object, a kernel LSM hook, a check
   in SPLAT's own process, or a declaration. Documents, tool descriptions and refusal messages name
   which. [ARCHITECTURE.md](ARCHITECTURE.md#who-enforces-what) keeps the table.
3. **Fail closed, loudly.** Containment that cannot be applied refuses the work; it never falls back
   to running uncontained and logging a warning.
4. **Refuse what you cannot enforce; never accept it and drop it.** A field that is parsed and
   ignored reads back to its caller as granted.
5. **Built is not wired.** A class no composition root constructs is not a capability, however well
   tested. [ARCHITECTURE.md](ARCHITECTURE.md#built-but-not-on-a-live-path) lists the current cases,
   and `CompositionRootTests` pins the registrations that matter.
6. **A control not observed failing was never measured.** A security fix lands with a test that
   fails against the parent commit and a negative control showing the legitimate path still works.
   Probes assert their own controls. A containment test checks the *work* as well as the boundary:
   proving a socket was refused said nothing about whether the sensor still ran.
7. **Never present simulation as output.** No model key means a visible `SimulatedNotice`; a metric
   nobody measured is reported as unavailable, not as a plausible number.
8. **The comment records the defect.** Comments here explain what the previous code got wrong and
   why the current code is shaped to prevent it. Keep to that when you change something: the next
   reader needs the failure being guarded against, not a restatement of the syntax.
9. **Identifiers are append-only.** `TemplateId`s are written into the ledger; `Fnn` and `AG-Fnn`
   finding ids are cited from code comments and commit messages. Renaming either orphans the record.

## Vocabulary

| Term | Meaning |
| --- | --- |
| **Mission** | One governed execution: one template, one tool run, one analysis, and the ledger rows under one mission id |
| **Governed template**, **1:1:1** | `SingleToolTemplate`: one model, one native tool, one egress FQDN. "1:1:1" is what `ValidateStrictRules()` checks |
| **Sensor** | The native tool a template runs — `ping`, `wevtutil`, a PowerShell pipeline |
| **Egress scope** | Which process reaches a template's FQDN: `ModelGateway`, SPLAT's own model call and the default, or `ToolProcess`, the sensor itself |
| **Jail** | A mission's working directory with a protected ACL, under `%LOCALAPPDATA%\MissionController\Jails` |
| **Network denial** | Launching the sensor into SPLAT's zero-capability AppContainer, so it has no network stack |
| **Argument binding** | `GovernedArgumentBinder`: parameters into a command line in one pass, refused rather than escaped |
| **Credential shield**, **DLP** | The two scrubbers applied to tool output before it leaves the mission |
| **Quality island**, **Quadrant I** | `QualityIslandEngine` scores an analysis on structure and on grounding; only an analysis high on both is accepted |
| **Grounding**, `[UNSUPPORTED]` | `TelemetryGrounder` marks findings whose specifics do not appear in the sensor's output |
| **Ledger**, **commitment**, **anchor** | The SHA-256 chained audit log; each row commits to a salted digest of its details; an anchor is the head hash returned with an MCP result |
| **Recall** | Similar past missions pulled from semantic memory into the prompt, fenced as data |
| **Investigation**, **project**, **crew**, **workflow**, **brain** | Engines that compose missions — never a second way to run a process |
| **Lease** | A per-cgroup grant the kernel enforces through BPF-LSM: executables, protected files, IPv4 endpoints, plus clamps and a lifetime |
| **Daemon** | `splat-agent`, the root process in the WSL2 guest that installs leases and runs leased tools |
| **Canary** | `splat-canary`, the standalone harness that first proved the hooks; frozen |
| **Probe**, **evidence file** | A script that exercises the real thing, and the JSON verdict it writes, bound to a source hash |
| **Enforcing** | The daemon health field saying leases reach the kernel. Reachable is not enforcing |
| **Last hop** | An agent's request travelling `splat-mcp` → bridge → daemon. Wired; no recorded run |
| **Run record** | P3's per-mission evidence bundle |
| **`Fnn`**, **`AG-Fnn`** | Finding ids from [the clinical audit](audits/2026-09-04-clinical-audit.md) and [the antigravity audit](audits/2026-09-05-antigravity-deep-audit.md) |
| **Wave** | A batch of remediations; [WAVE-PLAN.md](audits/WAVE-PLAN.md) records the commit that closed each |
| **P0–P3** | The phases of the live plan |
| **The net9 leg** | The `net9.0` target the shared libraries keep so the frozen console still compiles |

## Working in this tree

**Build and test.** The solution needs the .NET 10 SDK, plus the .NET 9 SDK for the console's leg.
On the reference machine both are installed user-local under `%LOCALAPPDATA%\Microsoft\dotnet` and
are **not on `PATH`**, so call that `dotnet.exe` by its full path:

~~~powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" build MissionController.sln
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test tests\MissionController.Tests\MissionController.Tests.csproj
~~~

The bar is zero errors and zero warnings on both legs. Several tests start real processes, job
objects, AppContainers and PowerShell, so the suite needs a Windows host and exercises the machine
it runs on. The Rust crates build inside WSL — `cargo build --release` in `native/splat-agent`,
which is what `run-daemon.sh` does.

**Documents are tested.** `DocumentationDriftTests` holds `README.md` and the top level of `docs/`
to the tree: every relative link must resolve, no document may promise latency the recorded
benchmark does not support, and the test count advertised in `README.md` and `docs/TUTORIAL.md`
must equal the suite's — so run the suite before you change that number, not after.
`docs/SPLAT-Field-Guide.html` is the source for `docs/TUTORIAL.md` and a published copy: change
the HTML first, then the other two.

**The app runs from `dist\App`,** a `dotnet publish` output that git ignores — nothing in git will
restore it, and a stale copy can fail to start. A start that fails before its window opens shows a
message box, writes the reason to `%LOCALAPPDATA%\SPLAT\crash.log` and exits;
[the runbook](RUNBOOK-human-steps.md) has the checks for a launch that looks alive but is not.

**Where state lives:**

| What | Where |
| --- | --- |
| Console database — ledger, registries, memory | `%LOCALAPPDATA%\MissionController\Data\missioncontroller.db` |
| `splat-mcp` database — a separate chain and memory | `%LOCALAPPDATA%\SPLAT\audit_ledger.db` |
| Jails | `%LOCALAPPDATA%\MissionController\Jails\{missionId}` |
| DPAPI vault | `%LOCALAPPDATA%\MissionController\Vault` |
| Compliance packages | `%LOCALAPPDATA%\MissionController\ComplianceExports` |
| MCP and Copilot workspaces | `%LOCALAPPDATA%\SPLAT\mcp-workspace`, `%LOCALAPPDATA%\SPLAT\copilot-workspace` |
| Crash log | `%LOCALAPPDATA%\SPLAT\crash.log` |
| In the WSL2 guest: daemon token, daemon log, lease cgroups | `/etc/splat/agent.token` (root, 0600), `/tmp/splat-agent.log`, `/sys/fs/cgroup/splat_leases` |

**The Linux side needs a person.** Loading BPF-LSM programs needs root, `sudo` prompts, and an agent
cannot type into the prompt. [RUNBOOK-human-steps.md](RUNBOOK-human-steps.md) lists those steps.
Three traps:

- From an agent's shell tool, `wsl bash -lc '…'` has been seen to expand `$?` and shell variables
  *before* WSL receives the command, even inside single quotes — so a status read inside it lies.
  Let the status propagate out of `wsl.exe` and read it in the outer shell.
- `rustup` puts `cargo` on `PATH` from `.bashrc`, which a non-login shell never reads.
- Windows updates WSL's kernel on its own schedule. Re-run `preflight.sh` when it does.

**More than one agent works this checkout.** Treat the working tree as shared. Check
`git status --short` and `git branch --show-current` yourself rather than trusting a snapshot taken
when your session began; re-read a file immediately before editing it; stage only your own paths —
a hunk someone else left uncommitted is not yours to commit. For branch work, use a `git worktree`
rather than switching the shared checkout's branch.

**Commit subjects** read `type(scope): what changed, and why it matters` — for example,
`fix(mcp): confine fs_read and fs_write by handle, not by string`.

## Known, and deliberate

Open, and written down, so that nobody rediscovers them as news.

| Gap | Where it is stated |
| --- | --- |
| UDP `sendto`, AF_UNIX and AF_NETLINK, inherited descriptors, writes outside the workspace and ambient reads are not policed by the lease | [SUPPORTED_POLICY.md](../native/splat-agent/SUPPORTED_POLICY.md) |
| `readOnlyFs` and copy-on-write are refused — the workload has no mount namespace yet | SUPPORTED_POLICY.md; P2 |
| No recorded run of the last hop | The README's status table |
| The daemon's shared secret does not stop a same-user Windows process | [auth.rs](../native/splat-agent/src/auth.rs); AF_VSOCK in P2 |
| On Windows, a `ToolProcess` sensor's destination is a claim, and WMI-dependent templates keep their network | [Windows substrate](ARCHITECTURE-windows-substrate.md#who-gets-the-appcontainer) |
| The ledger runs unkeyed, so a rewrite is undetectable | [Control plane](ARCHITECTURE-control-plane.md#evidence-and-memory); the README |
| No bare-token DLP rules for AWS, GitHub, OpenAI, Stripe or JWT | AG-F06, planned with P3 |
| The console and `splat-mcp` keep separate ledgers and memories | [ARCHITECTURE.md](ARCHITECTURE.md#two-hosts-one-pipeline) |
| `splat-mcp` has no CLI | P1 |

## Read next

1. [ARCHITECTURE.md](ARCHITECTURE.md), then the companion for the area you are touching.
2. [MODULE_INFO.md](MODULE_INFO.md), for the project you are in.
3. [SUPPORTED_POLICY.md](../native/splat-agent/SUPPORTED_POLICY.md), before saying anything about
   what a lease stops.
4. [The live plan](audits/2026-09-09-oem-subtraction-plan.md), before starting anything new.
