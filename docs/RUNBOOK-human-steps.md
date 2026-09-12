# Runbook — what you verify, and what only you can do

Companion to [the current plan](audits/2026-09-09-oem-subtraction-plan.md). Every command here was
run on this machine on the date it is marked with, so the expected output is what actually came
back, not what should theoretically happen.

> **Superseded companion.** This was written against `PLAN-substrate-completion.md`, removed
> 2026-09-09. Two of its four gates had closed — the gRPC/`proto` ambiguity settled by deleting the
> proto, and kernel evidence machine-checked in `daemon-probe.json`. First-run provisioning moved to
> P1 of the plan above. Windows network denial is not closed — 33 of 49 catalog templates run with
> it and 16 without — and was recorded here first as closed, then as half closed; the last section
> has the detail.

Two things need a human and cannot be delegated to an agent:

1. **Anything needing an interactive `sudo` password.** Loading a BPF-LSM program needs root.
   `sudo` on this box is configured to prompt, and an agent cannot type into that prompt.
2. **Anything that changes system state** — installing Windows features, rebooting, swapping the
   WSL kernel. Those are yours by policy, not by capability.

---

## Your machine's actual state

Re-verified 2026-09-10 by re-running preflight and `dotnet --list-sdks`; first recorded 2026-09-02.

| Thing | State |
| :--- | :--- |
| WSL2 + Ubuntu | Installed; systemd is PID 1 |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` — the one the committed canary evidence was recorded on |
| `.wslconfig` kernel command line | `lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf` |
| `CONFIG_BPF_LSM`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF` | All `=y` on the running kernel |
| `bpf` active as an LSM | Yes. Read straight from securityfs on 2026-09-02 as `capability,landlock,yama,safesetid,selinux,bpf,ima`. On 2026-09-10 securityfs was unmounted after a cold boot, so it was confirmed from the boot command line instead — see Part 3 |
| Runtime BTF, cgroup v2 unified | Both present |
| clang 21.1.8, bpftool 7.7.0, cargo/rustc 1.98.0 | All installed |
| `vmlinux.h` for both crates | Generated 2026-08-29, 3.6 MB |
| .NET SDKs (Windows side) | `9.0.317` and `10.0.401`, both in `%LOCALAPPDATA%\Microsoft\dotnet` |
| **Preflight verdict** | **GREEN** |

There is no setup left, and the canary has run and passed — see Part 2.

> Preflight reported YELLOW until 2026-09-02, claiming cargo and rustc were missing on a machine that
> had 1.98 installed. `rustup` puts cargo on `PATH` from `.bashrc`, which a non-login shell never
> reads, so `command -v cargo` came back empty. Fixed then — but worth knowing that a *verification
> script* was the thing lying to you. It happened a second time on 2026-09-10; Part 3 has that one.

---

## Part 0 — the .NET 10 SDK  ✅ DONE 2026-09-09

> **Installed and verified.** `10.0.401` alongside `9.0.317` in the same user-local root, and the
> retarget it unblocked has landed: the suite runs 459/459 on `.NETCoreApp,Version=v10.0`, and the
> frozen UI still builds on the net9 leg. Kept below because it is the procedure to repeat on
> another machine, and because both failure modes it documents cost a 300 MB download each.

The reason it had to happen first: .NET 9 leaves support on **2026-11-10**, and .NET 8 leaves the
same day, so there is no LTS below 10.

`9.0.317` was already present in a **user-local** root
(`%LOCALAPPDATA%\Microsoft\dotnet`), so 10 goes into that same root. Do **not** use winget: it
installs under `Program Files`, and two dotnet roots means two `dotnet.exe` that disagree about
which SDKs exist.

```powershell
Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1' -OutFile "$env:TEMP\dotnet-install.ps1"
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\dotnet-install.ps1" -Channel 10.0 -InstallDir "$env:LOCALAPPDATA\Microsoft\dotnet"
```

> **Download it, do not pipe it.** The obvious one-liner —
> `& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing '...').Content))` — fails on Windows
> PowerShell 5.1 with a wall of `Unexpected token '13'` parse errors. `-UseBasicParsing` returns
> `.Content` as a **byte array** for this content type, so `[scriptblock]::Create()` stringifies it
> as space-separated byte values and tries to parse *those* as PowerShell. The numbers in the error
> are the script's own header: `35 13 10 35 32 67 111 112` decodes to the comment line the file
> opens with. `-OutFile` writes the raw bytes to disk and sidesteps the encoding entirely.

> **Close the build servers first.** The extract overwrites `dotnet.exe` itself, and it is the very
> first file out of the archive — so if anything holds it, the install fails after downloading all
> 300 MB:
>
> ```
> dotnet-install: Failed to extract package. Exception: … "The process cannot access the file
> '…\Microsoft\dotnet\dotnet.exe' because it is being used by another process."
> ```
>
> The usual culprit is nobody's fault and easy to miss: `dotnet build` and `dotnet test` leave a
> Roslyn compiler server (`VBCSCompiler`) and MSBuild worker nodes resident for about fifteen minutes
> after they finish, and those run *as* `dotnet.exe` out of this root. Run
> `dotnet build-server shutdown` before installing. A failed extract leaves nothing behind to clean
> up — `dotnet.exe` is the first entry, so the SDK directory is never created — and the archive is
> not cached, so a retry re-downloads in full.

It is a large download and it prints little while it runs; several minutes of apparent silence is
normal. `dotnet-install: Installation finished` is the last line. Confirm it landed:

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" --list-sdks
```

Expected: **two** lines, `9.0.317` and a `10.0.x`, both under the same path. One line means the
script chose a different `-InstallDir` or did not finish.

What actually came back on 2026-09-09:

```
9.0.317 [C:\Users\s_pla\AppData\Local\Microsoft\dotnet\sdk]
10.0.401 [C:\Users\s_pla\AppData\Local\Microsoft\dotnet\sdk]
```

Everything after that was ordinary editing and is done — see
[P0 of the plan](audits/2026-09-09-oem-subtraction-plan.md#5-sequence).

---

## Part 1 — Verify what is already claimed (about 5 minutes, no setup)

Nothing here changes state. Run them in any order.

> **PowerShell, because that is what your terminal is.** Until 2026-09-10 this part gave `cmd.exe`
> syntax — `cd … && "%LOCALAPPDATA%\…"` — inside `bash` fences, and it ran in neither. Windows
> PowerShell 5.1 rejects `&&` as a statement separator and never expands `%VAR%`; bash treats
> `%LOCALAPPDATA%` as a literal directory name. Both were confirmed by parsing the old lines, not
> assumed. Commands that run *inside* WSL stay `bash`.

### 1.1 The test suite

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test C:\C_AGENT_BUILDER\tests\MissionController.Tests\MissionController.Tests.csproj
```

**Expect:** `Passed! - Failed: 0, Passed: 525`, on a line ending `(net10.0)`. The `dotnet` on this
box is not on `PATH`, which is why the full path is used; the leading `&` is PowerShell's call
operator, without which a quoted path followed by arguments is a parse error.

**Why it matters:** the number is not decorative. A test fails if the README, the tutorial, the
Field Guide or this runbook advertise a count that disagrees with the suite, so the number in the
docs is checked, not asserted.

**When it goes red, do not edit the four documents by hand.** They state the count in four different
spellings - prose, the shields badge, the tree diagram, the pasted run output - and hand-editing is
what put them out of step repeatedly. Re-derive all of them from the suite instead:

```powershell
$env:SPLAT_SYNC_TEST_COUNT = "1"
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test C:\C_AGENT_BUILDER\tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~TheAdvertisedTestCount_MatchesTheSuite"
Remove-Item Env:\SPLAT_SYNC_TEST_COUNT
```

That writes the real count into every spelling in all four files, using the same regexes that detect
the drift - so a spelling the check can see is necessarily one the fix can reach. Review the diff and
commit it like any other change.

### 1.2 The documentation actually matches the code

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test C:\C_AGENT_BUILDER\tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~DocumentationDrift"
```

**Expect:** all pass - the count is deliberately not quoted here, because a number in this runbook
rots the same way the ones it is policing do. These check that every relative link in the README and
in `docs/` resolves on disk, that every tool the MCP server exposes is documented, that retired
overclaims have not crept back, and that the advertised test count matches reality.

**Try breaking it:** change the advertised test count in `README.md` to any wrong number and re-run.
It should go red, name the file, and print the sync command above. If it does not, the check is not
doing its job — tell me.

### 1.3 The published Field Guide is not stale

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test C:\C_AGENT_BUILDER\tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~ThePublishedFieldGuide"
```

**Expect:** 1 passed.

**Why it matters:** the Field Guide has three copies — `docs/SPLAT-Field-Guide.html` (the source),
`docs/TUTORIAL.md`, and a published page at
<https://claude.ai/code/artifact/18992308-da75-4782-87b8-20b6ba7b4311>. The first two are checked
against the code by everything above. The third is the one a non-engineer actually reads, it lives
outside the repository, and for weeks it told readers that Windows does not filter network sockets
at all — after both repository copies had been corrected. This check records the source's hash, so
editing the guide without republishing the page now fails the build.

**When it goes red:** that is the check working. Two commands and a publish, in this order:

```powershell
C:\C_AGENT_BUILDER\packaging\build-field-guide-artifact.ps1
```

That writes `dist\field-guide-artifact.html` — the exact body to publish — and prints the hash. Ask
me to publish that file to the artifact URL. Once the page is live:

```powershell
C:\C_AGENT_BUILDER\packaging\build-field-guide-artifact.ps1 -RecordPublished
```

**Do not run the second command first.** It is a separate switch precisely so that recording is a
deliberate act: it asserts the live page matches the source, and if it does not, you have just
hidden that. Doing only the second half is worse than doing neither — the page stays wrong and now
looks verified.

### 1.4 The audit ledger verifies

The ledger is a hash chain: every entry commits to the one before it. `VerifyLedgerIntegrityAsync`
recomputes the chain and fails on any edit. It is exercised by the suite above; to see it against
your real database rather than a test fixture, open the app's **Security Audit** screen, which
verifies the console's own chain in `%LOCALAPPDATA%\MissionController\Data\missioncontroller.db`.
`splat-mcp` keeps a separate chain in `%LOCALAPPDATA%\SPLAT\audit_ledger.db`, which that screen does
not read.

### 1.4 The app runs

```powershell
Start-Process C:\C_AGENT_BUILDER\dist\App\MissionController.UI.exe -WorkingDirectory C:\C_AGENT_BUILDER\dist\App
```

Give it ten seconds, then:

```powershell
(Get-Process MissionController.UI).MainWindowTitle
```

**Expect:** `SPLAT — Autonomous AI Agent Fleet & System Appliance`. Seen on 2026-09-09 right after
the refresh below, with the process at about 247 MB, responding, and no new crash log.

**Why the title and not "is it running":** a startup failure in this app does not exit.
`App.OnUnhandledException` marks every unhandled exception handled, so a bad start leaves a **live
process with no window** and a blank title. Note the timestamp on `%LOCALAPPDATA%\SPLAT\crash.log`
*before* launching: a newer one afterwards names the failure — usually a XAML resource that did not
load — and an old one proves nothing either way. The working directory is set explicitly so the
launch does not depend on where your shell happens to be.

#### Refreshing `dist\App`

After pulling changes, or when the crash log names something the source has already fixed.
`dist\App` is a publish output, not a build copy, and **`dist/` is gitignored — git cannot give it
back.** Back it up first:

```powershell
robocopy C:\C_AGENT_BUILDER\dist\App "C:\C_AGENT_BUILDER\dist\App.backup-$(Get-Date -Format yyyyMMdd)" /E
```

Publish framework-dependent — the shape `dist\App` has always held, with the .NET runtime coming
from the machine rather than the folder:

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" publish C:\C_AGENT_BUILDER\src\MissionController.UI\MissionController.UI.csproj -c Release -r win-x64 --self-contained false -p:Platform=x64 -p:WindowsPackageType=None
```

Then mirror the result in:

```powershell
robocopy C:\C_AGENT_BUILDER\src\MissionController.UI\bin\x64\Release\net9.0-windows10.0.19041.0\win-x64\publish C:\C_AGENT_BUILDER\dist\App /MIR
```

`robocopy` reports success as exit codes 0–7 — `1` means "files copied" — so a red exit status from
it is not a failure; 8 and above is. Then repeat the launch check. This sequence ran on 2026-09-09 to
ship the patched `e_sqlite3.dll`; the folder held 290 files before and after.

---

## Part 2 — Gate 0, step by step

Gate 0 made the kernel enforcement provable instead of anecdotal. It is **done**, and the section is
kept because 0.5 is the step you re-run whenever the kernel changes.

The problem it fixed: `run-canary.sh` used to end by printing `Expected: … three -EPERM lines` for a
person to read, while the loader returned success unconditionally — so the harness could not fail,
and a green run proved nothing.

### Who does what

| Step | Who | Status (re-verified 2026-09-09) |
| :--- | :--- | :--- |
| 0.1 Make the canary assert and exit non-zero on a bad run | me | **done** — `run-canary.sh` exits non-zero and prints `FAIL (exit N)` |
| 0.2 Emit a structured evidence file | me | **done** — `evidence/canary-6.18.33.2-microsoft-standard-WSL2.json`, verdict `PASS` |
| 0.3 Test that the docs match the evidence | me | **done** — `CommittedKernelEvidence_IsEitherAbsentOrMatchesItsBpfSource` |
| 0.4 Bind evidence to the BPF source that produced it | me | **done** — `bpf_source_sha256` in both PASS evidence files |
| **0.5 Run the canary with `sudo`** | **you** | **done once**; re-run per Part 3 when the kernel changes |
| 0.6 Commit the evidence file | either | **done** |

The daemon-level equivalent went further and is also done: `native/splat-agent/evidence/daemon-probe.json`,
PASS on 17 checks under a root daemon, which is what [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)
cites for every claim in its enforced tables. The hop into it from a real MCP client is recorded
separately, in `evidence/last-hop-probe.json`; `native/splat-agent/probe-last-hop.ps1` re-runs that
one from Windows against the same root daemon, and needs no `sudo` of its own.

### Step 0.5 — running the canary (yours)

Do this in an **interactive** WSL terminal, not through an agent, because `sudo` will prompt.

Open a terminal and run:

```bash
wsl
```

Then inside WSL:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && bash run-canary.sh
```

It builds the loader (a minute or two the first time), then asks for your password, because loading
a BPF-LSM program needs `CAP_BPF` and `CAP_SYS_ADMIN`.

**What a correct run looks like — one permitted action and three kernel refusals:**

```
[lease] cgroup /sys/fs/cgroup/splat-canary -> id 4020
[lease] protecting /etc/shadow (ino 44904)
[lease] allowing egress only to 127.0.0.1
ALLOWED   curl 127.0.0.1        (exit 7 = connection refused — permitted, nothing listening)
  -EPERM  [cat  …] open denied (inode 44904)      ← /etc/shadow
  -EPERM  [curl …] connect denied (dst 1.1.1.1)   ← egress outside the lease
  -EPERM  [sh   …] exec denied (inode 1633)       ← an unleased binary
```

The `ALLOWED` line matters as much as the refusals. Three denials with nothing permitted would mean
the lease is blocking everything, which proves the hooks fire but not that the policy is *correct*.

**If it goes wrong:**

| Symptom | Meaning |
| :--- | :--- |
| `must run as root` | `sudo` did not take. Re-run; do not `sudo bash run-canary.sh` — the script elevates only the loader on purpose |
| `load skeleton … -EINVAL` | The kernel rejected the program — usually `bpf` missing from the active LSM list. Re-run `preflight.sh` |
| `not cgroup v2` | systemd/cgroup v2 is off in the guest. See `wslconfig.sample` section (B) |
| `vmlinux.h missing` | Run `bash setup-guest.sh` first (not needed on this machine — it is already there) |
| Denials appear but no `ALLOWED` | The lease is over-broad or the allow-list is wrong. Capture the output; this is a real finding, not a setup problem |

**Copy the entire output** and give it to me either way. A failed run is as useful as a passing one —
it is the first honest datapoint about this kernel either way.

### Step 0.6 — commit the evidence

The run writes `native/splat-canary/evidence/canary-<kernel>.json`, carrying the kernel release, the
active LSM list, the violations and failures it observed, the verdict, and `bpf_source_sha256` — a
SHA-256 of the BPF source file that produced them, not a git commit. Commit it. The suite then fails
if the documents claim more than that file supports, and fails again if the BPF program changes
without a fresh run.

---

## Part 3 — Re-running preflight whenever the kernel changes

Windows updates WSL's kernel without asking. When it does, the LSM list can change under you. From
your PowerShell terminal:

```powershell
wsl bash -lc "cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && bash preflight.sh"
```

**Expect:** `VERDICT: GREEN`, last seen 2026-09-10. If it drops to YELLOW, every line not marked
`[ok]` names what to resolve — after a Windows update, usually the `.wslconfig` kernel command line
needing to be re-applied, followed by `wsl --shutdown`. That shutdown is yours to run: it stops every
distro and anything else using WSL, including Docker Desktop.

> **A YELLOW that wasn't, fixed 2026-09-10.** A fresh WSL boot does not mount securityfs, so
> `/sys/kernel/security/lsm` does not exist and preflight could not read the active LSM list. It
> reported that as YELLOW — on an unchanged kernel with `bpf` fully active — and then told you to
> apply `[FIX]` lines it had never printed. It now falls back to the boot command line
> (`/proc/cmdline`), which is world-readable and is what the kernel initialised its LSMs from: a
> `bpf` named there, with `CONFIG_BPF_LSM=y`, was initialised. When neither source settles it, it
> prints a real `[FIX]` — how to mount securityfs and read the list yourself.

---

## What is deliberately not in this runbook

- **Building the MSIX package** — deferred. Before reviving it: `packaging/build-msix.ps1` publishes
  `--self-contained true`, a different artifact from the framework-dependent build `dist\App`
  actually holds. Reconcile the two first.
- **Windows network denial for the sixteen templates without it** — still open, and a design
  decision before it is anything to run. Of the 49 catalog templates, 33 launch their tool in an
  AppContainer with no capabilities, so their network denial is enforced. One needs the network
  (Grant Opportunity Ingestion, `EgressScope.ToolProcess`); an AppContainer chooses network or none,
  not a host, so its destination is a claim, not a control. Fifteen are built on WMI, the Event Log
  service, Defender or the service manager, which the container would also cut off, so they keep a
  network stack they do not need. Closing both needs an egress control that is not also an RPC
  wall — a WFP filter is the candidate. `IEgressFirewall` covers neither; it guards SPLAT's own
  model-API client. Counted from the shipped catalog on 2026-09-10, and corrected here from "four"
  and from "every tool that needs no network is denied".
- **The rest of the plan** — P1 (the `splat-mcp` CLI, `doctor`, first-run provisioning) has no
  human-only step. P2, the mount namespace, will: its proof comes from the daemon probe, which needs
  a root daemon and a `sudo` read of its token — the same hand-off as Step 0.5. It gets a section
  here when it is ready to run.
- **`wsl --install` and reboots** — already done on this machine, and not needed again.
