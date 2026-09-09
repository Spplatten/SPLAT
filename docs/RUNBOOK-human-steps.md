# Runbook — what you verify, and what only you can do

Companion to [the current plan](audits/2026-09-09-oem-subtraction-plan.md). Every command here was
run on this machine on the date it is marked with, so the expected output is what actually came
back, not what should theoretically happen.

> **Superseded companion.** This was written against `PLAN-substrate-completion.md`, removed
> 2026-09-09 once three of its four gates had closed (Windows egress via AppContainer and
> `IEgressFirewall`; the gRPC/`proto` ambiguity settled by deleting the proto; kernel evidence
> machine-checked in `daemon-probe.json`). Its one open gate — first-run provisioning — moved to
> P1 of the plan above.

Two things need a human and cannot be delegated to an agent:

1. **Anything needing an interactive `sudo` password.** Loading a BPF-LSM program needs root.
   `sudo` on this box is configured to prompt, and an agent cannot type into that prompt.
2. **Anything that changes system state** — installing Windows features, rebooting, swapping the
   WSL kernel. Those are yours by policy, not by capability.

---

## Your machine's actual state

Verified 2026-09-02. This is better than the plan documents assume — the kernel work is already done.

| Thing | State |
| :--- | :--- |
| WSL2 + Ubuntu | Installed, running |
| `.wslconfig` with `bpf` in the LSM list | **Already applied** |
| `CONFIG_BPF_LSM`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF` | All `=y` on the running kernel |
| `bpf` in the *active* LSM list | Yes — `capability,landlock,yama,safesetid,selinux,bpf,ima` |
| Runtime BTF, cgroup v2 unified | Both present |
| clang 21.1.8, bpftool 7.7.0, cargo/rustc 1.98.0 | All installed |
| `vmlinux.h` for both crates | Generated 2026-08-29, 3.6 MB |
| **Preflight verdict** | **GREEN** |

There is no setup left. You are one interactive `sudo` away from a real canary run.

> Preflight reported YELLOW until today, claiming cargo and rustc were missing on a machine that
> had 1.98 installed. `rustup` puts cargo on `PATH` from `.bashrc`, which a non-login shell never
> reads, so `command -v cargo` came back empty. Now fixed — but worth knowing that a *verification
> script* was the thing lying to you.

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

### 1.1 The test suite

```bash
cd C:\C_AGENT_BUILDER && "%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" test tests\MissionController.Tests\MissionController.Tests.csproj
```

**Expect:** `Passed! - Failed: 0, Passed: 459`. The `dotnet` on this box is not on `PATH`, which is
why the full path is used.

**Why it matters:** the number is not decorative. A test now fails if the README or the Field Guide
advertise a count that disagrees with the suite, so `459` in the docs is checked, not asserted.

### 1.2 The documentation actually matches the code

```bash
"%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" test tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~DocumentationDrift"
```

**Expect:** 10 passed. These check that every relative link in the README resolves on disk, that every
tool the MCP server exposes is documented, that retired overclaims have not crept back, and that the
advertised test count matches reality.

**Try breaking it:** change `459` to `458` in `README.md` and re-run. It should go red and name the
file. If it does not, the check is not doing its job — tell me.

### 1.3 The audit ledger verifies

The ledger is a hash chain: every entry commits to the one before it. `VerifyLedgerIntegrityAsync`
recomputes the chain and fails on any edit. It is exercised by the suite above; to see it against
your real database rather than a test fixture, open the app's **Security Audit** screen, which reads
`%LOCALAPPDATA%\SPLAT\audit_ledger.db`.

### 1.4 The app runs

```bash
C:\C_AGENT_BUILDER\dist\App\MissionController.UI.exe
```

**If it exits silently,** the publish output is stale — check `%LOCALAPPDATA%\SPLAT\crash.log`,
which is where startup failures land.

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
PASS on 15 checks under a root daemon, which is what [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)
cites for every claim in its enforced tables.

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

Once 0.1–0.2 land, the run writes `native/splat-canary/evidence/canary-<kernel>.json` carrying the
kernel release, the LSM list, the four outcomes, and the git SHA of the BPF source that produced
them. Commit it. From then on the suite fails if the documents claim more than that file supports,
and fails again if the BPF program changes without a fresh run.

---

## Part 3 — Re-running preflight whenever the kernel changes

Windows updates WSL's kernel without asking. When it does, the LSM list can change under you.

```bash
wsl bash -lc "cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && bash preflight.sh"
```

**Expect:** `VERDICT: GREEN`. If it drops to YELLOW after a Windows update, the `[FIX]` lines name
the exact cause — usually the `.wslconfig` kernel command line needing to be re-applied, followed by
`wsl --shutdown`. That shutdown is yours to run: it stops every distro and anything else using WSL,
including Docker Desktop.

---

## What is deliberately not in this runbook

- **Building the MSIX package** — deferred.
- **Gates 1–4** — none of them are runnable yet; they are design decisions first. Gate 1 (the Windows
  egress gap) needs a choice between three approaches before anyone runs anything.
- **`wsl --install` and reboots** — already done on this machine, and not needed again.
