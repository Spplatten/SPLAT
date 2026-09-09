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

## Part 0 — the .NET 10 SDK (the one open human step, 2026-09-09)

This is the only thing currently blocking work, and it is an install rather than a decision. .NET 9
leaves support on **2026-11-10**, and .NET 8 leaves the same day, so there is no LTS below 10.

Only `9.0.317` is present, and it lives in a **user-local** root
(`%LOCALAPPDATA%\Microsoft\dotnet`). Install 10 into that same root. Do **not** use winget: it
installs under `Program Files`, and two dotnet roots means two `dotnet.exe` that disagree about
which SDKs exist.

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1').Content)) -Channel 10.0 -InstallDir "$env:LOCALAPPDATA\Microsoft\dotnet"
```

It is a large download and it prints little while it runs; several minutes of apparent silence is
normal. Confirm it landed:

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" --list-sdks
```

Expected: **two** lines, `9.0.317` and a `10.0.x`, both under the same path. One line means the
script chose a different `-InstallDir` or did not finish.

Everything after that is ordinary editing and belongs to the agent — the eight `.csproj` edits and
five package bumps are itemised in
[P0 of the plan](audits/2026-09-09-oem-subtraction-plan.md#5-sequence).

---

## Part 1 — Verify what is already claimed (about 5 minutes, no setup)

Nothing here changes state. Run them in any order.

### 1.1 The test suite

```bash
cd C:\C_AGENT_BUILDER && "%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" test tests\MissionController.Tests\MissionController.Tests.csproj
```

**Expect:** `Passed! - Failed: 0, Passed: 342`. The `dotnet` on this box is not on `PATH`, which is
why the full path is used.

**Why it matters:** the number is not decorative. A test now fails if the README or the Field Guide
advertise a count that disagrees with the suite, so `342` in the docs is checked, not asserted.

### 1.2 The documentation actually matches the code

```bash
"%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" test tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~DocumentationDrift"
```

**Expect:** 8 passed. These check that every relative link in the README resolves on disk, that every
tool the MCP server exposes is documented, that retired overclaims have not crept back, and that the
advertised test count matches reality.

**Try breaking it:** change `342` to `341` in `README.md` and re-run. It should go red and name the
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

Gate 0 makes the kernel enforcement provable instead of anecdotal. Today `run-canary.sh` ends by
printing `Expected: … three -EPERM lines` for a person to read, and the loader returns success
unconditionally — so **the harness cannot fail**, which means a green run proves nothing.

### Who does what

| Step | Who | Status |
| :--- | :--- | :--- |
| 0.1 Make the canary assert and exit non-zero on a bad run | me | not started |
| 0.2 Emit a structured evidence file | me | not started |
| 0.3 Test that the docs match the evidence | me | not started |
| 0.4 Bind evidence to the BPF source that produced it | me | not started |
| **0.5 Run the canary with `sudo`** | **you** | blocked on 0.1–0.2 |
| 0.6 Commit the evidence file | either | after 0.5 |

Steps 0.1–0.4 are mine and need no permissions. Step 0.5 is the one that needs your password.

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
