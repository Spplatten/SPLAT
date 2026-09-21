<!-- Written 2026-09-20 for the operator, after the substrate audit. Two questions: how to learn
     what is going on, and which steps are theirs because they need root. Commands were run on this
     machine on that date unless a line says otherwise. Links are checked by DocumentationDriftTests. -->

# Operator guide — what is going on, how to learn it, and the steps that are yours

Two halves. The first is a reading and running order for understanding the Linux side of SPLAT
as it stands today. The second is the short list of things only you can do, because they need
root inside WSL, with the exact commands and what a good result looks like.

---

## Part 1 — What is going on

### The pieces, in plain words

SPLAT's Linux side is one program and one bridge.

- **The guard** is `splat-agent`, a small Rust program that runs as root inside your WSL Ubuntu.
  When it starts it loads a tiny kernel program (`lease_lsm.bpf.c`, 261 lines of C) into the
  Linux kernel. That kernel program watches three moments: a program starting, a file being
  opened, and a network connection being made. For a process under a **lease**, each of those is
  allowed only if the lease says so; otherwise the kernel refuses it and writes one 40-byte note
  into a shared buffer saying what it refused. The guard reads those notes and passes them on.
- **The bridge** is the C# code on the Windows side (`WslLeasedExecutor` and friends) that
  `splat-mcp` uses. It connects to the guard over the loopback network, proves it holds the
  shared secret, sends one request describing the lease and the command, and reads back the
  command's output, any kernel refusals, and the exit code.

A lease is small on purpose: one command, a list of files it may not open, at most a few network
addresses and ports, a memory and CPU ceiling, a time limit, and it runs as the unprivileged
`nobody` user. When the lease ends, the process is killed and the policy withdrawn, in that
order, because a process that outlived its policy would be running with no guard at all.

### What the audit found, and what was done about it

The kernel program held up. It is short, has no loops, uses 40 bytes of stack, and every one of
its map keys carries the lease's identity so two leases cannot borrow each other's permissions.
The problems were around it, in the guard's own code and in the documents. In the order they
mattered:

| Found | Why it mattered | Done |
| --- | --- | --- |
| The thread reading kernel refusals stopped on its first error and never restarted | The kernel kept refusing, but nobody was told: enforcement intact, evidence gone | Fixed; it logs and keeps reading |
| A burst of refusals across leases could silently end one lease's stream of them | Same effect, one lease at a time | Fixed; it reports how many it missed and carries on |
| A tool's output was read one line at a time with no limit, in a root process | One endless line grew the guard by the size of the output | Fixed; output travels in 64 KiB pieces |
| The bridge did the same on the Windows side | Same growth, one hop later | Fixed; results are capped at 4 MiB per stream and say so |
| Whatever sat on the guard's port could send the bridge a line it never ended | The bridge would buffer it forever | Fixed; abandoned at 1 MiB |
| A guard that crashed or was stopped left its leased processes running with no kernel program behind them | Those processes were uncontained from that moment on | Fixed; leftover leases are killed at startup and on shutdown |
| An expired lease whose process would not die was forgotten while its policy stayed installed | Kernel map entries leaked; nobody retried | Fixed; retried every second |
| A request the guard did not understand got no answer | The bridge waited out its whole time limit | Fixed; refused with a reason |
| Documents disagreed with the code in five places | A reader would act on the wrong fact | Fixed; see the list below |
| The lease was a deny-list on files, not a jail: everything not named was reachable, your Windows drives included | The one boundary that mattered most was a list of exceptions | Built: every leased command now runs in its own root with the system read-only, its working directory, a fresh `/tmp`, and no `/home` or `/mnt` at all. Unproven until step 1 |
| Closing the Windows drives was a runbook line to remember | A host whose operator forgot it stayed open | `provision --apply` writes it and measures whether it took |
| Anyone holding the guard's secret could ask it for any lease at all | A leaked secret bought the guard's whole authority | The guest now holds a ceiling of its own that every request is cut down to, written by `provision`; a leaked secret buys at most what the file allows |
| A leased tool could send UDP anywhere, DNS included | The guard watched connections, and a datagram names its own destination instead of connecting | A fourth hook judges datagrams against the same list. **This changes behaviour:** a lease that wants to look a name up must name its resolver, or the lookup is refused |

Then, on your say-so, the kernel program itself changed: each refusal record now carries the
kernel's own clock and a sequence number, the program counts the refusals it had no room to
record, and the connect hook refuses a network address too short to hold one. Every recorded proof
carries the SHA-256 of that file, so the daemon and last-hop proofs no longer name the program
that ships. The README's "proven" claims are withdrawn until they are re-run, and re-running them
needs root. That is Part 2.

### How to learn it, in order

Read these in this order; each one answers one question.

| Read | The question it answers | About how long |
| --- | --- | --- |
| [The Field Guide](TUTORIAL.md), Parts 2, 7 and 9 | What is a lease, and what is real today | 15 minutes |
| [ARCHITECTURE.md](ARCHITECTURE.md), "Who enforces what" and the continuum map | Which boundary is held by the kernel, which by SPLAT's own code, and why each layer is coupled or not | 20 minutes |
| [ARCHITECTURE-linux-substrate.md](ARCHITECTURE-linux-substrate.md) | How the guard, the kernel program and the bridge fit, step by step | 30 minutes |
| [SUPPORTED_POLICY.md](../native/splat-agent/SUPPORTED_POLICY.md) | What a lease enforces, what it refuses, and what it does not police | 15 minutes |
| [SCHEMA.md](SCHEMA.md) | The exact bytes and frames that cross each boundary, and what is not guaranteed | 20 minutes |
| [RUNBOOK.md](RUNBOOK.md) | What a machine needs, and where the developer setup differs from a hardened one | 15 minutes |

Then the source, in the order the data flows. Each file is small enough to read whole.

| File | Read it for |
| --- | --- |
| [`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c) | The three hooks. Start at the bottom, `splat_socket_connect`, which is the clearest |
| [`violation.rs`](../native/splat-agent/src/violation.rs) | How a 40-byte kernel note becomes text, and why the byte order comments exist |
| [`lease.rs`](../native/splat-agent/src/lease.rs) | What a lease holds, and the tests that prove two leases stay apart |
| [`cgroup.rs`](../native/splat-agent/src/cgroup.rs) | How a process is put in a box with a memory and CPU ceiling, and how the box is emptied |
| [`auth.rs`](../native/splat-agent/src/auth.rs) | How the two sides prove they share the secret without sending it |
| [`main.rs`](../native/splat-agent/src/main.rs) | Everything above, wired together. Read `handle_client` last |
| [`WslLeasedExecutor.cs`](../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs) | The Windows end of the same conversation |

### How to see it working, without root

From a WSL terminal, the guard's own tests:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && cargo test
```

Expect `test result: ok. 44 passed`. From PowerShell, the bridge's tests against a stand-in guard:

```powershell
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test C:\C_AGENT_BUILDER\tests\MissionController.Tests\MissionController.Tests.csproj --filter "FullyQualifiedName~WslLeasedExecutorWire|FullyQualifiedName~WslAgentSession"
```

Expect every test passing. And the installed guard's own account of itself:

```powershell
splat-mcp doctor
```

The two lines that matter are `daemon token` and `enforcement`. Reachable is not enforcing; only
`enforcement live` means a lease reaches the kernel.

---

## Part 2 — What you need to do with root

Two kinds of root exist here, and only one of them needs you.

- `wsl -u root` runs a command as root in the guest **without a password**. `splat-mcp provision`
  and the bridge use it. Nothing in this part needs it from you.
- `sudo` inside a WSL shell **prompts for your password**. An agent cannot type into that prompt.
  Everything below is here because of it.

### Step 1 — Re-run the guard's proofs against the new build

Both the guard and its kernel program changed today, so this step is required, not optional: the
recorded daemon and last-hop proofs name a program that no longer ships, and the README says so
until you have run this. The standalone canary is a frozen copy and does not need re-running.
Three runs, in two terminals.

Terminal one, inside WSL. This builds the guard and starts it with `sudo`, which prompts:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash run-daemon.sh
```

Leave it running. A good start prints `BPF-LSM programs attached successfully`,
`Lease maps bound; kernel enforcement is live` and `listening and ready`. If it prints
`Ended N orphaned lease(s)` first, that is the new startup sweep finding leftovers from an earlier
guard; it is expected once and worth telling me about.

Terminal two, inside WSL, while the first is running:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash probe-daemon.sh
```

Expect a last line `evidence written: ... (verdict PASS)` and a rewritten
`evidence/daemon-probe.json`. Five of its lines are new and are the jail's first proof: `jail
hides /home and /mnt`, `system dirs read-only in jail`, `workdir, /tmp writable, /etc visible`
and `readOnlyFs makes workdir read-only`, with `host has /home and /mnt` as their control. A
`False` among them is the finding of the day; paste the whole run. Then, from PowerShell, against
the same running guard:

```powershell
C:\C_AGENT_BUILDER\native\splat-agent\probe-last-hop.ps1
```

Expect the same `(verdict PASS)` line and a rewritten `evidence/last-hop-probe.json`. Stop the
guard in terminal one with
Ctrl-C. The new shutdown path should print `Stopping; no lease was running.` Paste both results
to me: with two passes on record I restore the README's "Enforcing, proven under root" and
"Demonstrated end to end" wording, which the suite then holds to the new evidence, and commit the
evidence with it. A failure is a finding, not a setup problem; paste it whole.

### Step 2 — Watch the shutdown behaviour once, with your own eyes

This is the change most worth seeing, because it is the one that used to leave a process running
with no guard. Start the guard as in step 1, then from PowerShell ask for a long lease through the
connector, for example a `run_command` of `/bin/sleep` with `60` as its argument and a
`timeoutSeconds` of 120. While it runs, in another WSL terminal:

```bash
ps -eo pid,user,cmd | grep '[s]leep 60'
```

Expect one line owned by `nobody`. Now stop the guard with Ctrl-C in its terminal, and run the
`ps` line again. Expect nothing: the guard's last act was to end the lease it could no longer
police, and its log says `Stopping; ended 1 leased workload(s)`.

### Step 3 — Put the new guard into the installed service

The service under systemd runs the copy that `splat-mcp provision` installed, not the one
`run-daemon.sh` built. Rebuilding `splat-mcp.exe` embeds a fresh guard; that build needs the
static libraries the packaging script asks for, so run the script and follow what it says:

```powershell
C:\C_AGENT_BUILDER\packaging\publish-splat-mcp.ps1
```

Then install and restart the service. No password: this uses `wsl -u root`. Give it the same
endpoint list you give the server, so the guest holds a ceiling of its own:

```powershell
splat-mcp provision --apply --egress 127.0.0.1:80
```

Expect `daemon binary ... replaces it and restarts the service`, a `lease ceiling` line naming
the endpoints, and `enforcement live`. One thing to know before step 1, not after: once a ceiling
is in the guest, the dev daemon that `run-daemon.sh` starts reads it too, and the probes dial
`127.0.0.1:80` and `127.0.0.1:53` as their permitted endpoints. A ceiling that leaves either out
fails those checks for a reason that has nothing to do with the kernel, so keep both in the list,
or run the probes before writing one.

Add your own resolver to the list as well if any leased tool will look a name up, for example
`--egress 127.0.0.1:80,127.0.0.1:53,203.0.113.7:443`. Since the datagram hook landed, a DNS query
is a destination like any other and is refused when the lease does not name one; `doctor` prints a
`name lookups` line when your policy has none.

### Step 4 — The kernel-side change is in; step 1 is what proves it

Applied 2026-09-20 on your say-so: each refusal record carries the kernel's clock and a sequence
number, the program counts what it could not record, and the connect hook refuses an address too
short to hold one. What could be checked without root was: the program compiles for the v3
instruction set it now needs, its three hooks are still straight-line code with 40 bytes of stack,
the Rust side asserts the new 56-byte layout, and the bridge's tests see the new fields arrive.
What cannot be checked without root is the only thing that matters — that the kernel's verifier
accepts the program and the hooks still refuse what they should — and that is step 1.

### What does not need you

The mount namespace for the workload (P2 of the plan), policing UDP, pinned kernel maps and a
guest-side ceiling policy are all real work and none of it is blocked on root to *write*. Each is
blocked on being *proven*, which comes back to step 1's probes. What I think should be done about
each, and in what order, is in
[the hardening note](audits/2026-09-20-substrate-hardening.md).

### What to send back

The three verdict lines from step 1, the two `ps` results from step 2, and the last three lines
of `splat-mcp provision --apply` from step 3. Failures are as useful as passes; paste the whole
output either way.
