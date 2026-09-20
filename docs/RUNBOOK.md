<!-- The environment contract for the Linux substrate: what a kernel and a guest must have for
     splat-agent to enforce, how to set one up, and where a developer's shortcuts diverge from a
     hardened deployment. RUNBOOK-human-steps.md is this machine's verification checklist and the
     steps only a human can take; this file is what any machine needs. Written 2026-09-20 against
     the tree at 965366b; the recorded kernel and toolchain versions are from that machine. -->

# Runbook — kernel environment and deployment for the Linux substrate

The substrate is one root daemon, [`splat-agent`](../native/splat-agent), which loads
[`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c) into a BPF-LSM kernel and
serves leases on `127.0.0.1:50051`. What it enforces and refuses is in
[`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md); the wire and binary contracts
are in [SCHEMA.md](SCHEMA.md). This file is about the ground it stands on.

---

## 1. Prerequisites

### Kernel

| Requirement | Why | How to check |
| --- | --- | --- |
| `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_LSM=y` | The program type is `BPF_PROG_TYPE_LSM` | `zcat /proc/config.gz \| grep -E 'CONFIG_BPF_(SYSCALL\|LSM)='` |
| `bpf` in the **active** LSM list | Built in is not enabled; the LSM must be named on the boot line | `cat /sys/kernel/security/lsm`, or `lsm=` in `/proc/cmdline` when securityfs is not mounted |
| `CONFIG_DEBUG_INFO_BTF=y` and `/sys/kernel/btf/vmlinux` | CO-RE relocations against the running kernel's types | `test -r /sys/kernel/btf/vmlinux` |
| cgroup v2, unified hierarchy | Lease identity is the cgroup id `bpf_get_current_cgroup_id()` returns on the default hierarchy | `stat -fc %T /sys/fs/cgroup` prints `cgroup2fs` |
| `memory`, `cpu` and `pids` controllers available at `/sys/fs/cgroup` | The daemon delegates them to `splat_leases/` and reads every clamp back; a controller the root does not offer refuses the lease | `cat /sys/fs/cgroup/cgroup.controllers` |
| Kernel release | BPF-LSM programs: 5.7. BPF ring buffer: 5.8. Fetching atomics (the program is built for the v3 instruction set, for its sequence counter): 5.12. `cgroup.kill`: 5.14 (older kernels fall back to a SIGKILL loop). These floors are from kernel history, not re-measured here | `uname -r` |

Recorded and proven on: `6.18.33.2-microsoft-standard-WSL2`, with `CONFIG_BPF_LSM=y`,
`CONFIG_DEBUG_INFO_BTF=y`, boot line
`lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf`.
[`preflight.sh`](../native/splat-canary/preflight.sh) checks every row above and prints a
GREEN / YELLOW / RED verdict; RED means `CONFIG_BPF_LSM` is absent and nothing below applies.

### Toolchain (build machine only)

| Tool | Recorded | Used for |
| --- | --- | --- |
| `clang` / `llvm` | 21.1.8 | Compiling the BPF program to `-target bpf` through `libbpf-cargo` |
| `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `pkg-config`, `build-essential` | Ubuntu packages | `libbpf-sys` |
| `bpftool` | 7.7.0 | Generating `vmlinux.h` from the live BTF |
| Rust stable, `cargo` | 1.98.0 | The daemon; `libbpf-rs` / `libbpf-cargo` **0.24** — the skeleton, map and ring-buffer APIs move between releases |

A shipped `splat-mcp.exe` carries a prebuilt daemon (the `portable` feature links libelf, zlib
and zstd statically), so a guest that only *runs* leases needs none of this.

### Privilege

The daemon runs as root under systemd. Root is more than it uses; what it actually exercises:

| Operation | Needs |
| --- | --- |
| Load and attach the three LSM programs | `CAP_BPF` and `CAP_PERFMON` (LSM is a perfmon program type) |
| Create `splat_leases/mission_*`, write `cgroup.subtree_control`, `memory.max`, `cpu.max`, `pids.max`, `cgroup.procs`, `cgroup.kill` | Write access to the cgroup tree — root by DAC on an undelegated tree |
| `setgroups`, `setresgid`, `setresuid` to `nobody` in the forked child | `CAP_SETGID`, `CAP_SETUID` |
| SIGKILL a workload's tree (fallback below 5.14) | `CAP_KILL` |
| `stat` protected paths under `0700` directories | `CAP_DAC_READ_SEARCH` |
| Create `/etc/splat/agent.token` as `0600` root | root by DAC |
| Mount namespace and `pivot_root` (P2, not built) | `CAP_SYS_ADMIN` |

`CAP_NET_ADMIN` is **not** needed: the program is an LSM hook, not a cgroup or socket program. A
capability-bounded unit is listed under hardening below; it has not been run, and the shipped unit
does not use one.

---

## 2. Setup — WSL2 / Ubuntu, copy-paste

Windows side first. `lsm=` **replaces** the whole list, so it repeats the shipped kernel's
built-in order with `bpf` appended; dropping one silently disables that LSM.

```powershell
Add-Content -Path "$env:USERPROFILE\.wslconfig" -Value "`n[wsl2]`nkernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf"
```

```powershell
wsl --shutdown
```

Guest side: systemd for cgroup v2, and Windows drives closed to `nobody` — a leased command runs
as `nobody`, and WSL otherwise mounts your profile with every mode bit open
([`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md), *Ambient reads*).

```bash
sudo tee -a /etc/wsl.conf >/dev/null <<'EOF'
[boot]
systemd=true
[automount]
options = "umask=077"
EOF
```

Then `wsl --shutdown` again from Windows, reopen, and confirm the ground:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && bash preflight.sh
```

Expect `VERDICT: GREEN`. Build toolchain and `vmlinux.h` (one time; safe to re-run):

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && sudo bash setup-guest.sh
```

It installs the packages in the table above, `rustup` if `cargo` is absent, and writes
`src/bpf/vmlinux.h` into both crates from `/sys/kernel/btf/vmlinux`.

### Developer run — a root daemon in a terminal

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash run-daemon.sh
```

Builds in `~/.cache/splat-agent-target` (not `/tmp`, which any guest user could pre-own) and
starts the daemon with `sudo` on loopback. It exits `1`, rather than serving, if the LSM programs
do not load, if `/etc/splat/agent.token` cannot be created, if the workload uid resolves to root,
or if a lease cgroup a previous daemon left behind will not drain. The unit tests need no root:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && cargo test
```

### Product run — the installed service

From Windows, with a published `splat-mcp.exe`:

```powershell
splat-mcp provision
```

prints what the host still needs and changes nothing; `--apply` does it: writes `[boot]
systemd=true` if PID 1 is not systemd (then `wsl --shutdown` is yours), checks `bpf` on the boot
line, installs the daemon it carries at `/opt/splat/splat-agent` after hashing it and running it
once, writes `/etc/systemd/system/splat-agent.service`, enables and starts it, then asks the
daemon — through the authenticated health check — whether it is enforcing. The unit:

```ini
[Unit]
Description=SPLAT resident BPF-LSM lease daemon
After=network.target

[Service]
Type=simple
ExecStart=/opt/splat/splat-agent --listen 127.0.0.1:50051
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure`, never on a clean exit: the daemon exits `0` after SIGTERM and `1` when it
refuses to enforce, and restarting the refusal would turn a fail-closed stop into a loop. The one
loop it does accept is the orphan case — a leftover lease that will not drain is retried every two
seconds, loudly, rather than served beside.

Verify from Windows:

```powershell
splat-mcp doctor
```

The lines to read are `daemon token` (this host authenticated) and `enforcement` (`live`).
`reachable` alone means something is listening; only `enforcing` means a lease reaches the kernel.

### When the BPF source changes

Evidence is bound to the SHA-256 of the program that produced it, and
`DocumentationDriftTests` withdraws the README's claims until it is re-recorded. All three need
root, so they are interactive:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-canary && bash run-canary.sh
```

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash run-daemon.sh
```

and, in a second terminal while that daemon runs:

```bash
cd /mnt/c/C_AGENT_BUILDER/native/splat-agent && bash probe-daemon.sh
```

then from Windows, against the same daemon, [`probe-last-hop.ps1`](../native/splat-agent/probe-last-hop.ps1).
Commit the three evidence files. [RUNBOOK-human-steps.md](RUNBOOK-human-steps.md) has what a
correct run looks like.

### When Windows updates the WSL kernel

It does so without asking. Re-run `preflight.sh`; a YELLOW usually means the `.wslconfig` line
needs re-applying and a `wsl --shutdown`. The daemon is CO-RE, so it does not need rebuilding for
a new kernel, but the canary evidence file is named by kernel release and the daemon probe records
the release it ran on, so re-run them when you want the proof to name the kernel you are on.

---

## 3. Where developer pragmatism diverges from a hardened deployment

Each row is a choice the code makes today. The right-hand column is what a multi-tenant or
production host would need instead, and **none of it is built** unless the row says so.

| Today, on purpose | Why it is acceptable here | Hardened, not built |
| --- | --- | --- |
| The daemon is root | It loads BPF, owns the cgroup tree and drops the *workload* to `nobody`; that drop is what the probes check | A unit with `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_READ_SEARCH`, `AmbientCapabilities=` of the same, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/etc/splat /sys/fs/cgroup`. **Unverified** — the cgroup writes and the `cgroup.procs` join under a bounded set have not been tried |
| Loopback TCP with a shared secret | An unprivileged guest process cannot read the 0600 token, and a squatter on the port gets one nonce | A transport carrying peer identity: `AF_VSOCK` with a guest-side allow-list, or `SO_PEERCRED` over `AF_UNIX`. Closes the gap that any Windows process running as the same user can read the token exactly as the bridge does |
| No mount namespace for the workload | The deny-list names inodes; the privilege drop carries the rest | `unshare(CLONE_NEWNS)` and `pivot_root` in the same `pre_exec` closure; then `readOnlyFs` and the overlay in [`cow.rs`](../native/splat-agent/src/cow.rs) stop being refusals. P2 of the plan |
| Maps and programs die with the daemon | Simple ownership; nothing to clean in `/sys/fs/bpf` | Pinned maps under `/sys/fs/bpf/splat`, so a daemon restart re-attaches instead of unpolicing. Today the daemon compensates by **killing** every leftover lease at startup and on SIGTERM |
| Violations fan out through a 128-slot broadcast channel | A lease's forwarder tolerates lagging and says so | A per-lease queue with a drop counter surfaced in the `EXIT` frame |
| A full 1 MiB ring buffer drops events, counted host-wide | 18 000 records of headroom on a machine running a handful of leases, and the count moves when it is not enough | A per-lease count, which needs the counter keyed by cgroup — another source change, another re-probe |
| One guest, one tenant | WSL2 is the developer's own VM | A dedicated guest per tenant; the lease keys cannot separate two tenants who share a kernel and a token |
| `Restart=on-failure` with a 2 s delay | A refusing daemon should be seen, not hidden behind a restart | The same, plus journal shipping — a daemon that exits `1` every two seconds is only useful if someone reads why |
| The build tree lives on `/mnt/c` | Convenient from Windows | Build in the guest's own filesystem; DrvFS is slow and every guest process can write to it, which is why `provision` hashes the daemon before it installs it |

---

## 4. Failure modes, and what the daemon does

| Condition | Behaviour | Where |
| --- | --- | --- |
| BPF programs fail to open, load or attach | Exits `1` unless `--mock-bpf` was passed | `main.rs`, startup |
| Token file missing and cannot be created; or empty | Exits `1` | `auth.rs` |
| `--workload-uid` or `--workload-gid` is 0 | Exits `1` | `main.rs` |
| A `splat_leases/mission_*` cgroup from a previous daemon | Killed and removed before serving; exits `1` if it will not drain | `cgroup.rs`, `reap_orphans` |
| SIGTERM or SIGINT | Every live lease's cgroup is killed while its policy is still installed, then exit `0` | `main.rs` |
| A controller missing from `/sys/fs/cgroup/cgroup.controllers` | The request is refused and names the controller | `cgroup.rs` |
| A clamp reads back looser than requested | The request is refused; the cgroup is removed | `cgroup.rs` |
| A map write fails partway through a lease | The partial write is rolled back and the request refused | `lease.rs` |
| A protected path does not resolve | The request is refused — a missing deny entry fails open | `lease.rs` |
| The client disconnects mid-run | The cgroup is killed, then the lease withdrawn | `main.rs` |
| The lease expires with the workload running | Killed inside the policy, then withdrawn; a tree that will not drain keeps its policy and is retried every second | `main.rs`, reaper |
| The ring buffer poll returns an error | Logged; polling continues. It used to end the drain thread silently | `main.rs` |
| The ring buffer is full when a denial happens | The `-EPERM` still happens; the record is dropped, its sequence number is skipped, the program's drop counter moves, and the lease's `EXIT` frame reports how far it moved | `lease_lsm.bpf.c`, `main.rs` |
| A leased process connects with an AF_INET address shorter than `sockaddr_in` | Refused with a violation of detail `0` rather than judged on bytes past the caller's buffer | `lease_lsm.bpf.c` |
| A tool prints a line longer than 64 KiB | Forwarded in 64 KiB frames, never buffered whole | `main.rs`, `pump_output` |
| A request frame over 1 MiB | Refused; connection closed | `main.rs`, `read_frame` |
| A request of unknown `type` | Refused with a `STDERR` frame naming the type; the connection stays open | `main.rs` |
| A tool's output exceeds 4 MiB per stream | The bridge keeps the first 4 MiB and marks the result `[OUTPUT_TRUNCATED]`; streaming consumers still receive everything | `WslLeasedExecutor.cs` |
