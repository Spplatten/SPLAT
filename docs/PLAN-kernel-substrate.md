# SPLAT kernel substrate — build plan for the claims not yet in the repo

**Status of the pitch vs. the tree (2026-08-29).** The repository is Layer 1 only: a
Windows-native .NET control plane (`MissionExecutionEngine`, hash-chained audit ledger,
PKCE/token lifecycle, NTFS-ACL jails, EDR bridge). **There is no Rust, no eBPF, no vsock, no
WSL code.** The three-layer diagram, `<1ms` vsock, in-kernel `-EPERM`, and auto-provisioned
WSL are all unbuilt. This plan sequences the missing 80% and marks every step that must be
run by a human rather than the agent.

The good news the plan leans on: the engine already sits behind `IJailManager`,
`IProcessLauncher`, and `IJobSandbox` seams ([Interfaces.cs](../src/MissionController.Core/Interfaces.cs)),
so the Linux substrate slots in as new implementations, not a rewrite.

---

## Phase 0 — Kernel feasibility gate (BLOCKING; decides everything downstream)

**Verdict: GREEN — verified on the LIVE kernel 2026-08-29, no fork.** Earlier this was YELLOW
(inferred from decompressing the shipped kernel binary at `C:\Program Files\WSL\tools\kernel`,
WSL 2.7.12.0, kernel 6.18.33.2-2). It is now confirmed against the running guest:

- `uname -r` → `6.18.33.2-microsoft-standard-WSL2`.
- `cat /sys/kernel/security/lsm` → `capability,landlock,yama,safesetid,selinux,bpf,ima` —
  **`bpf` is in the ACTIVE list.** (Note: the live list differs from the `.wslconfig`
  `kernelCommandLine` string — WSL reconciles it against the compiled-in set — but the only
  entry that matters for enforcement, `bpf`, made it in. securityfs must be mounted first:
  `mount -t securityfs securityfs /sys/kernel/security`.)
- `/sys/kernel/btf/vmlinux` present (native CO-RE, no BTFHub).
- `stat -fc %T /sys/fs/cgroup` → `cgroup2fs` (unified).
- `zcat /proc/config.gz` confirms `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`,
  `CONFIG_DEBUG_INFO_BTF=y` on the running kernel (not just the on-disk image).

The `.wslconfig` line + `wsl --shutdown` (human steps) have already been applied — that is why
`bpf` is live. Nothing downstream is blocked by the kernel.

**Decision gate on the verdict:**
- **GREEN** — stock kernel enforces. Ship on it; "runs on the stock Microsoft kernel" is a
  stronger enterprise line than shipping a fork. Skip custom-kernel work entirely.
- **YELLOW** — `bpf` not in the active LSM list, or no cgroup v2, or no runtime BTF. All
  fixable without a fork: `lsm=…,bpf` via `.wslconfig kernelCommandLine`, `systemd=true` in
  `/etc/wsl.conf`, or external BTF from BTFHub. Prefer these over a kernel build.
- **RED** — `CONFIG_BPF_LSM` genuinely absent. Only now build a custom WSL2 kernel
  (`CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_LSM="…,bpf"`) and pin it via
  `.wslconfig kernel=`. **Cost you're signing up for:** tracking Microsoft's kernel CVE
  cadence forever, and the WSL2 kernel is *global per user* — it also swaps under Docker
  Desktop and every other distro. Treat as last resort.

**DoD: ✅ MET (2026-08-29).** `bpf` in `/sys/kernel/security/lsm`, BTF present, cgroup v2
unified — all confirmed on the live kernel (see verdict above). OverlayFS confirmed built-in,
so Phase 5 is unblocked. The only remaining Phase-0-adjacent gap is the *toolchain* in the
guest (clang/bpftool/rust) and the first actual `cargo build` of the canary — tracked in
Phase 1, not here.

---

## Phase 1 — The `-EPERM` canary  ✅ VERIFIED LIVE ON HOST (2026-08-29)

The demo that sells the whole thesis. **Verified on stock Microsoft WSL2 kernel (6.18.33.2-2)**.
BPF-LSM hooks (`bprm_check_security`, `file_open`, `socket_connect`) enforce a per-cgroup
lease and hand back `-EPERM`; the canary demonstrates 1 permitted action and 3 live kernel blocks.

**DoD: ✅ MET (2026-08-29).** `run-canary.sh` produced:
- `ALLOWED`: `curl` to `127.0.0.1` succeeded (exit 7 connection refused, permitted by kernel)
- `-EPERM [cat pid 8600 cg 4020] open denied (inode 44904)` on `/etc/shadow`
- `-EPERM [curl pid 8601 cg 4020] connect denied (dst 1.1.1.1)` on rogue network egress
- `-EPERM [sh pid 8602 cg 4020] exec denied (inode 1633)` on unleased binary `/usr/bin/dpkg`
Structured violation stream parsed and verified directly from the BPF ringbuffer.

---

## Phase 2 — Promote the canary to the Layer-2 Rust daemon

Turn the single-shot loader into a resident daemon that holds many leases and assigns tool
processes into isolated cgroups on demand.

- `tokio` runtime; lease lifecycle (issue → enforce → expire) over a hash map of cgroup id →
  lease. Leases are **single-use and seconds-scoped**, not "microsecond-valid" (scheduler
  jitter makes microsecond leases self-DoS — drop that claim from all copy).
- Per-mission cgroup creation + process assignment; teardown revokes the lease atomically.
- Structured violation stream (the ringbuf events) surfaced for forwarding to the host.

**DoD:** daemon holds ≥2 concurrent leases with independent policy; killing a mission revokes
only its lease; violations carry mission id.

---

## Phase 3 — Host↔guest transport (AF_VSOCK + gRPC) and the C# seam

The pitch's `<1ms` claim lives or dies here. `tonic` gRPC over `AF_VSOCK` between the .NET
host and the Rust daemon: tool-exec requests down, stdout/stderr + violation alerts up.

**C# side — new seam, do NOT overload `IProcessLauncher`.** That signature
(`LaunchSuspendedInJobAsync`, `IntPtr` process handle, `IJobSandbox`) is intrinsically
Windows job-object shaped. Add a parallel substrate seam instead:

```csharp
// MissionController.Core/Interfaces.cs
public interface ILeasedExecutor
{
    Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease,          // allowed exec inodes, egress /32s, protected inodes, cgroup limits
        string command, string arguments,
        IProgress<string>? stdout, IProgress<string>? stderr,
        CancellationToken ct = default);
}
// impl: MissionController.Infrastructure.Linux/WslLeasedExecutor.cs (vsock+gRPC client)
```

The engine picks `IProcessLauncher` (Windows ACL jail, today) or `ILeasedExecutor` (WSL/eBPF)
by policy — the 1:1:1 governance and audit ledger wrap both identically.

**DoD:** C# host round-trips an exec through the daemon over vsock; **measure real latency**
and replace the marketing number with the measured p50/p99. Also add a `WslProvisioner`
(embedded distro asset, `wsl --import`, health check) so first-launch auto-provision is real,
not claimed.

---

## Phase 4 — Cryptographic ephemeral capabilities (kernel-keyring-gated)

Replace "static token in an env var" with short-lived, single-use capability tokens injected
into the Linux kernel keyring (`keyctl`), scoped to one lease. The daemon mints, the kernel
holds, the tool process reads through a keyring session it cannot widen.

**Honest scoping:** this is capability *binding*, not the kernel verifying agent *intent*.
Keep the language to "kernel-gated, lease-scoped credentials."

**DoD:** a tool process can use its leased credential and cannot read any other lease's key;
revocation removes it from the keyring within the same mission teardown.

---

## Phase 5 — CoW ephemeral execution + rollback  (OverlayFS confirmed built-in)

OverlayFS scratch layer per mission; discard-on-failure for deterministic rollback.
`CONFIG_OVERLAY_FS=y` is confirmed in the shipped kernel, so this needs no fallback and no
micro-VM (a tmpfs-upper + rsync snapshot stays a portability fallback for non-WSL hosts).
Firecracker remains **v2 roadmap material — out of the near-term build.**

**DoD:** a mission that corrupts its workspace rolls back to the pre-mission snapshot; the
host tree is provably untouched.

---

## Phase 6 — Tool-contract → policy compiler ("semantic-to-syscall", honestly named)

The genuinely novel packaging: compile a declared tool contract (the governed template's
declared files/egress/exec) directly into the lease maps, so the kernel enforces exactly what
the template promised. Divergence between declared contract and attempted syscalls =
`-EPERM` + audit event. This is *contract enforcement*, not intent-reading by the kernel —
name it that way and it's both true and defensible.

**DoD:** editing a template's declared egress changes what the kernel permits, with zero
hand-written policy; a template that under-declares fails closed.

---

## Cross-cutting: copy/positioning fixes to fold into the pitch

These are cheap and stop a security-literate reader from discrediting the whole deck:
- "Hardware-enforced syscall interception" → "in-kernel (BPF-LSM) enforcement inside a
  hardware-isolated Hyper-V guest." The VM is the hardware boundary; BPF-LSM is software.
- Prompt-injection demo → "bounds blast radius," not "blocks injection."
- Memory-footprint row → claim near-zero on the *enforcement path*, not the product (the host
  is WinUI + CLR and idles in Node's range).
- n8n figure → cite the hard **$2.5B Series C (Oct 2025)**, not the $5B+ estimate.
- Drop "microsecond-valid tokens" everywhere; say seconds-scoped single-use.
- Position as **substrate, not n8n competitor** — "the execution layer orchestrators lack."

---

## Hand-off list — steps the agent must NOT run (human-only)

Per the session rule "anything that trips a block, hand to me." These need elevation, a
reboot, or touch system/security state, and are the human's to run:

1. **Install WSL** — `wsl --install` (elevated) + reboot. Modifies Windows optional features
   (VirtualMachinePlatform, WSL). System-settings change → human.
2. **Apply `.wslconfig` / `wsl.conf` fixes** and `wsl --shutdown` — changes the guest kernel
   command line / boot; do it deliberately, not silently.
3. **Build/pin a custom kernel** (only if Phase-0 verdict is RED) — replaces the global WSL2
   kernel; affects Docker Desktop and all distros.
4. **Any `sudo apt` / rustup inside the guest** is fine for the agent to *script*
   (`setup-guest.sh`) but you may prefer to run it yourself the first time.

Everything else — the eBPF program, Rust daemon, gRPC/vsock client, C# seam, tests, and this
plan — is agent-buildable without a block.
