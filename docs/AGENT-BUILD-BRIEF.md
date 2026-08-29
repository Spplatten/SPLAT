# SPLAT — agent build brief (seed prompt for a fresh session)

Paste this into a new builder session to work on the SPLAT kernel substrate. It is written to
be **legible and honest**, not to evade review: the work below is ordinary systems programming
for a *defensive* containment tool, and every genuinely sensitive step is delegated to the
human operator rather than attempted. If a step here is refused, the fix is clearer framing or
operator hand-off — never obfuscation, payload-splitting, or "test mode" claims.

---

## Context (this is true; state it plainly)

SPLAT is a **local-first, defensive** execution substrate that *contains* AI agents. The eBPF
layer **denies** actions (it is an airbag, not a weapon): a BPF-LSM policy returns `-EPERM`
when a leased process steps outside a declared capability lease. The goal is to *shrink the
blast radius* of a hallucinating or prompt-injected agent — the opposite of building an
exploit. Work happens on the operator's **own machine and own repository, with authorization**.
Nothing exfiltrates data; canary payloads are benign probes that are *expected to fail*.

Repo: `C:\C_AGENT_BUILDER` (Windows/.NET control plane). Seams already exist in
`src/MissionController.Core/Interfaces.cs`. The `-EPERM` canary lives in
`native/splat-canary/`. The full phase plan is `docs/PLAN-kernel-substrate.md`.

## Ground truth already established (do not re-derive)

- **Kernel is capable — no fork.** Shipped WSL2 kernel (WSL 2.7.12.0, 6.18.33.2-2) has
  `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_OVERLAY_FS=y`,
  `CONFIG_HYPERV_VSOCKETS=y`, `CONFIG_CGROUP_BPF=y`. Only gap: `bpf` was absent from the active
  `lsm=` list; already fixed via `%USERPROFILE%\.wslconfig` `kernelCommandLine`.
- **libbpf-rs 0.24 API facts** (verified against docs.rs): `SkeletonBuilder::clang_args` takes
  `IntoIterator<Item: AsRef<OsStr>>`; `MapCore` must be in scope for
  `update(&[u8], &[u8], MapFlags)`; `RingBufferBuilder::add(&dyn MapCore, FnMut(&[u8]) -> i32)`
  then `.build()` then `.poll(Duration)`; skeleton `open(&mut MaybeUninit<OpenObject>)` → `load`
  → `attach`. **Unconfirmed:** the generated `skel.maps.<name>` field form — verify against the
  installed version's generated skeleton on first `cargo build`.

## Scope of THIS build (all normal systems programming)

Advance the plan's software phases; see `docs/PLAN-kernel-substrate.md` for DoD per phase.
1. **Layer-2 Rust daemon** — promote the single-shot canary loader to a resident `tokio`
   service holding multiple per-cgroup leases (issue → enforce → expire), seconds-scoped and
   single-use. Structured violation stream out.
2. **Transport** — `tonic` gRPC over `AF_VSOCK`, host↔guest. Define the `.proto`.
3. **C# seam** — add `ILeasedExecutor` to `Interfaces.cs` and `WslLeasedExecutor` (vsock/gRPC
   client) in a new `MissionController.Infrastructure.Linux`. Do **not** overload
   `IProcessLauncher` (its signature is Windows job-object shaped).
4. **CoW rollback** — OverlayFS scratch layer per mission (confirmed built-in), discard on
   failure.
5. **Contract → policy compiler** — compile a governed template's declared files/egress/exec
   into the lease maps, so the kernel enforces exactly what the template promised.

## Human-only steps — STOP and ask the operator (do not attempt)

These are delegated by design, not blocked by trickery:
- Installing WSL or a Linux distribution; downloading rootfs/images.
- Entering any password, creating any account (incl. distro OOBE).
- Editing `.wslconfig` / `wsl.conf` kernel command line; `wsl --shutdown`.
- Anything needing Windows elevation or that changes system/security settings.

For distro-less setup the operator can run `wsl --install -d Ubuntu --no-launch`; afterward an
agent may drive the guest **as root** (`wsl -d Ubuntu -u root`) with no password — that is the
clean path to build and run the canary without a credential step.

## Working agreements

- **Verify before asserting.** Never claim a build/test passed without running it; show real
  output. The Rust/eBPF has not yet compiled on this machine — treat it as unverified until
  `native/splat-canary/run-canary.sh` prints `-EPERM`.
- **Minimal diffs**, match surrounding style, comment the *why*.
- **Benign canaries only.** No real exploits, no data exfiltration, no detection-evasion. The
  point is to demonstrate the boundary holding.
- Replace marketing numbers (e.g. `<1ms` vsock) with **measured** p50/p99 once real.
