# SPLAT kernel canary (`-EPERM` proof)

The smallest honest artifact that proves SPLAT's core thesis: **an agent process that
steps outside its declared capability lease is stopped by the Linux kernel with `-EPERM`,
not by a user-space filter it could bypass.** This is the seed of Layer 3 in the
architecture; everything else in the pitch is scaffolding around this one guarantee.

## What it actually demonstrates

A BPF-LSM program ([`src/bpf/lease_lsm.bpf.c`](src/bpf/lease_lsm.bpf.c)) attaches to three
kernel hooks and enforces a per-cgroup lease:

| Hook | Policy for a leased cgroup | Canary probe | Expected |
|------|----------------------------|--------------|----------|
| `bprm_check_security` | exec only allow-listed inodes | `/bin/ls /` | `-EPERM` |
| `file_open` | never open a protected inode | `cat /etc/shadow` | `-EPERM` |
| `socket_connect` | egress only to allow-listed IPv4 | `curl 1.1.1.1` | `-EPERM` |
| `socket_connect` | approved target passes | `curl 127.0.0.1` | permitted |

Only processes whose cgroup id is in the lease map are policed. The host and every other
workload are untouched — that is the "blast radius, not detection" framing.

## Honest boundaries (read before demoing)

- **Inode identity, not path strings.** Full-path resolution in BPF is racy (TOCTOU) and
  slow, so the policy matches `(dev, ino)`. That is the defensible primitive and what the
  pitch's "inode write attempts" line should mean.
- **Containment, not injection-proofing.** If a task's lease *allows* `api.github.com`, an
  injected agent can still exfiltrate *there*. The kernel bounds the blast radius; it does
  not detect that the agent was hijacked. Caption demos accordingly.
- **Not yet compiled here.** These files were authored before WSL was installed on this
  machine. Nothing in this directory has been run. The **first real verification is
  `preflight.sh` followed by `run-canary.sh`** — treat any claim of "it works" as unproven
  until you see the `-EPERM` lines yourself.
- **libbpf-rs 0.24 API.** The Rust loader and `build.rs` target that version; the skeleton,
  map, and ringbuf call shapes drift between releases. If the build errors in `main.rs`,
  reconcile against your installed `libbpf-rs` version first.

## Run order

```bash
# 0. sanitize line endings if git handed you CRLF (Windows checkout)
sed -i 's/\r$//' *.sh

# 1. is this kernel even capable? (GREEN / YELLOW / RED verdict)
bash preflight.sh

# 2. one-time toolchain + generate vmlinux.h from live BTF
bash setup-guest.sh

# 3. build + fire the canary
bash run-canary.sh
```

If `preflight.sh` prints `[FIX]` lines, apply the matching stanza from
[`wslconfig.sample`](wslconfig.sample) (LSM list and/or cgroup v2), `wsl --shutdown`, and
re-run. A `RED` verdict (no `CONFIG_BPF_LSM`) means this kernel cannot host the substrate at all:
nothing downstream works until it is replaced, and what the substrate does and does not enforce once
it can load is enumerated in
[`native/splat-agent/SUPPORTED_POLICY.md`](../splat-agent/SUPPORTED_POLICY.md).

## Where this goes next

This single-shot loader is the embryo of the Layer-2 Rust daemon. The plan doc covers the
path from here to leases over vsock/gRPC, kernel-keyring-gated capabilities, CoW rollback,
and the tool-contract → policy compiler.
