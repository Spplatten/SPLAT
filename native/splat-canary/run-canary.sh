#!/usr/bin/env bash
# Build + run the -EPERM canary. Run inside WSL after setup-guest.sh:  bash run-canary.sh
#
# src/bpf/lease_lsm.bpf.c is a FROZEN FORK of the daemon's program at native/splat-agent. The two
# were identical until the daemon's policy maps were re-keyed by (cgroup id, resource) so that two
# concurrent leases stop receiving the union of each other's permissions (finding F06). The canary
# runs one lease at a time, so that defect never applied to it, and the primitive it proves - the
# kernel vetoes an out-of-lease exec, open and connect - is unchanged. Its source is hashed into
# the evidence below, so it is not edited casually: a comment here rather than there is deliberate.
set -euo pipefail
cd "$(dirname "$0")"

CGROUP=/sys/fs/cgroup/splat-canary

cleanup() {
  # A cgroup dir only rmdir's once empty; the loader's child has exited by now.
  [ -d "$CGROUP" ] && rmdir "$CGROUP" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -f src/bpf/vmlinux.h ]; then
  echo "src/bpf/vmlinux.h missing — run: bash setup-guest.sh" >&2
  exit 1
fi

echo "== cargo build --release =="
export EXTRA_CFLAGS="-Wno-error"
export CFLAGS="-Wno-error"
export CARGO_TARGET_DIR="/tmp/splat_canary_target"
touch build.rs src/bpf/lease_lsm.bpf.c
cargo build --release

echo
echo "== running canary (sudo: BPF-LSM load needs root) =="
# Hash the BPF source so the evidence file names the exact program that produced it; proof of an
# older program must never read as proof of the current one.
BPF_SHA="$(sha256sum src/bpf/lease_lsm.bpf.c | cut -d' ' -f1)"

# The loader creates the cgroup, seeds the lease, forks canary.sh into it, streams violations,
# then asserts the outcome and writes evidence/. It exits non-zero on a bad run - this script
# no longer asks a human to eyeball whether the kernel did its job.
sudo /tmp/splat_canary_target/release/splat-canary \
  --cgroup "$CGROUP" \
  --protect /etc/shadow \
  --allow-connect 127.0.0.1 \
  --canary ./canary.sh \
  --bpf-sha "$BPF_SHA" \
  --evidence-dir ./evidence
status=$?

echo
if [ "$status" -eq 0 ]; then
  echo "PASS — evidence written to evidence/. Commit it."
else
  echo "FAIL (exit $status) — see the VERDICT lines above. The evidence file records why."
fi
exit "$status"
