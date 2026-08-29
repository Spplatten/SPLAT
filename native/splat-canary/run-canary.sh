#!/usr/bin/env bash
# Build + run the -EPERM canary. Run inside WSL after setup-guest.sh:  bash run-canary.sh
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
# The loader creates the cgroup, seeds the lease, forks canary.sh into it, and streams violations.
sudo /tmp/splat_canary_target/release/splat-canary \
  --cgroup "$CGROUP" \
  --protect /etc/shadow \
  --allow-connect 127.0.0.1 \
  --canary ./canary.sh

echo
echo "Expected: exactly one ALLOWED action passed, and three -EPERM lines from the kernel."
