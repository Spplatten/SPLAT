#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export EXTRA_CFLAGS="-Wno-error"
export CFLAGS="-Wno-error"
# Not /tmp: the guest's /tmp is world-writable, so another user could create this directory before
# the first build and own the binary that `sudo` runs below.
export CARGO_TARGET_DIR="$HOME/.cache/splat-agent-target"
touch build.rs src/bpf/lease_lsm.bpf.c
cargo build --release

# Bind loopback only. The Windows host reaches this via WSL2 localhost-forwarding; 0.0.0.0 would
# expose the leased-execution RPC on the guest's network (and the LAN in mirrored-networking mode).
echo "== Starting SPLAT Resident eBPF Daemon on 127.0.0.1:50051 =="
sudo "$CARGO_TARGET_DIR/release/splat-agent" --listen 127.0.0.1:50051