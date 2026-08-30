#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export EXTRA_CFLAGS="-Wno-error"
export CFLAGS="-Wno-error"
export CARGO_TARGET_DIR="/tmp/splat_agent_target"
touch build.rs src/bpf/lease_lsm.bpf.c
cargo build --release

# Bind loopback only. The Windows host reaches this via WSL2 localhost-forwarding; 0.0.0.0 would
# expose the leased-execution RPC on the guest's network (and the LAN in mirrored-networking mode).
echo "== Starting SPLAT Resident eBPF Daemon on 127.0.0.1:50051 =="
sudo /tmp/splat_agent_target/release/splat-agent --listen 127.0.0.1:50051