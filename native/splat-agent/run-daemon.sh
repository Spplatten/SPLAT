#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export EXTRA_CFLAGS="-Wno-error"
export CFLAGS="-Wno-error"
export CARGO_TARGET_DIR="/tmp/splat_agent_target"
touch build.rs src/bpf/lease_lsm.bpf.c
cargo build --release

echo "== Starting SPLAT Resident eBPF Daemon on 0.0.0.0:50051 =="
sudo /tmp/splat_agent_target/release/splat-agent --listen 0.0.0.0:50051