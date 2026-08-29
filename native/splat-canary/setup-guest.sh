#!/usr/bin/env bash
# One-time build-toolchain setup inside the WSL2 guest. Safe to re-run.
# Installs clang/libbpf/bpftool + Rust, then generates src/bpf/vmlinux.h from the live BTF.
set -euo pipefail
cd "$(dirname "$0")"

echo "== apt: build toolchain =="
sudo apt-get update
# linux-tools gives bpftool; libbpf-dev + clang build the BPF object; the rest are libbpf-rs deps.
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential \
  linux-tools-common linux-tools-generic bpftool || \
  sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential bpftool

echo "== rust toolchain =="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

echo "== generate vmlinux.h from live BTF =="
if [ -r /sys/kernel/btf/vmlinux ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
  echo "  wrote src/bpf/vmlinux.h ($(wc -l < src/bpf/vmlinux.h) lines)"
else
  echo "  !! /sys/kernel/btf/vmlinux missing — this kernel has no runtime BTF."
  echo "     Fetch a matching BTF from BTFHub, or build a CONFIG_DEBUG_INFO_BTF=y kernel."
  echo "     See docs/PLAN-kernel-substrate.md, Phase 0."
  exit 2
fi

echo "== done. next: bash run-canary.sh =="
