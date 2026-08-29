#!/usr/bin/env bash
# One-time build-toolchain setup inside the WSL2 guest. Safe to re-run.
# Installs clang/libbpf/bpftool + Rust, then generates src/bpf/vmlinux.h from live BTF.
set -euo pipefail
cd "$(dirname "$0")"

export DEBIAN_FRONTEND=noninteractive

echo "== apt: build toolchain =="
apt-get update -y
apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential \
  linux-tools-common bpftool || \
apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential bpftool || true

echo "== rust toolchain =="
if ! command -v cargo >/dev/null 2>&1 && [ ! -f "$HOME/.cargo/bin/cargo" ] && [ ! -f "/root/.cargo/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
elif [ -f "/root/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "/root/.cargo/env"
fi

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

echo "== generate vmlinux.h from live BTF =="
if [ -r /sys/kernel/btf/vmlinux ]; then
  mkdir -p src/bpf
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
  echo "  wrote splat-canary src/bpf/vmlinux.h ($(wc -l < src/bpf/vmlinux.h) lines)"

  if [ -d "../splat-agent" ]; then
    mkdir -p ../splat-agent/src/bpf
    cp src/bpf/vmlinux.h ../splat-agent/src/bpf/vmlinux.h
    echo "  synced vmlinux.h to splat-agent"
  fi
else
  echo "  !! /sys/kernel/btf/vmlinux missing — this kernel has no runtime BTF."
  exit 2
fi

echo "== cargo version =="
cargo --version

echo "== done. next: bash run-canary.sh =="

