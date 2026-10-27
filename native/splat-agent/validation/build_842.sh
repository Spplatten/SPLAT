#!/usr/bin/env bash
# Build everything experiment 8.4.2 runs, from one committed tree, into a staging directory.
# Run in the build guest (it has cargo/clang/gcc); the run guest only needs python3 and bpftool.
#   bash build_842.sh <staging-dir>
set -euo pipefail
cd "$(dirname "$0")/.."
STAGE="$1"
[ -z "$(git status --porcelain -- . )" ] || { echo "refusing: native/splat-agent has uncommitted changes" >&2; exit 2; }
source "$HOME/.cargo/env"
export EXTRA_CFLAGS="-Wno-error" CFLAGS="-Wno-error"
export CARGO_TARGET_DIR="$HOME/.cache/splat-exp-842-target"
touch build.rs src/bpf/lease_lsm.bpf.c
cargo build --release --locked
mkdir -p "$STAGE"
cp "$CARGO_TARGET_DIR/release/splat-agent" "$STAGE/splat-agent"
gcc -static -O2 -o "$STAGE/a" validation/workload_a.c
gcc -static -O2 -o "$STAGE/x" validation/workload_x.c
gcc -static -O2 -o "$STAGE/p" validation/workload_p.c
cp validation/gate.py validation/run_842.py validation/run_843.py validation/profile.json validation/run_unified.sh \
   validation/PROTOCOL.md probe-daemon.sh "$STAGE/"
# The probe hashes the BPF source relative to its cwd; staging it makes the stage the whole apparatus.
mkdir -p "$STAGE/src/bpf" && cp src/bpf/lease_lsm.bpf.c "$STAGE/src/bpf/"
{
  echo "{"
  echo "  \"commit\": \"$(git rev-parse HEAD)\","
  echo "  \"bpfSourceSha256\": \"$(sha256sum src/bpf/lease_lsm.bpf.c | cut -d' ' -f1)\","
  echo "  \"buildHost\": \"$(uname -r) / $(. /etc/os-release; echo "$PRETTY_NAME")\","
  echo "  \"rustc\": \"$(rustc --version)\","
  echo "  \"clang\": \"$(clang --version | head -1)\","
  echo "  \"gcc\": \"$(gcc --version | head -1)\""
  echo "}"
} > "$STAGE/build.json"
(cd "$STAGE" && sha256sum splat-agent a x p gate.py run_842.py run_843.py profile.json run_unified.sh \
    PROTOCOL.md probe-daemon.sh src/bpf/lease_lsm.bpf.c > SHA256SUMS)
cat "$STAGE/build.json" "$STAGE/SHA256SUMS"
