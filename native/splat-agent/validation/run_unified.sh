#!/usr/bin/env bash
# One apparatus, two experiments: the root lifecycle probe and experiment 8.4.2, on the SAME staged
# daemon binary, in one guest, into one bundle. Run as root in the run guest:
#   bash run_unified.sh <staging-dir> <bundle-dir> [blocks]
# The probe starts the daemon without --admission-gate, so it measures the unchanged admission path of
# the very binary the gate experiment then runs with the flag.
set -uo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$1"; BUNDLE="$2"; BLOCKS="${3:-3}"
PROBE_BIN=/opt/splat-probe/splat-agent
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ ! -e "$BUNDLE" ] || { echo "$BUNDLE exists" >&2; exit 2; }
(cd "$STAGE" && sha256sum -c --quiet SHA256SUMS) || { echo "staged files do not match SHA256SUMS" >&2; exit 2; }

# The hook must be ours alone before either experiment: WSL distros share one kernel.
lsm_links=$(bpftool -j link show | python3 -c 'import json,sys;print(sum(1 for l in json.load(sys.stdin) if l.get("attach_type")=="lsm_mac"))')
[ "$lsm_links" = 0 ] || { echo "refusing: $lsm_links LSM link(s) already attached in the shared kernel" >&2; bpftool link show >&2; exit 3; }
mkdir -p "$BUNDLE/probe"
cp "$STAGE/build.json" "$STAGE/SHA256SUMS" "$BUNDLE/"
mountpoint -q /sys/fs/bpf || { mount -t bpf bpffs /sys/fs/bpf; echo mounted > "$BUNDLE/probe/bpffs-mounted-by-driver"; }
pins_before=$( [ -e /sys/fs/bpf/splat ] && echo yes || echo no )
[ "$pins_before" = no ] || { echo "refusing: /sys/fs/bpf/splat already exists" >&2; exit 3; }

# 1. Root lifecycle probe. It owns the daemon (SIGKILL, restart, expiry with no daemon) and keeps pins.
install -d -m 0755 /opt/splat-probe && install -m 0755 "$STAGE/splat-agent" "$PROBE_BIN"
(cd "$CRATE" && SPLAT_PROBE_DAEMON="$PROBE_BIN" SPLAT_EVIDENCE_DIR="$BUNDLE/probe" bash probe-daemon.sh 127.0.0.1:50051) \
    > "$BUNDLE/probe/console.txt" 2>&1
echo "probe exit=$?" | tee -a "$BUNDLE/probe/console.txt"
pgrep -af "$PROBE_BIN" && { echo "probe left its daemon running" >&2; exit 4; }
# This run made the pins (none existed before it), so this run retires them.
bpftool link show > "$BUNDLE/probe/links-after-probe.txt"
rm -rf /sys/fs/bpf/splat /opt/splat-probe
[ -f "$BUNDLE/probe/bpffs-mounted-by-driver" ] && umount /sys/fs/bpf

# 2. Experiment 8.4.2 on the same staged binary (the harness installs it under its own path).
python3 -I "$STAGE/run_842.py" "$STAGE" "$BUNDLE/842" --blocks "$BLOCKS" > "$BUNDLE/842-console.txt" 2>&1
echo "842 exit=$?" | tee -a "$BUNDLE/842-console.txt"
mv "$BUNDLE/842-console.txt" "$BUNDLE/842/console.txt"

# 3. One identity across both: the binary each experiment says it ran, and the program each loaded.
python3 -I - "$BUNDLE" <<'PY'
import glob, json, os, sys
b = sys.argv[1]
staged = dict(reversed(l.split()) for l in open(f"{b}/SHA256SUMS").read().splitlines())["splat-agent"]
probe = json.load(open(sorted(glob.glob(f"{b}/probe/daemon-probe*.json"))[0]))  # PASS file sorts before INCOMPLETE
m = json.load(open(f"{b}/842/manifest.json"))
probe_bin = probe.get("daemon_binary_sha256") or probe.get("root_feature_observations", {}).get("daemon_binary_sha256")
tags = sorted({p["tag"] for p in m["deployment"]["programs"] if p["name"] == "splat_bprm_check"})
out = {"stagedDaemonSha256": staged, "probeDaemonSha256": probe_bin, "harnessDaemonSha256": m["stagedSha256"]["splat-agent"],
       "sameBinary": staged == probe_bin == m["stagedSha256"]["splat-agent"],
       "bpfSourceSha256": {"build": json.load(open(f"{b}/build.json"))["bpfSourceSha256"], "probe": probe["bpf_source_sha256"]},
       "harnessExecProgramTags": tags, "commit": json.load(open(f"{b}/build.json"))["commit"],
       "probeVerdict": probe.get("verdict"), "harnessVerdict": m["verdict"]}
out["sameSource"] = out["bpfSourceSha256"]["build"] == out["bpfSourceSha256"]["probe"]
out["verdict"] = "PASS" if out["sameBinary"] and out["sameSource"] and out["probeVerdict"] == "PASS" and out["harnessVerdict"] == "PASS" else "FAIL"
json.dump(out, open(f"{b}/unified.json", "w"), indent=2)
print(json.dumps(out, indent=2))
PY
