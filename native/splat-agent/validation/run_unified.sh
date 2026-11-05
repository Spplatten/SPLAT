#!/usr/bin/env bash
# One apparatus, three experiments: the root lifecycle probe (with its expiry series) and experiments
# 8.4.2 and 8.4.3, on the SAME staged daemon binary, in one guest, into one bundle. Run as root:
#   bash run_unified.sh <staging-dir> <bundle-dir> [blocks] [expiry-repeats]
# The probe starts the daemon without --admission-gate, so it measures the unchanged admission path of
# the very binary the gate experiments then run with the flag. The probe script and the BPF source it
# hashes run from the stage too, so every file the run executes is in SHA256SUMS (see PROTOCOL.md).
set -uo pipefail
STAGE="$1"; BUNDLE="$2"; BLOCKS="${3:-3}"; EXPIRY_REPEAT="${4:-1}"
PROBE_BIN=/opt/splat-probe/splat-agent
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ ! -e "$BUNDLE" ] || { echo "$BUNDLE exists" >&2; exit 2; }
(cd "$STAGE" && sha256sum -c --quiet SHA256SUMS) || { echo "staged files do not match SHA256SUMS" >&2; exit 2; }

# The hook must be ours alone before either experiment: WSL distros share one kernel.
mkdir -p "$BUNDLE/probe" || exit 2
bpftool -j link show > "$BUNDLE/preflight-lsm-links.json" || exit 3
lsm_links=$(python3 -c 'import json,sys;print(sum(1 for l in json.load(sys.stdin) if l.get("attach_type")=="lsm_mac"))' < "$BUNDLE/preflight-lsm-links.json") || exit 3
[ "$lsm_links" = 0 ] || { echo "refusing: $lsm_links LSM link(s) already attached in the shared kernel" >&2; bpftool link show >&2; exit 3; }
cp "$STAGE/build.json" "$STAGE/SHA256SUMS" "$STAGE/PROTOCOL.md" "$STAGE/AUDIT_GAP_PROTOCOL.md" "$BUNDLE/" || exit 2
mountpoint -q /sys/fs/bpf || { mount -t bpf bpffs /sys/fs/bpf; echo mounted > "$BUNDLE/probe/bpffs-mounted-by-driver"; }
pins_before=$( [ -e /sys/fs/bpf/splat ] && echo yes || echo no )
[ "$pins_before" = no ] || { echo "refusing: /sys/fs/bpf/splat already exists" >&2; exit 3; }

# 1. Root lifecycle probe. It owns the daemon (SIGKILL, restart, expiry with no daemon) and keeps pins.
install -d -m 0755 /opt/splat-probe && install -m 0755 "$STAGE/splat-agent" "$PROBE_BIN"
(cd "$STAGE" && SPLAT_PROBE_DAEMON="$PROBE_BIN" SPLAT_EVIDENCE_DIR="$BUNDLE/probe" SPLAT_PROBE_EXPIRY_REPEAT="$EXPIRY_REPEAT" \
    bash probe-daemon.sh 127.0.0.1:50051) \
    > "$BUNDLE/probe/console.txt" 2>&1
probe_status=$?
echo "probe exit=$probe_status" | tee -a "$BUNDLE/probe/console.txt"
[ "$probe_status" = 0 ] || exit "$probe_status"
pgrep -af "$PROBE_BIN" && { echo "probe left its daemon running" >&2; exit 4; }
# This run made the pins (none existed before it), so this run retires them.
bpftool link show > "$BUNDLE/probe/links-after-probe.txt"
rm -rf /sys/fs/bpf/splat /opt/splat-probe
[ -f "$BUNDLE/probe/bpffs-mounted-by-driver" ] && umount /sys/fs/bpf

# 2. Experiment 8.4.2 on the same staged binary (the harness installs it under its own path).
python3 -I "$STAGE/run_842.py" "$STAGE" "$BUNDLE/842" --blocks "$BLOCKS" > "$BUNDLE/842-console.txt" 2>&1
harness_status=$?
echo "842 exit=$harness_status" | tee -a "$BUNDLE/842-console.txt"
[ "$harness_status" = 0 ] || exit "$harness_status"
mv "$BUNDLE/842-console.txt" "$BUNDLE/842/console.txt"

# 3. Experiment 8.4.3, same binary again, including its two research-fault daemon phases.
python3 -I "$STAGE/run_843.py" "$STAGE" "$BUNDLE/843" --blocks "$BLOCKS" > "$BUNDLE/843-console.txt" 2>&1
harness_status=$?
echo "843 exit=$harness_status" | tee -a "$BUNDLE/843-console.txt"
[ "$harness_status" = 0 ] || exit "$harness_status"
mv "$BUNDLE/843-console.txt" "$BUNDLE/843/console.txt"

# 4. One identity across all three: the binary each experiment says it ran, and the program each loaded.
python3 -I - "$BUNDLE" <<'PY'
import glob, json, os, sys
b = sys.argv[1]
staged = dict(reversed(l.split()) for l in open(f"{b}/SHA256SUMS").read().splitlines())["splat-agent"]
probe = json.load(open(sorted(glob.glob(f"{b}/probe/daemon-probe*.json"))[0]))  # PASS file sorts before INCOMPLETE
m = json.load(open(f"{b}/842/manifest.json"))
m3 = json.load(open(f"{b}/843/manifest.json")) if os.path.exists(f"{b}/843/manifest.json") else {}
probe_bin = probe.get("daemon_binary_sha256") or probe.get("root_feature_observations", {}).get("daemon_binary_sha256")
tags = sorted({p["tag"] for p in m["deployment"]["programs"] if p["name"] == "splat_bprm_check"})
out = {"stagedDaemonSha256": staged, "probeDaemonSha256": probe_bin, "harnessDaemonSha256": m["stagedSha256"]["splat-agent"],
       "harness843DaemonSha256": m3.get("stagedSha256", {}).get("splat-agent"),
       "sameBinary": staged == probe_bin == m["stagedSha256"]["splat-agent"] == m3.get("stagedSha256", {}).get("splat-agent"),
       "bpfSourceSha256": {"build": json.load(open(f"{b}/build.json"))["bpfSourceSha256"], "probe": probe["bpf_source_sha256"]},
       "harnessExecProgramTags": tags, "commit": json.load(open(f"{b}/build.json"))["commit"],
       "probeVerdict": probe.get("verdict"), "harnessVerdict": m["verdict"], "harness843Verdict": m3.get("verdict")}
out["sameSource"] = out["bpfSourceSha256"]["build"] == out["bpfSourceSha256"]["probe"]
out["verdict"] = "PASS" if out["sameBinary"] and out["sameSource"] and out["probeVerdict"] == "PASS" \
    and out["harnessVerdict"] == "PASS" and out["harness843Verdict"] == "PASS" else "FAIL"
json.dump(out, open(f"{b}/unified.json", "w"), indent=2)
print(json.dumps(out, indent=2))
sys.exit(0 if out["verdict"] == "PASS" else 1)
PY
