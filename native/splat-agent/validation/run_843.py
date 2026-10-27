#!/usr/bin/python3 -I
"""Run thesis experiment 8.4.3 in the run guest, as root, from a directory staged by build_842.sh.

    python3 -I run_843.py <staging-dir> <bundle-dir> [--blocks N] [--seed S]

The mutations of 8.4.3, each against the variants it is meant to separate, with the same three
independent channels as 8.4.2 (daemon frames, gate record, ftrace launches). The daemon runs in four
phases because two of the mutations are a property of the writer, not of one request:

    normal      correct controls; a missing protection; a write that ignores the daemon's lock,
                between the gate's capture passes or after its decision
    identity    --research-fault dev-encoding: every key built with the userspace st_dev
    binding     --research-fault decoy-exec-map: exec grants written to a map no program reads
    baseline    no admission gate at all, for the cost pilot

Every expectation below is written before any run is seen. A mutation that did not take effect
(the setup check) is reported as invalid setup, never as a detection.
"""
import argparse
import importlib.util
import json
import os
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location("run_842", os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_842.py"))
r842 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r842)

OPT, LIBEXEC, ETC, STATE, TRACE = r842.OPT, r842.LIBEXEC, r842.ETC, r842.STATE, r842.TRACE
HOST, PORT, A, X = r842.HOST, r842.PORT, r842.A, r842.X
P = f"{LIBEXEC}/p"
TARGET = "/etc/splat-842-target"  # under /etc: the jail shows /etc read-only and hides /var
GATE = f"{OPT}/gate.py"
LEASE_SECONDS = r842.LEASE_SECONDS
ALWAYS_PROTECTED = ["/etc/shadow", "/etc/sudoers"]  # the daemon adds both to every lease

PHASES = [
    ("normal", ["--admission-gate", GATE],
     [("correct", "B2"), ("correct", "B2W"), ("correct", "B3"),
      ("protected-correct", "B2"), ("protected-correct", "B3"),
      ("protected-missing", "B2"), ("protected-missing", "B3"),
      ("midwrite-between", "B2"), ("midwrite-between", "B3"),
      ("midwrite-after", "B2"), ("midwrite-after", "B3")]),
    ("identity", ["--admission-gate", GATE, "--research-fault", "dev-encoding"],
     [("identity-wrong", "B2"), ("identity-wrong", "B3")]),
    ("binding", ["--admission-gate", GATE, "--research-fault", "decoy-exec-map"],
     [("binding-decoy", "B2"), ("binding-decoy", "B2W"), ("binding-decoy", "B3")]),
]
BASELINE_PER_BLOCK = 3


def expected(policy, variant):
    """What each run must show. None means the field is not asserted (stated, not guessed)."""
    refused = {"admitted": False, "aExec": False, "xExec": False, "launched": [GATE], "exitCode": -1, "gateDecision": "reject"}
    if policy == "correct":
        return {"admitted": True, "aExec": True, "xExec": False, "launched": [GATE, A], "exitCode": 10, "gateDecision": "admit"}
    if policy == "protected-correct":
        return {"admitted": True, "aExec": False, "xExec": False, "launched": [GATE, P], "exitCode": 13, "gateDecision": "admit"}
    if policy == "protected-missing":
        # B2 sees bytes equal to the writer's, which omitted the protection: P opens the file.
        if variant == "B2":
            return {"admitted": True, "aExec": False, "xExec": False, "launched": [GATE, P], "exitCode": 0, "gateDecision": "admit"}
        return refused
    if policy == "midwrite-between":
        return dict(refused, gateDecision="indeterminate")
    if policy == "midwrite-after":
        # The documented boundary: a write that lands after the decision is invisible to every variant.
        return {"admitted": True, "aExec": True, "xExec": True, "launched": [GATE, A, X], "exitCode": 0, "gateDecision": "admit"}
    if policy == "identity-wrong":
        if variant == "B2":
            # Admitted, and then the kernel refuses A itself: safe, and useless.
            return {"admitted": True, "aExec": False, "xExec": False, "launched": [GATE], "exitCode": None, "gateDecision": "admit"}
        return refused
    if policy == "binding-decoy":
        if variant == "B2W":
            return {"admitted": True, "aExec": False, "xExec": False, "launched": [GATE], "exitCode": None, "gateDecision": "admit"}
        return refused
    raise ValueError(policy)


def effect(policy, observed):
    """The behavioural consequence, which is what false acceptance and usefulness are judged on."""
    if not observed["admitted"]:
        return "refused"
    if observed["xExec"] or (policy.startswith("protected") and observed["exitCode"] == 0):
        return "contract-violated"
    approved = P if policy.startswith("protected") else A
    return "useful" if approved in observed["launched"] else "not-useful"


def setup_valid(policy, gate):
    """Did the mutation take effect? Checked from the gate's record, not assumed."""
    if not gate:
        return True  # no record is an observation failure, classified elsewhere
    written = gate.get("written") or {}
    if policy == "identity-wrong":
        key = bytes.fromhex((written.get("allowedExec") or ["00" * 24])[0])
        st = os.stat(A)
        return int.from_bytes(key[16:20], "little") != ((os.major(st.st_dev) << 20) | os.minor(st.st_dev))
    if policy == "binding-decoy":
        ids = written.get("writerMapIds") or {}
        maps = (gate.get("deployment") or {}).get("maps") or {}
        return "allowed_exec" not in maps or ids.get("allowedExec") != maps["allowed_exec"].get("id")
    if policy.startswith("midwrite"):
        return bool(gate.get("injection")) or gate.get("decision") == "indeterminate"
    return True


def classify(valid, complete, observed, want, gate):
    if not valid:
        return "invalid-setup"
    if not complete:
        return "indeterminate-observation"
    decision = (gate or {}).get("decision")
    if decision == "indeterminate" and want["gateDecision"] != "indeterminate":
        return "indeterminate-refused" if observed["launched"] == [GATE] else "indeterminate-unsafe"
    matches = decision == want["gateDecision"] and all(
        observed.get(k) == v for k, v in want.items() if k != "gateDecision" and v is not None)
    return "as-expected" if matches else "unexpected"


def start_daemon(bundle, phase, extra):
    log = open(f"{bundle}/daemon-{phase}.log", "w")
    proc = subprocess.Popen([f"{OPT}/splat-agent", "--listen", f"{HOST}:{PORT}",
                             "--auth-token-file", f"{ETC}/agent.token", "--outcome-key-file", f"{ETC}/outcome.key",
                             "--receipt-root", f"{STATE}/receipts", *extra],
                            stdout=log, stderr=subprocess.STDOUT, env={"RUST_LOG": "info", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"daemon ({phase}) exited with {proc.returncode}; see daemon-{phase}.log")
        try:
            socket.create_connection((HOST, PORT), timeout=1).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"daemon ({phase}) never listened")


def stop_daemon(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return proc.returncode


def trace_teardown(bundle, phase):
    # One trace per phase: each phase execs the daemon once, which is how DaemonTasks finds it.
    if not os.path.exists(TRACE):
        return
    with open(f"{bundle}/trace-{phase}.txt", "w") as f:
        f.write(r842.trace_read())
    with open(f"{TRACE}/tracing_on", "w") as f:
        f.write("0")
    for event in ("sched_process_fork", "sched_process_exec"):
        with open(f"{TRACE}/events/sched/{event}/enable", "w") as f:
            f.write("0")
    os.rmdir(TRACE)


def request_for(policy, mission):
    if policy.startswith("protected"):
        return {"type": "EXECUTE_TOOL", "missionId": mission, "command": P, "argv": [], "allowedExecPaths": [P],
                "protectedPaths": [TARGET] if policy == "protected-correct" else [],
                "leaseDurationSeconds": LEASE_SECONDS}
    return {"type": "EXECUTE_TOOL", "missionId": mission, "command": A, "argv": [], "allowedExecPaths": [A],
            "leaseDurationSeconds": LEASE_SECONDS}


def approval_for(policy, mission):
    boot = open("/proc/sys/kernel/random/boot_id").read().strip()
    exe = P if policy.startswith("protected") else A
    approval = {"missionId": mission, "bootId": boot, "executables": [{"path": exe, "sha256": r842.sha256_file(exe)}],
                "leaseDurationSeconds": LEASE_SECONDS, "approvedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if policy.startswith("protected"):
        approval["protected"] = ALWAYS_PROTECTED + [TARGET]
    return approval


def run_one(token, bundle, phase, block, index, policy, variant):
    mission = f"e843-{phase}-b{block}-{index:02d}-{policy}-{variant}".lower()[:64]
    rundir = f"{bundle}/runs/{mission}"
    os.makedirs(rundir)
    approval = approval_for(policy, mission)
    r842.write_json(f"{ETC}/approvals/{mission}.json", approval)
    when = {"midwrite-between": "between-passes", "midwrite-after": "after-capture"}.get(policy)
    gate_config = {"variant": variant, "recordDir": rundir, "corrupt": None,
                   "midWrite": {"when": when, "insertExecPath": X} if when else None}
    r842.write_json(f"{ETC}/gate.json", gate_config)
    request = request_for(policy, mission)
    r842.trace_mark(f"begin {mission}")
    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    frames = r842.call(token, request)
    finished = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    time.sleep(0.3)
    r842.trace_mark(f"end {mission}")
    full = r842.trace_read()
    tasks = r842.DaemonTasks(full)
    trace = r842.trace_slice(full, mission)
    overruns = r842.trace_overruns()

    gate_path = f"{rundir}/{mission}.gate.json"
    gate = json.load(open(gate_path)) if os.path.exists(gate_path) else None
    cleanup = None
    if gate and gate.get("injection"):
        # A key the writer never knew of: the daemon's revoke cannot remove it, so the harness does.
        exec_map = gate["deployment"]["maps"]["allowed_exec"]["id"]
        key = bytes.fromhex(gate["injection"]["insertedExecKey"])
        cleanup = r842.sh("/usr/sbin/bpftool", "map", "delete", "id", str(exec_map), "key", "hex",
                          *[f"{b:02x}" for b in key]) or "deleted"
    admission = next((f for f in frames if f.get("type") == "ADMISSION"), None)
    exit_frame = next((f for f in frames if f.get("type") == "EXIT"), {})
    obs = r842.observe(trace, tasks)
    observed = {"admitted": bool(admission and admission.get("admitted")), "aExec": obs["aExec"], "xExec": obs["xExec"],
                "launched": obs["launched"], "exitCode": exit_frame.get("exitCode")}
    want = expected(policy, variant)
    complete = overruns == 0 and gate is not None
    valid = setup_valid(policy, gate)
    record = {"missionId": mission, "phase": phase, "block": block, "policy": policy, "variant": variant,
              "expected": want, "observed": observed, "effect": effect(policy, observed),
              "setupValid": valid, "observationComplete": complete,
              "classification": classify(valid, complete, observed, want, gate),
              "gateDecision": gate and gate.get("decision"), "gateReasons": gate and gate.get("reasons"),
              "gateMs": (gate["gateFinishedBootNs"] - gate["gateStartedBootNs"]) / 1e6 if gate else None,
              "requestMs": (finished - started) / 1e6, "traceOverruns": overruns,
              "violations": [f for f in frames if f.get("type") == "VIOLATION"], "injectionCleanup": cleanup}
    for name, value in (("request", request), ("approval", approval), ("frames", frames), ("result", record)):
        r842.write_json(f"{rundir}/{name}.json", value, 0o644)
    with open(f"{rundir}/trace.txt", "w") as f:
        f.write(trace)
    os.remove(f"{ETC}/approvals/{mission}.json")
    return record


def run_baseline(token, bundle, index):
    # No gate: the admission path as shipped. Only latency and the workload's own result are recorded.
    mission = f"e843-baseline-{index:02d}"
    r842.trace_mark(f"begin {mission}")
    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    frames = r842.call(token, request_for("correct", mission))
    finished = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    time.sleep(0.3)
    r842.trace_mark(f"end {mission}")
    full = r842.trace_read()
    obs = r842.observe(r842.trace_slice(full, mission), r842.DaemonTasks(full))
    exit_code = next((f for f in frames if f.get("type") == "EXIT"), {}).get("exitCode")
    return {"missionId": mission, "variant": "none", "launched": obs["launched"], "exitCode": exit_code,
            "requestMs": (finished - started) / 1e6,
            "classification": "as-expected" if obs["launched"] == [A] and exit_code == 10 else "unexpected"}


def describe(values):
    values = [v for v in values if v is not None]
    if not values:
        return {"n": 0}
    return {"n": len(values), "medianMs": round(statistics.median(values), 3), "minMs": round(min(values), 3),
            "maxMs": round(max(values), 3)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("bundle")
    ap.add_argument("--blocks", type=int, default=3)
    ap.add_argument("--seed", type=int, default=int.from_bytes(os.urandom(4), "big"))
    args = ap.parse_args()
    mounted_bpffs = r842.preflight()
    if os.path.exists(TARGET):
        sys.exit(f"{TARGET} exists from an earlier run; remove it first")
    os.makedirs(f"{args.bundle}/runs")
    manifest = {"experiment": "thesis 8.4.3 - mutation coverage and a cost pilot",
                "build": json.load(open(f"{args.stage}/build.json")), "environment": r842.environment(),
                "bpffsMountedByHarness": mounted_bpffs, "seed": args.seed, "blocks": args.blocks,
                "startedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "order": {}, "phases": {}}
    runs, baseline, daemon = [], [], None
    rng = random.Random(args.seed)
    try:
        manifest["stagedSha256"] = r842.install(args.stage)
        shutil.copyfile(f"{args.stage}/p", P)
        os.chmod(P, 0o755)
        with open(TARGET, "w") as f:
            f.write("protected by the lease, readable by its uid otherwise\n")
        os.chmod(TARGET, 0o644)
        profile = json.load(open(f"{ETC}/profile.json"))
        for phase, extra, conditions in PHASES + [("baseline", [], None)]:
            r842.trace_setup()
            daemon = start_daemon(args.bundle, phase, extra)
            token = open(f"{ETC}/agent.token").read().strip()
            if phase == "normal":
                manifest["deployment"] = r842.deployment_snapshot(args.bundle, "before")
            if conditions is None:
                baseline = [run_baseline(token, args.bundle, i) for i in range(1, args.blocks * BASELINE_PER_BLOCK + 1)]
            else:
                manifest["order"][phase] = []
                for block in range(1, args.blocks + 1):
                    order = conditions[:]
                    rng.shuffle(order)
                    manifest["order"][phase].append([f"{p}/{v}" for p, v in order])
                    for index, (policy, variant) in enumerate(order, 1):
                        r = run_one(token, args.bundle, phase, block, index, policy, variant)
                        print(f"{r['missionId']:56} gate={r['gateDecision']!s:13} {r['classification']:22} {r['effect']}")
                        runs.append(r)
            manifest["phases"][phase] = {"args": extra, "daemonExit": stop_daemon(daemon)}
            daemon = None
            trace_teardown(args.bundle, phase)
        manifest["deploymentAfter"] = r842.deployment_snapshot(args.bundle, "after")
        manifest["residualMaps"] = r842.residual(profile)
    finally:
        if daemon is not None:
            stop_daemon(daemon)
        trace_teardown(args.bundle, "aborted")
        shutil.rmtree(r842.PIN_BASE, ignore_errors=True)
        manifest["pinsRemoved"] = not os.path.exists(r842.PIN_BASE)
        if os.path.exists(STATE):
            shutil.copytree(STATE, f"{args.bundle}/daemon-state", dirs_exist_ok=True)
        for d in (OPT, LIBEXEC, ETC, STATE):
            shutil.rmtree(d, ignore_errors=True)
        if os.path.exists(TARGET):
            os.remove(TARGET)
        if mounted_bpffs:
            subprocess.run(["umount", "/sys/fs/bpf"])

    residual_entries = sum(len(v or []) for maps in manifest.get("residualMaps", {}).values() for v in maps.values())
    conditions = [(p, v) for _, _, conds in PHASES for p, v in conds]
    manifest["finishedUtc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["summary"] = {
        "runs": len(runs), "asExpected": sum(r["classification"] == "as-expected" for r in runs),
        "residualPolicyEntries": residual_entries,
        "byCondition": {f"{p}/{v}": {"classification": [r["classification"] for r in runs if (r["policy"], r["variant"]) == (p, v)],
                                     "effect": [r["effect"] for r in runs if (r["policy"], r["variant"]) == (p, v)]}
                        for p, v in conditions},
        "baseline": [r["classification"] for r in baseline]}
    # The cost pilot: what the gate itself takes, and the request with and without it, on correct leases.
    manifest["cost"] = {
        "gateMsByVariant": {v: describe([r["gateMs"] for r in runs if r["variant"] == v and r["policy"] == "correct"])
                            for v in ("B2", "B2W", "B3")},
        "requestMsByVariant": dict({v: describe([r["requestMs"] for r in runs if r["variant"] == v and r["policy"] == "correct"])
                                    for v in ("B2", "B2W", "B3")}, none=describe([r["requestMs"] for r in baseline])),
        "note": "pilot: a few runs per variant, one machine; the protocol repetitions are fixed separately"}
    complete = len(runs) == args.blocks * len(conditions) and len(baseline) == args.blocks * BASELINE_PER_BLOCK \
        and residual_entries == 0
    if complete and all(r["classification"] == "as-expected" for r in runs) \
            and all(r["classification"] == "as-expected" for r in baseline):
        manifest["verdict"] = "PASS"
    else:
        manifest["verdict"] = "FAIL"
    manifest["runs"] = [{k: r[k] for k in ("missionId", "phase", "policy", "variant", "expected", "observed", "effect",
                                           "classification", "gateDecision", "gateReasons", "gateMs", "requestMs")}
                        for r in runs]
    manifest["baselineRuns"] = baseline
    r842.write_json(f"{args.bundle}/manifest.json", manifest, 0o644)
    print(json.dumps({"summary": manifest["summary"], "cost": manifest["cost"]}, indent=2), manifest["verdict"])
    return 0 if manifest["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
