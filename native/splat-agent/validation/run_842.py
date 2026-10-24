#!/usr/bin/python3 -I
"""Run thesis experiment 8.4.2 in the run guest, as root, from a directory staged by build_842.sh.

    python3 -I run_842.py <staging-dir> <bundle-dir> [--blocks N] [--seed S]

One daemon, one deployment, every condition. Per run the harness writes the approval (always: A only)
and the gate's variant, sends one EXECUTE_TOOL whose allowedExecPaths is the WRITER's intent, and
records what happened through three channels that do not depend on each other: the daemon's frames,
the gate's capture and decision, and an ftrace instance on sched_process_fork/sched_process_exec,
which the kernel emits outside the BPF-LSM program and only for an exec that succeeded.

The guest is left as it was found: the daemon is stopped, its pins and the harness's files removed.
"""
import argparse
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

OPT = "/opt/splat-842"
LIBEXEC = "/usr/local/libexec/splat-842"
ETC = "/etc/splat-842"
STATE = "/var/lib/splat-842"
PIN_BASE = "/sys/fs/bpf/splat"
TRACE = "/sys/kernel/tracing/instances/splat842"
HOST, PORT = "127.0.0.1", 50842
A, X = f"{LIBEXEC}/a", f"{LIBEXEC}/x"
LEASE_SECONDS = 20

CONDITIONS = [("correct", "OFF"), ("correct", "B2"), ("correct", "B3"),
              ("mutated", "OFF"), ("mutated", "B2"), ("mutated", "B3"),
              ("corrupted", "B2"), ("corrupted", "B3")]


def expected(policy, variant):
    """Thesis 8.4.2's table, made executable before any run is seen."""
    if policy == "correct":
        return {"admitted": True, "aExec": True, "xExec": False, "exitCode": 10}
    if policy == "mutated" and variant in ("OFF", "B2"):
        return {"admitted": True, "aExec": True, "xExec": True, "exitCode": 0}
    return {"admitted": False, "aExec": False, "xExec": False, "exitCode": -1}


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_json(path, value, mode=0o600):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        json.dump(value, f, indent=2)


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def bpftool(*args):
    return json.loads(sh("/usr/sbin/bpftool", "-j", *args) or "null")


# ---- protocol 3 client (the shape probe-daemon.sh speaks) -------------------------------------------

def prove(key, label, cn, sn, tail=b""):
    return hmac.new(key, label + bytes([0]) + cn + sn + tail, hashlib.sha256).hexdigest()


def call(token, req, timeout=60):
    key = token.encode()
    frames = []
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        cn = os.urandom(32)
        s.sendall((json.dumps({"type": "HELLO", "protocolVersion": 3, "clientNonce": cn.hex(), "proveFrames": True}) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise RuntimeError("daemon closed during handshake")
            buf += chunk
        first, _, buf = buf.partition(b"\n")
        challenge = json.loads(first)
        sn = bytes.fromhex(challenge["serverNonce"])
        if not challenge.get("framesProven") or not hmac.compare_digest(
                prove(key, b"splat-agent/3 daemon+frames", cn, sn), challenge.get("serverProof", "")):
            raise RuntimeError("daemon did not prove the token")
        body = json.dumps(dict(req, protocolVersion=3))
        proof = prove(key, b"splat-agent/3 request", cn, sn, (0).to_bytes(8, "big") + body.encode())
        s.sendall((json.dumps({"type": "AUTHENTICATED", "proof": proof, "request": body}) + "\n").encode())
        s.settimeout(timeout)
        seq = 0
        while True:
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    return frames
                buf += chunk
            line, _, buf = buf.partition(b"\n")
            wrapper = json.loads(line)
            inner = wrapper["frame"]
            if not hmac.compare_digest(prove(key, b"splat-agent/3 frame", cn, sn, seq.to_bytes(8, "big") + inner.encode()),
                                       wrapper["proof"]):
                raise RuntimeError(f"frame {seq} failed its proof")
            seq += 1
            frame = json.loads(inner)
            frames.append(frame)
            if frame.get("type") == "EXIT":
                return frames


# ---- independent launch observation -----------------------------------------------------------------

def trace_setup():
    os.makedirs(TRACE, exist_ok=True)
    with open(f"{TRACE}/trace_clock", "w") as f:
        f.write("boot")  # the clock the gate and the program's deadline use
    for event in ("sched_process_fork", "sched_process_exec"):
        with open(f"{TRACE}/events/sched/{event}/enable", "w") as f:
            f.write("1")
    with open(f"{TRACE}/tracing_on", "w") as f:
        f.write("1")


def trace_reset(marker):
    with open(f"{TRACE}/trace", "w"):
        pass
    with open(f"{TRACE}/trace_marker", "w") as f:
        f.write(marker)


def trace_read():
    with open(f"{TRACE}/trace") as f:
        return f.read()


FORK = re.compile(r"sched_process_fork: comm=(.*?) pid=(\d+) child_comm=(.*?) child_pid=(\d+)")
EXEC = re.compile(r"sched_process_exec: filename=(\S+) pid=(\d+) old_pid=(\d+)")


def observe(trace, daemon_tids):
    forks = [(int(m.group(2)), int(m.group(4))) for m in FORK.finditer(trace)]
    execs = [(m.group(1), int(m.group(2))) for m in EXEC.finditer(trace)]
    daemon_children = {child for parent, child in forks if parent in daemon_tids}
    return {"aExec": any(f == A for f, _ in execs), "xExec": any(f == X for f, _ in execs),
            "daemonChildExecs": [f for f, pid in execs if pid in daemon_children],
            "execsOfAOrX": [{"filename": f, "pid": p} for f, p in execs if f in (A, X)]}


# ---- the experiment ----------------------------------------------------------------------------------

def preflight():
    if os.geteuid() != 0:
        sys.exit("run as root")
    if os.path.exists(PIN_BASE):
        sys.exit(f"{PIN_BASE} exists: a previous daemon's program would be reused, not the staged one")
    for p in (OPT, LIBEXEC, ETC, STATE, TRACE):
        if os.path.exists(p):
            sys.exit(f"{p} exists from an earlier run; remove it first")


def install(stage):
    sums = dict(reversed(line.split()) for line in open(f"{stage}/SHA256SUMS").read().splitlines())
    for name, digest in sums.items():
        if sha256_file(f"{stage}/{name}") != digest:
            sys.exit(f"staged {name} does not match SHA256SUMS")
    for d, mode in ((OPT, 0o755), (LIBEXEC, 0o755), (ETC, 0o700), (f"{ETC}/approvals", 0o700), (STATE, 0o700)):
        os.makedirs(d, mode=mode)
        os.chmod(d, mode)
    for name, dest in (("splat-agent", f"{OPT}/splat-agent"), ("gate.py", f"{OPT}/gate.py"), ("a", A), ("x", X)):
        shutil.copyfile(f"{stage}/{name}", dest)
        os.chmod(dest, 0o755)
    shutil.copyfile(f"{stage}/profile.json", f"{ETC}/profile.json")
    return sums


def environment():
    return {"uname": sh("uname", "-a"), "osRelease": open("/etc/os-release").read(),
            "bootId": open("/proc/sys/kernel/random/boot_id").read().strip(),
            "cmdline": open("/proc/cmdline").read().strip(), "bpftool": bpftool("version"),
            "python": sys.version, "pinsBefore": os.path.exists(PIN_BASE)}


def start_daemon(bundle):
    log = open(f"{bundle}/daemon.log", "w")
    proc = subprocess.Popen([f"{OPT}/splat-agent", "--listen", f"{HOST}:{PORT}",
                             "--auth-token-file", f"{ETC}/agent.token", "--outcome-key-file", f"{ETC}/outcome.key",
                             "--receipt-root", f"{STATE}/receipts", "--admission-gate", f"{OPT}/gate.py"],
                            stdout=log, stderr=subprocess.STDOUT, env={"RUST_LOG": "info", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    for _ in range(100):
        if proc.poll() is not None:
            sys.exit(f"daemon exited with {proc.returncode}; see daemon.log")
        try:
            socket.create_connection((HOST, PORT), timeout=1).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    sys.exit("daemon never listened")


def deployment_snapshot(bundle, when):
    progs = bpftool("prog", "show")
    links = bpftool("link", "show")
    ours = [p for p in progs if p.get("name", "").startswith("splat_")]
    xlated = {}
    for p in ours:
        path = f"{bundle}/xlated-{when}-{p['name']}.bin"
        sh("/usr/sbin/bpftool", "prog", "dump", "xlated", "id", str(p["id"]), "file", path)
        xlated[p["name"]] = sha256_file(path) if os.path.exists(path) else None
    return {"programs": ours, "links": links, "xlatedSha256": xlated}


def run_one(token, bundle, block, index, policy, variant, daemon_pid):
    mission = f"e842-b{block}-{index:02d}-{policy}-{variant}".lower()
    rundir = f"{bundle}/runs/{mission}"
    os.makedirs(rundir)
    approval = {"missionId": mission, "bootId": open("/proc/sys/kernel/random/boot_id").read().strip(),
                "executables": [{"path": A, "sha256": sha256_file(A)}], "leaseDurationSeconds": LEASE_SECONDS,
                "approvedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    write_json(f"{ETC}/approvals/{mission}.json", approval)
    gate_config = {"variant": variant, "recordDir": rundir,
                   "corrupt": {"insertExecPath": X} if policy == "corrupted" else None}
    write_json(f"{ETC}/gate.json", gate_config)
    writer_intent = [A, X] if policy == "mutated" else [A]
    request = {"type": "EXECUTE_TOOL", "missionId": mission, "command": A, "argv": [],
               "allowedExecPaths": writer_intent, "leaseDurationSeconds": LEASE_SECONDS}
    daemon_tids = {int(t) for t in os.listdir(f"/proc/{daemon_pid}/task")}
    trace_reset(f"begin {mission}")
    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    frames = call(token, request)
    finished = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    time.sleep(0.3)
    trace = trace_read()

    gate = json.load(open(f"{rundir}/{mission}.gate.json")) if os.path.exists(f"{rundir}/{mission}.gate.json") else None
    cleanup = None
    if gate and gate.get("injection"):
        # The injected key is outside the writer's knowledge, so the daemon's revoke cannot remove it.
        exec_map = gate["deployment"]["maps"]["allowed_exec"]["id"]
        key = bytes.fromhex(gate["injection"]["insertedExecKey"])
        cleanup = sh("/usr/sbin/bpftool", "map", "delete", "id", str(exec_map), "key", "hex", *[f"{b:02x}" for b in key]) or "deleted"
    admission = next((f for f in frames if f.get("type") == "ADMISSION"), None)
    exit_frame = next((f for f in frames if f.get("type") == "EXIT"), {})
    obs = observe(trace, daemon_tids)
    observed = {"admitted": bool(admission and admission.get("admitted")), "aExec": obs["aExec"], "xExec": obs["xExec"],
                "exitCode": exit_frame.get("exitCode")}
    want = expected(policy, variant)
    record = {"missionId": mission, "block": block, "policy": policy, "variant": variant, "writerIntent": writer_intent,
              "expected": want, "observed": observed, "asExpected": observed == want,
              "gateDecision": gate and gate.get("decision"), "gateReasons": gate and gate.get("reasons"),
              "daemonChildExecs": obs["daemonChildExecs"], "execsOfAOrX": obs["execsOfAOrX"],
              "violations": [f for f in frames if f.get("type") == "VIOLATION"],
              "requestBootNs": [started, finished], "injectionCleanup": cleanup}
    write_json(f"{rundir}/request.json", request, 0o644)
    write_json(f"{rundir}/approval.json", approval, 0o644)
    write_json(f"{rundir}/frames.json", frames, 0o644)
    write_json(f"{rundir}/result.json", record, 0o644)
    with open(f"{rundir}/trace.txt", "w") as f:
        f.write(trace)
    os.remove(f"{ETC}/approvals/{mission}.json")
    return record


def residual(profile):
    # After every lease has ended, the exec program's policy maps must hold nothing for anyone.
    out = {}
    for role, spec in profile["maps"].items():
        ids = [m["id"] for m in bpftool("map", "show") if m.get("name") == spec["name"]]
        out[role] = {str(i): bpftool("map", "dump", "id", str(i)) for i in ids}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("bundle")
    ap.add_argument("--blocks", type=int, default=3)
    ap.add_argument("--seed", type=int, default=int.from_bytes(os.urandom(4), "big"))
    args = ap.parse_args()
    preflight()
    os.makedirs(f"{args.bundle}/runs")
    sums = install(args.stage)
    manifest = {"experiment": "thesis 8.4.2 - first native comparison: a consistently wrong executable grant",
                "build": json.load(open(f"{args.stage}/build.json")), "stagedSha256": sums,
                "environment": environment(), "seed": args.seed, "blocks": args.blocks,
                "startedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    profile = json.load(open(f"{ETC}/profile.json"))
    daemon = start_daemon(args.bundle)
    runs = []
    try:
        token = open(f"{ETC}/agent.token").read().strip()
        manifest["deployment"] = deployment_snapshot(args.bundle, "before")
        trace_setup()
        rng = random.Random(args.seed)
        manifest["order"] = []
        for block in range(1, args.blocks + 1):
            order = CONDITIONS[:]
            rng.shuffle(order)
            manifest["order"].append([f"{p}/{v}" for p, v in order])
            for index, (policy, variant) in enumerate(order, 1):
                r = run_one(token, args.bundle, block, index, policy, variant, daemon.pid)
                print(f"{r['missionId']:40} gate={r['gateDecision']!s:13} {r['observed']} {'ok' if r['asExpected'] else 'UNEXPECTED'}")
                runs.append(r)
        manifest["deploymentAfter"] = deployment_snapshot(args.bundle, "after")
        manifest["residualMaps"] = residual(profile)
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=20)
        except subprocess.TimeoutExpired:
            daemon.kill()
        manifest["daemonExit"] = daemon.returncode
        if os.path.exists(TRACE):
            with open(f"{TRACE}/tracing_on", "w") as f:
                f.write("0")
            for event in ("sched_process_fork", "sched_process_exec"):
                with open(f"{TRACE}/events/sched/{event}/enable", "w") as f:
                    f.write("0")
            os.rmdir(TRACE)
        # Pins outlive the daemon by design; this run made them, so it retires them.
        shutil.rmtree(PIN_BASE, ignore_errors=True)
        manifest["pinsRemoved"] = not os.path.exists(PIN_BASE)
        shutil.copytree(STATE, f"{args.bundle}/daemon-state", dirs_exist_ok=True)
        for d in (OPT, LIBEXEC, ETC, STATE):
            shutil.rmtree(d, ignore_errors=True)

    residual_entries = sum(len(v or []) for maps in manifest.get("residualMaps", {}).values() for v in maps.values())
    manifest["finishedUtc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["summary"] = {
        "runs": len(runs), "asExpected": sum(r["asExpected"] for r in runs),
        "residualPolicyEntries": residual_entries,
        "byCondition": {f"{p}/{v}": [r["asExpected"] for r in runs if (r["policy"], r["variant"]) == (p, v)]
                        for p, v in CONDITIONS}}
    manifest["verdict"] = ("PASS" if runs and all(r["asExpected"] for r in runs) and residual_entries == 0
                           and len(runs) == args.blocks * len(CONDITIONS) else "FAIL")
    manifest["runs"] = [{k: r[k] for k in ("missionId", "policy", "variant", "expected", "observed", "asExpected",
                                           "gateDecision", "gateReasons")} for r in runs]
    write_json(f"{args.bundle}/manifest.json", manifest, 0o644)
    print(json.dumps(manifest["summary"], indent=2), manifest["verdict"])
    return 0 if manifest["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
