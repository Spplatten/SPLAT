#!/usr/bin/env python3
"""Bounded offline stress of the actual lease daemon, with installed-service restoration.

No provider requests, global memory pressure, installed-daemon throttling, or policy relaxation.
Measures enforcement and evidence separately; dropped telemetry is not an allowed operation.
The optional pause stops only our temporary daemon for at most 500ms, with policies still loaded.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import struct
import subprocess
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("stress_runner", Path(__file__).with_name("probe-secrets.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BoundedSession(runner.Session):
    def receive(self):
        frame = super().receive()
        # Authenticity is checked by Session; retaining every raw flood frame would test our RAM.
        self.raw.clear()
        return frame


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def static_exit(code):
    payload = b"\xb8\x3c\x00\x00\x00\xbf" + struct.pack("<I", code) + b"\x0f\x05"
    return (struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
            2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000,
                          120 + len(payload), 120 + len(payload), 4096) + payload)


class StressProof(runner.Proof):
    def __init__(self, args, root):
        super().__init__(args, root)
        assert 1 <= args.workers <= 4 and 250 <= args.milliseconds <= 5000
        assert 0 <= args.pause_ms <= 500 and 1 <= args.churn_rounds <= 20
        assert os.uname().machine == "x86_64", "generated marker binaries require x86-64"
        manifest = json.loads(args.manifest.read_text())
        repo = Path(__file__).resolve().parents[2]
        inputs = [item for item in manifest["sourceInputs"]
                  if item["path"].startswith("native/splat-agent/")
                  and ("/src/" in item["path"] or Path(item["path"]).name in ("Cargo.toml", "Cargo.lock", "build.rs"))]
        assert inputs and all(runner.digest((repo / item["path"]).read_bytes()) == item["sha256"] for item in inputs), "stale native artifact inputs"
        assert runner.digest(args.daemon.read_bytes()) == manifest["daemonSha256"], "daemon does not match build manifest"
        self.compiled_inputs = []
        if args.mcp_exe:
            assert args.client_root and args.client_root.is_absolute(), "Windows client artifacts need an absolute output directory"
            assert runner.digest(args.mcp_exe.read_bytes()) == manifest["sha256"], "MCP executable does not match manifest"
            self.compiled_inputs = [item for item in manifest["sourceInputs"]
                if Path(item["path"]).suffix in (".cs", ".csproj", ".py", ".rs", ".c", ".h", ".toml", ".lock", ".props", ".targets")]
            assert all(runner.digest((repo / item["path"]).read_bytes()) == item["sha256"] for item in self.compiled_inputs), "stale managed artifact inputs"
            self.port = 50051
            self.command[self.command.index("--listen") + 1] = "127.0.0.1:50051"
        source = Path(__file__).with_name("stress-workload.c")
        library = root / "workload.so"
        subprocess.run(["cc", "-O2", "-shared", "-fPIC", "-pthread", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(library)], check=True, timeout=30, capture_output=True)
        self.library = base64.b64encode(library.read_bytes()).decode()
        self.observations = {"limits": {"workers": args.workers, "millisecondsPerFlood": args.milliseconds,
            "pauseTemporaryDaemonMs": args.pause_ms, "memoryBytesPerLease": 134217728,
            "cpuPercentPerLease": 50, "pidsPerLease": 16}, "phases": {},
            "workloadSourceSha256": runner.digest(source.read_bytes()),
            "workloadLibrarySha256": runner.digest(library.read_bytes()),
            "buildManifestSha256": runner.digest(args.manifest.read_bytes()), "modelApiRequests": 0,
            "scope": "Native leases and authenticated guest TCP; optional published Windows MCP bridge. Not WinUI FPS, A2A federation, content hashing or an unloaded-kernel overhead benchmark.",
            "verdictMeaning": "PASS covers containment, receipt honesty and cleanup; telemetry loss is measured separately and is not a performance pass."}
        self.health_times, self.health_errors, self.rss = [], [], []
        self.monitor_stop = threading.Event()
        self.pin_dir = Path("/sys/fs/bpf/splat") / runner.digest(Path(__file__).with_name("src").joinpath("bpf/lease_lsm.bpf.c").read_bytes())

    def session(self):
        session = BoundedSession(self.port, (self.root / "token").read_bytes().strip())
        session.socket.settimeout(25)
        self.sessions.append(session)
        return session

    def program(self, body):
        return """import base64, ctypes, json, os, time
from pathlib import Path
class Measurement(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ('attempts','allowed','denied','escaped','other','swaps','elapsed_ns')] + [('latency_bins', ctypes.c_uint64 * 64)]
Path('workload.so').write_bytes(base64.b64decode(LIBRARY))
lib = ctypes.CDLL(str(Path.cwd() / 'workload.so'))
for name in ('splat_open_storm', 'splat_exec_storm'):
    getattr(lib, name).argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint64, ctypes.POINTER(Measurement)]
lib.splat_inode_race.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint64, ctypes.POINTER(Measurement)]
def measure(kind, path, ms, limit):
    value = Measurement()
    getattr(lib, kind)(os.fsencode(path), ms, limit, ctypes.byref(value))
    return {name: list(getattr(value, name)) if name == 'latency_bins' else getattr(value, name) for name, _ in value._fields_}
print('READY', flush=True)
time.sleep(0.2)
""".replace("LIBRARY", repr(self.library)) + body

    def request(self, label, program="pass", duration=20):
        request = super().request("stress-" + label + "-" + uuid.uuid4().hex[:10], program, duration)
        request["limits"] = {"maxMemoryBytes": 134217728, "maxCpuPercent": 50, "maxPids": 16}
        return request

    def collect(self, request, ready=None, slow=False):
        session = self.session()
        lease, receipt, stdout, stderr, events = None, None, "", "", 0
        session.send(request)
        started = time.monotonic()
        try:
            while True:
                frame = session.receive()
                kind = frame["type"]
                if kind == "LEASE":
                    lease = frame
                elif kind == "VIOLATION":
                    events += 1
                elif kind in ("STDOUT", "STDERR"):
                    if kind == "STDOUT":
                        stdout += frame["data"]
                        if ready and "READY\n" in stdout:
                            ready.set()
                            ready = None
                            if slow: time.sleep(1)
                    else: stderr += frame["data"]
                    assert len(stdout) + len(stderr) <= 131072, "unexpected unbounded test output"
                elif kind == "EXIT":
                    receipt = frame
                    break
            result = {"missionId": request["missionId"], "elapsedSeconds": time.monotonic() - started,
                      "lease": lease, "receipt": receipt, "violationFrames": events, "stderr": stderr,
                      "samples": [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]}
            return result
        finally:
            session.close()

    def verify(self, label, request, result, ephemeral=True):
        self.observations["phases"][label] = result
        receipt, lease = result["receipt"], result["lease"]
        self.check(label + "_completed_enforcing", receipt["exitCode"] == 0 and lease is not None and lease["enforcing"])
        self.check(label + "_private_identity", lease["workloadUid"] >= 65536)
        self.check(label + "_resource_clamps_read_back", lease["limitsReadBack"] is True
            and lease["limits"] == request["limits"])
        self.check(label + "_frame_count_matches_receipt", result["violationFrames"] == receipt["violationsReported"])
        complete = receipt["violationsReported"] >= receipt["violationsCounted"] and receipt["violationsDropped"] == 0
        self.check(label + "_honest_completeness", receipt["violationsComplete"] == complete)
        verification = self.root / (label + "-signature")
        verification.mkdir()
        (verification / "key.der").write_bytes(base64.b64decode(receipt["outcomePublicKey"], validate=True))
        (verification / "signature").write_bytes(base64.b64decode(receipt["outcomeSignature"], validate=True))
        (verification / "canonical").write_bytes(receipt["outcomeCanonical"].encode())
        checked = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(verification / "key.der"),
            "-keyform", "DER", "-signature", str(verification / "signature"), str(verification / "canonical")], capture_output=True)
        self.check(label + "_signed_receipt", checked.returncode == 0)
        fields = [("mission", request["missionId"]), ("cgroup", lease["cgroupId"]),
                  ("enforcing", "true"), ("uid", lease["workloadUid"]), ("exit", receipt["exitCode"]),
                  ("counted", receipt["violationsCounted"]), ("reported", receipt["violationsReported"]),
                  ("dropped", receipt["violationsDropped"]),
                  ("workspace", request["workingDirectory"] if ephemeral else ""),
                  ("workspaceRemoved", str(receipt["workspaceRemoved"]).lower() if ephemeral else "n/a")]
        canonical = "splat-lease-outcome/1" + "".join("|" + key + "=" + str(value).replace("\\", "\\\\").replace("|", "\\p").replace("\n", "\\n") for key, value in fields)
        self.check(label + "_signature_binds_measurements", receipt["outcomeCanonical"] == canonical)
        self.check(label + "_cleanup", self.wait_removed(request) if ephemeral else self.wait_drained(request))
        for sample in result["samples"]:
            if "attempts" in sample:
                self.check(label + "_sample_consistent_" + str(result["samples"].index(sample)),
                    sample["attempts"] > 0 and sample["attempts"] == sum(sample[key] for key in ("allowed", "denied", "escaped", "other"))
                    and sum(sample["latency_bins"]) == sample["attempts"])

    def wait_drained(self, request):
        for _ in range(100):
            if not (Path("/sys/fs/cgroup/splat_leases") / ("mission_" + request["missionId"])).exists():
                return True
            time.sleep(0.1)
        return False

    def monitor(self):
        while not self.monitor_stop.is_set():
            started = time.monotonic()
            try:
                session = BoundedSession(self.port, (self.root / "token").read_bytes().strip())
                try:
                    assert session.health["enforcing"] is True
                    self.health_times.append((time.monotonic() - started) * 1000)
                finally: session.close()
                status = Path(f"/proc/{self.process.pid}/status").read_text().splitlines()
                self.rss.append(int(next(line.split()[1] for line in status if line.startswith("VmRSS:"))))
            except Exception as error:
                self.health_errors.append(type(error).__name__ + ": " + str(error))
            self.monitor_stop.wait(0.1)

    def kernel_counters(self):
        return json.loads(subprocess.check_output(["bpftool", "-j", "map", "dump", "pinned", str(self.pin_dir / "map_counters")]))

    @staticmethod
    def counters_as_values(snapshot):
        return {int(item["formatted"]["key"]): int(item["formatted"]["value"]) for item in snapshot}

    def flood(self, label, pause=False, slow=False):
        before = self.kernel_counters()
        requests = [self.request(label + "-" + str(index), self.program(
            "print(json.dumps(measure('splat_open_storm', '/etc/hostname', " + str(self.args.milliseconds) + ", 2000000)), flush=True)\n"))
            for index in range(self.args.workers)]
        for request in requests: request["protectedPaths"] = ["/etc/hostname"]
        ready = [threading.Event() for _ in requests]
        with ThreadPoolExecutor(max_workers=self.args.workers) as pool:
            futures = [pool.submit(self.collect, request, event, slow) for request, event in zip(requests, ready)]
            if pause:
                assert all(event.wait(10) for event in ready), "workload did not reach the pause barrier"
                try:
                    self.process.send_signal(signal.SIGSTOP)
                    time.sleep(self.args.pause_ms / 1000)
                finally:
                    self.process.send_signal(signal.SIGCONT)
            results = [future.result(timeout=30) for future in futures]
        after = self.kernel_counters()
        self.observations[label + "Counters"] = {"before": before, "after": after}
        previous, current = self.counters_as_values(before), self.counters_as_values(after)
        counted, dropped = current[0] - previous[0], current[1] - previous[1]
        received = sum(result["violationFrames"] for result in results)
        self.observations[label + "Delivery"] = {"kernelDenials": counted, "ringBufferDrops": dropped,
            "framesReceived": received, "additionalDeliveryLoss": counted - dropped - received,
            "losslessTelemetry": counted == received and dropped == 0,
            "ringDropFraction": dropped / counted if counted else None}
        self.check(label + "_global_counter_matches_workloads", counted == sum(r["samples"][0]["denied"] for r in results))
        self.check(label + "_loss_accounting_consistent", 0 <= dropped <= counted and 0 <= received <= counted - dropped)
        self.check(label + "_distinct_identities", len({r["lease"]["workloadUid"] for r in results}) == len(results))
        for index, (request, result) in enumerate(zip(requests, results)):
            key = label + "_" + str(index)
            self.verify(key, request, result)
            sample = result["samples"][0]
            self.check(key + "_every_open_denied", sample["denied"] == sample["attempts"] and sample["other"] == 0)
            self.check(key + "_kernel_count_exact", result["receipt"]["violationsCounted"] == sample["denied"])
            result["denialsPerSecond"] = sample["denied"] * 1e9 / sample["elapsed_ns"]

    def run(self):
        first = self.session()
        self.check("temporary_daemon_enforcing", first.health["enforcing"] is True)
        first.close()
        monitor = threading.Thread(target=self.monitor, daemon=True)
        monitor.start()
        try:
            control = self.request("positive", self.program("print(json.dumps(measure('splat_open_storm', '/etc/hostname', 250, 1000)), flush=True)\n"))
            result = self.collect(control)
            self.verify("positive_control", control, result)
            self.check("positive_control_reaches_file", result["samples"][0]["allowed"] == 1000)
            self.flood("denial_flood")
            self.flood("slow_reader", slow=True)
            if self.args.pause_ms: self.flood("paused_consumer", pause=True)
            deep = self.request("deep", self.program("""leaf = Path.cwd()
for index in range(64):
    leaf = leaf / (str(index).zfill(2) + 'x' * 58)
    leaf.mkdir()
(leaf / 'same-prefix-allow').symlink_to('/usr/bin/true')
(leaf / 'same-prefix-deny').symlink_to('/usr/bin/false')
print(json.dumps({'pathBytes': len(os.fsencode(leaf / 'same-prefix-allow')), 'depth': 64}), flush=True)
for suffix in ('allow', 'deny'):
    print(json.dumps(measure('splat_exec_storm', str(leaf / ('same-prefix-' + suffix)), 3000, 100)), flush=True)
"""))
            deep["allowedExecPaths"].append("/usr/bin/true")
            result = self.collect(deep)
            self.verify("deep_overlay", deep, result)
            self.check("deep_overlay_allowed_control", result["samples"][1]["allowed"] == 100)
            self.check("deep_overlay_denied_inode", result["samples"][2]["denied"] == 100)
            self.check("deep_overlay_count_exact", result["receipt"]["violationsCounted"] == 100)
            self.race()
            self.churn()
            if self.args.mcp_exe: self.windows_bridge()
        finally:
            self.monitor_stop.set()
            monitor.join(timeout=20)
            self.observations["health"] = {"samples": len(self.health_times), "errors": self.health_errors,
                "p50Ms": percentile(self.health_times, .5), "p95Ms": percentile(self.health_times, .95),
                "maxMs": max(self.health_times, default=None), "daemonSampledPeakRssKiB": max(self.rss, default=None)}
        self.check("health_available_during_stress", not self.health_errors and len(self.health_times) >= 5)
        final = self.session()
        self.check("all_leases_drained", final.health["activeLeaseCount"] == 0)
        final.close()
        if self.compiled_inputs:
            repo = Path(__file__).resolve().parents[2]
            self.check("managed_sources_unchanged", all(runner.digest((repo / item["path"]).read_bytes()) == item["sha256"] for item in self.compiled_inputs))

    def race(self):
        request = self.request("race")
        workspace = Path(request["workingDirectory"])
        workspace.mkdir(parents=True)
        workspace.chmod(0o777)
        left, right = workspace / "target", workspace / "replacement"
        for path, code in ((left, 0), (right, 73)):
            path.write_bytes(static_exit(code))
            path.chmod(0o755)
        request.update(ephemeralWorkspace=False, overlayFs={"enableCow": False})
        request["allowedExecPaths"].append(str(left))
        request["argv"] = ["-I", "-c", self.program("""value = Measurement()
lib.splat_inode_race(os.fsencode(Path.cwd() / 'target'), os.fsencode(Path.cwd() / 'replacement'), 3000, 1000, ctypes.byref(value))
print(json.dumps({name: list(getattr(value, name)) if name == 'latency_bins' else getattr(value, name) for name, _ in value._fields_}), flush=True)
""")]
        result = self.collect(request)
        self.verify("inode_race", request, result, ephemeral=False)
        sample = result["samples"][0]
        self.check("inode_race_both_states_exercised", sample["allowed"] > 0 and sample["denied"] > 0 and sample["swaps"] > 0)
        self.check("inode_race_no_unauthorized_marker", sample["escaped"] == sample["other"] == 0)
        self.check("inode_race_count_exact", result["receipt"]["violationsCounted"] == sample["denied"])

    def churn(self):
        latencies = []
        for round_index in range(self.args.churn_rounds):
            requests = [self.request("churn", "print('synthetic churn control', flush=True)") for _ in range(self.args.workers)]
            with ThreadPoolExecutor(max_workers=self.args.workers) as pool:
                results = list(pool.map(self.collect, requests))
            for index, (request, result) in enumerate(zip(requests, results)):
                self.verify(f"churn_{round_index}_{index}", request, result)
                latencies.append(result["elapsedSeconds"] * 1000)
        self.observations["churn"] = {"leases": len(latencies), "p50Ms": percentile(latencies, .5), "p95Ms": percentile(latencies, .95)}

    def windows_bridge(self):
        artifacts = self.args.client_root / ("windows-stress-" + uuid.uuid4().hex)
        artifacts.mkdir(parents=True)
        workspace = self.root / "windows-workload"
        workspace.mkdir(mode=0o755)
        windows_path = lambda path: subprocess.check_output(["wslpath", "-w", str(path.resolve())], text=True).strip()
        values = {"SPLAT_AGENT_TOKEN": (self.root / "token").read_text().strip(),
                  "SPLAT_DB_PATH": windows_path(artifacts / "ledger.db"),
                  "SPLAT_DATA_DIR": windows_path(artifacts / "state")}
        environment = dict(os.environ)
        for key in ("SPLAT_ALLOW_ANTHROPIC_TEST_REQUESTS", "SPLAT_ALLOW_HOST_TELEMETRY_TO_ANTHROPIC", "SPLAT_RECORD_CORPUS"):
            environment.pop(key, None)
        environment.update(values)
        environment["WSLENV"] = ":".join(filter(None, [environment.get("WSLENV"), *(key + "/w" for key in values)]))
        program = """import errno, json, os, time
denied = other = 0
started = time.monotonic()
for _ in range(50000):
    try: os.execve('/usr/bin/false', ['false'], {})
    except OSError as error:
        if error.errno == errno.EPERM: denied += 1
        else: other += 1
# Long decimal digit sequences can trigger the host's PII filter; bounded integer timing stays parseable.
print(json.dumps({'stressMarker':'SPLAT_WINDOWS_STRESS','attempts':50000,'denied':denied,'other':other,'elapsedMs':round((time.monotonic()-started)*1000)}), flush=True)
"""
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_command", "arguments": {
                "command": "/usr/bin/python3", "args": ["-I", "-c", program], "workingDirectory": str(workspace),
                "allowNetwork": False, "timeoutSeconds": 20}}}]
        started = time.monotonic()
        with open(artifacts / "stdout.jsonl", "w") as stdout, open(artifacts / "stderr.txt", "w") as stderr:
            # Output goes to disk: capture_output would duplicate the host's large response in the runner.
            client = subprocess.run([str(self.args.mcp_exe.resolve())], input="".join(json.dumps(m) + "\n" for m in messages),
                stdout=stdout, stderr=stderr, text=True, env=environment, timeout=90)
        elapsed = time.monotonic() - started
        self.check("windows_bridge_process_completed", client.returncode == 0)
        responses = [json.loads(line) for line in (artifacts / "stdout.jsonl").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        response = next(row for row in responses if row.get("id") == 2)
        text = "\n".join(part.get("text", "") for part in response.get("result", {}).get("content", []))
        samples = [json.loads(line) for line in text.splitlines() if line.startswith('{"stressMarker":')]
        self.check("windows_bridge_all_execs_denied", len(samples) == 1 and samples[0]["denied"] == 50000 and samples[0]["other"] == 0)
        self.check("windows_bridge_mission_completed", response["result"].get("isError") is False)
        with sqlite3.connect("file:" + str(artifacts / "ledger.db") + "?mode=ro", uri=True) as database:
            rows = database.execute("SELECT Details FROM AuditLedger WHERE Action = 'MISSION_RUN_FACTS'").fetchall()
        self.check("windows_bridge_sealed_one_run", len(rows) == 1)
        facts = json.loads(rows[0][0])
        self.check("windows_bridge_kernel_count_exact", facts["KernelRefusals"] == 50000)
        self.check("windows_bridge_loss_disclosed", facts["KernelRefusalEvidenceComplete"] is not False or "KERNEL_EVENTS_INCOMPLETE" in text)
        self.check("windows_bridge_drained", self.wait_drained({"missionId": facts["MissionId"]}))
        for name, field in (("key.der", "GuestOutcomePublicKey"), ("signature", "GuestOutcomeSignature")):
            (artifacts / name).write_bytes(base64.b64decode(facts[field], validate=True))
        (artifacts / "canonical.txt").write_bytes(facts["GuestSignedOutcome"].encode())
        checked = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(artifacts / "key.der"), "-keyform", "DER",
            "-signature", str(artifacts / "signature"), str(artifacts / "canonical.txt")], capture_output=True)
        self.check("windows_bridge_receipt_signature", checked.returncode == 0)
        fields = dict(part.split("=", 1) for part in facts["GuestSignedOutcome"].split("|")[1:])
        self.check("windows_bridge_signature_binds_counts", int(fields["counted"]) == facts["KernelRefusals"]
            and int(fields["reported"]) == facts["KernelRefusalsReported"] and fields["mission"] == facts["MissionId"]
            and fields["enforcing"] == "true" and fields["exit"] == "0")
        self.observations["windowsBridge"] = {"executableSha256": runner.digest(self.args.mcp_exe.read_bytes()),
            "compiledSourceInputs": self.compiled_inputs, "elapsedSeconds": elapsed, "workload": samples[0],
            "kernelDenials": facts["KernelRefusals"], "framesReceived": facts["KernelRefusalsReported"],
            "evidenceComplete": facts["KernelRefusalEvidenceComplete"], "ringBufferDrops": int(fields["dropped"]),
            "responseBytes": (artifacts / "stdout.jsonl").stat().st_size,
            "responseSha256": runner.digest((artifacts / "stdout.jsonl").read_bytes()),
            "receiptCanonical": facts["GuestSignedOutcome"], "receiptSignature": facts["GuestOutcomeSignature"],
            "receiptPublicKey": facts["GuestOutcomePublicKey"], "privateArtifacts": str(artifacts)}


def configure(parser):
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--milliseconds", type=int, default=2000)
    parser.add_argument("--pause-ms", type=int, default=500)
    parser.add_argument("--churn-rounds", type=int, default=4)
    parser.add_argument("--mcp-exe", type=Path)
    parser.add_argument("--client-root", type=Path)


if __name__ == "__main__":
    raise SystemExit(runner.main(StressProof, __file__, configure))
