#!/usr/bin/env python3
"""Root, offline, synthetic-secret proof. Owns its test daemon and restores the installed service.

Usage: sudo python3 probe-secrets.py --daemon /absolute/built/splat-agent --output evidence/secret-probe.json
The installed service is stopped only after proving that no lease is populated. No installed
binary, token, policy, or key is replaced. No provider credentials or external network are used.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time


def assert_idle():
    for path in Path("/sys/fs/cgroup/splat_leases").glob("mission_*/cgroup.events"):
        assert "populated 0" in path.read_text(), "an existing lease is active; policy must remain installed"


def retire_idle_pins(expected_hash):
    # An explicit hash authorizes only this idle pin set. Never hide foreign pins or change the
    # daemon's fail-closed loader; retire verified idle policy under the same instance lock.
    assert len(expected_hash) == 64 and all(char in "0123456789abcdef" for char in expected_hash)
    base = Path("/sys/fs/bpf/splat")
    if not base.exists() or not list(base.iterdir()):
        return
    with open("/run/splat/agent.lock", "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert_idle()
        directory = base / expected_hash
        assert list(base.iterdir()) == [directory], "unexpected pin set; refusing retirement"
        assert directory.is_dir() and not directory.is_symlink() and base.resolve() == base
        pins = list(directory.iterdir())
        assert {path.name for path in pins if path.name.startswith("link_")} == {
            "link_splat_bprm_check", "link_splat_file_open", "link_splat_socket_connect", "link_splat_socket_sendmsg"}
        for path in pins:
            kind = "link" if path.name.startswith("link_") else "map"
            assert path.name.startswith(kind + "_") and path.is_file() and not path.is_symlink()
            subprocess.run(["bpftool", "-j", kind, "show", "pinned", str(path)], check=True, capture_output=True)
        leased = subprocess.run(["bpftool", "-j", "map", "dump", "pinned", str(directory / "map_leased_cgroups")],
            check=True, capture_output=True)
        assert json.loads(leased.stdout) == [], "pinned leases remain; refusing retirement"
        for path in sorted(pins, key=lambda path: not path.name.startswith("link_")):
            path.unlink()
        directory.rmdir()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(request):
    value = {key: item for key, item in request.items() if key != "secretGrant"}
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


class Session:
    def __init__(self, port, token):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=15)
        self.reader = self.socket.makefile("rb")
        self.token = token
        self.client = os.urandom(32)
        self.sent = self.received = 0
        self.raw = []
        self.socket.sendall(json.dumps({"type": "HELLO", "protocolVersion": 3,
            "clientNonce": self.client.hex(), "proveFrames": True}).encode() + b"\n")
        challenge = json.loads(self.reader.readline(131073))
        self.server = bytes.fromhex(challenge["serverNonce"])
        assert challenge.get("framesProven") is True
        assert hmac.compare_digest(challenge["serverProof"], self.mac("daemon+frames"))
        # Proves a request and confirms the server has registered this session before deposit.
        self.send({"type": "HEALTH_CHECK"})
        self.health = self.receive()

    def mac(self, kind, suffix=b""):
        return hmac.new(self.token, ("splat-agent/3 " + kind).encode() + b"\0"
            + self.client + self.server + suffix, hashlib.sha256).hexdigest()

    def send(self, request):
        body = json.dumps(request, separators=(",", ":"))
        proof = self.mac("request", self.sent.to_bytes(8, "big") + body.encode())
        self.sent += 1
        self.socket.sendall(json.dumps({"type": "AUTHENTICATED", "request": body,
            "proof": proof}).encode() + b"\n")

    def receive(self):
        line = self.reader.readline(131073)
        assert line and len(line) <= 131072, "missing or oversized frame"
        self.raw.append(line)
        wrapper = json.loads(line)
        assert wrapper["type"] == "PROVEN"
        assert hmac.compare_digest(wrapper["proof"], self.mac("frame",
            self.received.to_bytes(8, "big") + wrapper["frame"].encode()))
        self.received += 1
        return json.loads(wrapper["frame"])

    def collect(self):
        frames = []
        while True:
            frame = self.receive()
            frames.append(frame)
            if frame["type"] == "EXIT":
                return frames

    def close(self):
        self.reader.close()
        self.socket.close()


class Proof:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.checks, self.sessions, self.needles = {}, [], []
        self.process = None
        self.log = open(root / "daemon.log", "w+b")
        self.socket = root / "secrets.sock"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.command = [str(args.daemon), "--listen", f"127.0.0.1:{self.port}",
            "--auth-token-file", str(root / "token"), "--outcome-key-file", str(root / "outcome.key"),
            "--policy-file", str(root / "absent-policy.json"), "--missions-root", str(root / "missions"),
            "--secret-socket", str(self.socket), "--secret-uid-count", "4"]

    def check(self, name, value):
        self.checks[name] = bool(value)
        assert value, name

    def start(self):
        self.process = subprocess.Popen(self.command, stdout=self.log, stderr=subprocess.STDOUT,
            env={**os.environ, "SPLAT_TEST_SERVICE_CREDENTIAL": "must-not-reach-a-step"})
        for _ in range(300):
            if self.process.poll() is not None:
                raise AssertionError("test daemon failed to start; inspect the local test log")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("test daemon startup timed out")

    def stop(self, crash=False):
        if self.process is not None and self.process.poll() is None:
            self.process.kill() if crash else self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def session(self):
        value = Session(self.port, (self.root / "token").read_bytes().strip())
        self.sessions.append(value)
        return value

    def request(self, label, program="import os; os.read(0, 4096)", duration=20):
        return {"type": "EXECUTE_TOOL", "protocolVersion": 3, "missionId": label,
            "stepId": label + "-step", "command": "/usr/bin/python3", "argv": ["-I", "-c", program],
            "workingDirectory": str(self.root / "missions" / label), "ephemeralWorkspace": True,
            "leaseDurationSeconds": duration, "allowNetwork": False, "allowedEgressIps": [],
            "allowedEgressPorts": [], "allowedExecPaths": ["/usr/bin/python3"],
            "environment": {"SPLAT_PARAM_REGION": "proof"}, "overlayFs": {"enableCow": True}}

    def secret(self):
        value = ("SYNTHETIC_" + os.urandom(24).hex()).encode()
        self.needles.append(value)
        return value

    def metadata(self, session, request, length, ttl=30):
        return {"clientNonce": session.client.hex(), "serverNonce": session.server.hex(),
            "request": request, "secretLength": length, "ttlSeconds": ttl}

    def wire(self, header, value, trailing=b""):
        public = json.dumps(header, separators=(",", ":")).encode()
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(7)
            stream.connect(str(self.socket))
            stream.sendall(struct.pack(">I", len(public)) + public + value + trailing)
            stream.shutdown(socket.SHUT_WR)
            result = bytearray()
            try:
                while part := stream.recv(1024):
                    result.extend(part)
                    assert len(result) <= 1024
            except ConnectionResetError:
                pass
            return bytes(result)

    def grant(self, session, request, value, ttl=30):
        response = self.wire(self.metadata(session, request, len(value), ttl), value)
        granted = copy.deepcopy(request)
        granted["secretGrant"] = json.loads(response)["secretGrant"]
        return granted

    def refused(self, session, request):
        session.send(request)
        frames = session.collect()
        return frames[-1]["exitCode"] == -1 and all(f["type"] != "LEASE" for f in frames)

    def completed(self, session, request):
        session.send(request)
        frames = session.collect()
        assert frames[-1].get("exitCode") == 0, "synthetic workload failed"
        return frames

    def wait_removed(self, request):
        paths = [Path(request["workingDirectory"]),
            Path("/sys/fs/cgroup/splat_leases") / ("mission_" + request["missionId"]),
            Path("/run/splat/roots") / ("mission_" + request["missionId"]),
            Path("/run/splat/cow") / ("mission_" + request["missionId"])]
        for _ in range(100):
            if all(not path.exists() for path in paths):
                return True
            time.sleep(0.1)
        return False

    def verify_receipt(self, request, frame):
        public = self.root / "verify.der"
        signature = self.root / "verify.sig"
        message = self.root / "verify.txt"
        public.write_bytes(base64.b64decode(frame["outcomePublicKey"], validate=True))
        signature.write_bytes(base64.b64decode(frame["secretOutcomeSignature"], validate=True))
        message.write_text(frame["secretOutcomeCanonical"])
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public),
            "-keyform", "DER", "-signature", str(signature), str(message)], capture_output=True)
        receipt = json.loads(frame["secretOutcomeCanonical"])
        return result.returncode == 0 and receipt["requestSha256"] == digest(canonical(request)) \
            and receipt["stepId"] == request["stepId"] and receipt["outcomeCanonical"] == frame["outcomeCanonical"] \
            and receipt["secretStdinClosed"] is True

    def run(self):
        first = self.session()
        self.check("enforcing_broker_advertised", first.health.get("enforcing") and first.health.get("secretStdinSupported"))
        self.check("broker_mode_0600", self.socket.stat().st_mode & 0o777 == 0o600)
        ordinary = self.request("secret-proof-environment", "import os; assert 'SPLAT_TEST_SERVICE_CREDENTIAL' not in os.environ; assert os.environ['SPLAT_PARAM_REGION']=='proof'; assert os.read(0,1)==b''")
        self.check("ordinary_child_has_explicit_environment_and_eof_stdin", bool(self.completed(first, ordinary)))

        # Deliberately relax only this private test directory/socket to exercise the peer UID
        # check independently of pathname permissions; restore both before issuing a grant.
        try:
            self.root.chmod(0o711)
            self.socket.chmod(0o666)
            client = subprocess.run(["/usr/bin/python3", "-I", "-c",
                "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); "
                "s.sendall(b'\\x00\\x00\\x00\\x00'); "
                "\ntry: assert not s.recv(1)\nexcept ConnectionResetError: pass", str(self.socket)],
                user=65534, group=65534, extra_groups=[], capture_output=True)
            self.check("nonroot_peer_refused_even_with_socket_access", client.returncode == 0)
        finally:
            self.socket.chmod(0o600)
            self.root.chmod(0o700)

        value = self.secret()
        request = self.request("secret-proof-binding")
        granted = self.grant(first, request, value)
        second = self.session()
        self.check("different_session_refused", self.refused(second, granted))
        for field, changed in [("stepId", "changed"), ("argv", ["-c", "pass"]),
            ("environment", {"SPLAT_PARAM_REGION": "changed"}), ("allowedEgressIps", ["127.0.0.2"])]:
            modified = copy.deepcopy(granted)
            modified[field] = changed
            self.check("changed_" + field + "_refused", self.refused(first, modified))
        self.check("matching_grant_consumed", bool(self.completed(first, granted)))
        self.check("grant_replay_refused", self.refused(first, granted))
        self.check("completed_resources_removed", self.wait_removed(request))
        expired = self.grant(first, self.request("secret-proof-expiry-grant"), value, ttl=1)
        time.sleep(1.1)
        self.check("expired_grant_refused", self.refused(first, expired))
        for name, header, payload, tail in [
            ("truncated_upload", self.metadata(first, request, len(value)), value[:-1], b""),
            ("trailing_upload", self.metadata(first, request, len(value)), value, b"x"),
            ("oversized_secret", self.metadata(first, request, 4097), b"", b""),
            ("invalid_ttl", self.metadata(first, request, len(value), 61), value, b"")]:
            self.check(name + "_refused", not self.wire(header, payload, tail))

        # The CLI receives payload bytes through stdin; its metadata file never contains them.
        cli_request = self.request("secret-proof-cli")
        binding = self.root / "binding.json"
        binding.write_text(json.dumps(self.metadata(first, cli_request, 0)))
        issued = subprocess.run([str(self.args.daemon), "--secret-socket", str(self.socket),
            "--issue-secret", str(binding)], input=value, capture_output=True)
        self.check("issuer_ack_contains_only_grant", issued.returncode == 0 and value not in issued.stdout + issued.stderr
            and set(json.loads(issued.stdout)) == {"secretGrant"})
        cli_request["secretGrant"] = json.loads(issued.stdout)["secretGrant"]
        self.check("issuer_grant_executes", bool(self.completed(first, cli_request)))

        # Keep a publisher alive while two other leases try to read its descriptors and memory.
        ready, release = threading.Event(), threading.Event()
        receiver_result = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(15)
        port = listener.getsockname()[1]
        def receive_publish():
            try:
                with listener.accept()[0] as stream:
                    stream.settimeout(15)
                    data = bytearray()
                    while len(data) < len(value):
                        part = stream.recv(len(value) - len(data))
                        if not part:
                            break
                        data.extend(part)
                    receiver_result.append(bytes(data) == value)
                    ready.set()
                    release.wait(15)
                    stream.sendall(b"done")
            except BaseException:
                receiver_result.append(False)
                ready.set()
        receiver = threading.Thread(target=receive_publish, daemon=True)
        receiver.start()
        code = f"""
import ctypes, errno, fcntl, hashlib, os, resource, socket, sys
secret = os.read(0,4096)
assert hashlib.sha256(secret).hexdigest() == {digest(value)!r}
assert 'SPLAT_TEST_SERVICE_CREDENTIAL' not in os.environ
assert os.environ['SPLAT_PARAM_REGION'] == 'proof'
assert resource.getrlimit(resource.RLIMIT_CORE) == (0,0)
assert fcntl.fcntl(0,1034) & 15 == 15
for operation in [lambda: open('/proc/self/fd/0','rb'), lambda: socket.socket(socket.AF_UNIX), socket.socketpair]:
    try: operation()
    except OSError as error: assert error.errno in (errno.EPERM,errno.EACCES)
    else: raise AssertionError('secret transfer channel permitted')
open('secret-copy','wb').write(secret)
os.write(1,secret); os.write(2,secret)
ctypes.CDLL(None).prctl(15, ctypes.c_char_p(secret[:15]), 0, 0, 0)
blocked = socket.socket(); blocked.settimeout(2)
try: blocked.connect(('127.0.0.2',{port}))
except OSError as error: assert error.errno == errno.EPERM
else: raise AssertionError('unpinned destination permitted')
with socket.create_connection(('127.0.0.1',{port}),timeout=15) as connection:
    connection.sendall(secret)
    assert connection.recv(4) == b'done'
"""
        publishing = self.request("secret-proof-publisher", code)
        publishing.update(allowNetwork=True, allowedEgressIps=["127.0.0.1"], allowedEgressPorts=[port])
        publisher = self.grant(first, publishing, value)
        first.send(publisher)
        lease = first.receive()
        self.check("secret_lease_declared", lease.get("type") == "LEASE" and lease.get("secretStdin") is True
            and lease.get("processOutput") == "discarded" and lease.get("environmentMode") == "explicit")
        try:
            self.check("pinned_receiver_received_secret", ready.wait(12) and receiver_result == [True])
            pid = int(Path(lease["cgroupPath"], "cgroup.procs").read_text().split()[0])
            self.check("private_ipc_namespace", os.readlink(f"/proc/{pid}/ns/ipc") != os.readlink(f"/proc/{self.process.pid}/ns/ipc"))
            smaps = Path(f"/proc/{self.process.pid}/smaps").read_text()
            blocks = smaps.split("memfd:splat-step-input")
            self.check("sealed_input_resident_and_excluded_from_fork_and_dump", any(
                all(flag in block.split("VmFlags:", 1)[1].splitlines()[0].split() for flag in ["lo", "dc", "dd"])
                for block in blocks[1:] if "VmFlags:" in block))
            attacker_code = f"""
import errno, os
os.read(0,4096)
for path in ['/proc/{pid}/fd/0','/proc/{pid}/mem','/proc/{pid}/environ']:
    try: open(path,'rb')
    except OSError as error: assert error.errno in (errno.EACCES,errno.EPERM)
    else: raise AssertionError('sibling secret accessible')
"""
            sibling = self.grant(second, self.request("secret-proof-sibling", attacker_code), self.secret())
            sibling_frames = self.completed(second, sibling)
            sibling_lease = next(frame for frame in sibling_frames if frame["type"] == "LEASE")
            self.check("concurrent_secret_uids_distinct_and_proc_reads_denied", sibling_lease["workloadUid"] != lease["workloadUid"])
            self.check("legacy_uid_cannot_read_secret_process", bool(self.completed(second,
                self.request("secret-proof-legacy", attacker_code))))
            duplicate = self.request("secret-proof-publisher", "pass")
            duplicate["workingDirectory"] = str(self.root / "missions" / "different-workspace")
            self.check("duplicate_mission_cannot_replace_live_cgroup", self.refused(second, duplicate)
                and Path(f"/proc/{pid}").exists())
        finally:
            release.set()
            receiver.join(5)
            listener.close()
        frames = first.collect()
        final = frames[-1]
        self.check("publisher_completed_and_stdin_closed", final.get("exitCode") == 0 and final.get("secretStdinClosed") is True)
        self.check("secret_output_and_process_name_withheld", not any(f["type"] in ["STDOUT", "STDERR"] for f in frames)
            and any(f["type"] == "VIOLATION" and f.get("comm") == "[withheld]" for f in frames))
        self.check("secret_receipt_signature_binds_approved_request", self.verify_receipt(publisher, final))
        self.check("publisher_workspace_and_scratch_removed", final.get("workspaceRemoved") is True and self.wait_removed(publishing))

        for label, duration, disconnect in [("secret-proof-disconnect", 20, True), ("secret-proof-deadline", 5, False)]:
            session = self.session()
            request = self.request(label, "import os,time; os.read(0,4096); os.fork(); time.sleep(60)", duration)
            session.send(self.grant(session, request, self.secret()))
            self.check(label + "_started", session.receive().get("type") == "LEASE")
            if disconnect:
                session.close()
            else:
                self.check("deadline_killed_step", session.collect()[-1]["exitCode"] == -1)
            self.check(label + "_all_resources_removed", self.wait_removed(request))

        failing = self.request("secret-proof-spawn", "pass")
        failing.update(command="/etc/hostname", argv=[], allowedExecPaths=["/etc/hostname"])
        first.send(self.grant(first, failing, self.secret()))
        self.check("failed_spawn_closes_input_and_workspace", first.collect()[-1]["exitCode"] == -1 and self.wait_removed(failing))
        crashed = self.request("secret-proof-crash", "import os,time; os.read(0,4096); os.fork(); time.sleep(60)")
        first.send(self.grant(first, crashed, self.secret()))
        self.check("crash_step_started", first.receive().get("type") == "LEASE")
        self.stop(crash=True)
        self.start()
        self.check("restart_drained_secret_orphans", not (Path("/sys/fs/cgroup/splat_leases") / ("mission_" + crashed["missionId"])).exists())
        self.check("restart_removed_secret_workspaces", not Path(crashed["workingDirectory"]).exists()
            and not list((self.root / "missions" / ".secret-steps").iterdir()))
        self.check("restarted_daemon_enforces", self.session().health.get("enforcing") is True)
        self.log.flush()
        self.log.seek(0)
        logs = self.log.read()
        self.check("no_secret_payload_in_frames_or_service_log", all(value not in logs and all(
            value not in line for session in self.sessions for line in session.raw) for value in self.needles))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--retire-idle-pins", metavar="INSTALLED_BPF_SHA256",
        help="Explicitly retire this verified idle pin set during testing, then rebuild the installed service's pins on restoration")
    args = parser.parse_args()
    assert os.geteuid() == 0, "root is required"
    args.daemon = args.daemon.resolve(strict=True)
    source = Path(__file__).resolve().parent
    inputs = [source / "Cargo.toml", source / "Cargo.lock", source / "build.rs", *sorted((source / "src").rglob("*.rs")),
        *sorted((source / "src" / "bpf").glob("*.c")), *sorted((source / "src" / "bpf").glob("*.h"))]
    hashes = {str(path.relative_to(source)): digest(path.read_bytes()) for path in inputs}
    report = {"timestampUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kernel": os.uname().release,
        "daemonSha256": digest(args.daemon.read_bytes()), "sourceSha256": hashes,
        "probeSha256": digest(Path(__file__).read_bytes()), "syntheticOnly": True, "externalNetworkUsed": False,
        "checks": {}, "verdict": "FAIL"}
    was_active = subprocess.run(["systemctl", "is-active", "--quiet", "splat-agent.service"]).returncode == 0
    installed_sha = None
    if was_active:
        installed_pid = int(subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "splat-agent.service"]))
        installed_sha = digest(Path(f"/proc/{installed_pid}/exe").read_bytes())
    root = Path(tempfile.mkdtemp(prefix="splat-secret-proof-"))
    root.chmod(0o700)
    proof = Proof(args, root)
    stopped = False
    retired = False
    try:
        assert_idle()
        if was_active:
            subprocess.run(["systemctl", "stop", "splat-agent.service"], check=True)
            stopped = True
        if args.retire_idle_pins:
            assert stopped, "pin retirement requires an installed service to restore"
            retire_idle_pins(args.retire_idle_pins)
            retired = True
            report["retiredIdlePinHash"] = args.retire_idle_pins
        proof.start()
        proof.check("running_artifact_matches_recorded_binary", digest(Path(f"/proc/{proof.process.pid}/exe").read_bytes()) == report["daemonSha256"])
        proof.run()
        proof.check("sources_unchanged_during_proof", all(digest(path.read_bytes()) == hashes[str(path.relative_to(source))] for path in inputs))
        report["verdict"] = "PASS"
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        proof.stop()
        for session in proof.sessions:
            session.close()
        proof.log.close()
        if retired:
            try:
                retire_idle_pins(hashes["src/bpf/lease_lsm.bpf.c"])
                proof.checks["test_pins_retired_after_drain"] = True
            except BaseException as error:
                proof.checks["test_pins_retired_after_drain"] = False
                report["verdict"] = "FAIL"
                report["restorationError"] = f"{type(error).__name__}: {error}"
        if stopped:
            started = subprocess.run(["systemctl", "start", "splat-agent.service"]).returncode == 0
            restored = False
            if started:
                for _ in range(30):
                    try:
                        installed_pid = int(subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "splat-agent.service"]))
                        restored = digest(Path(f"/proc/{installed_pid}/exe").read_bytes()) == installed_sha
                        installed = Session(50051, Path("/etc/splat/agent.token").read_bytes().strip())
                        try:
                            restored = restored and installed.health.get("enforcing") is True
                        finally:
                            installed.close()
                        if restored:
                            break
                    except (OSError, ValueError, AssertionError, KeyError):
                        restored = False
                    time.sleep(0.2)
            proof.checks["installed_service_restored"] = restored
            if not restored:
                report["verdict"] = "FAIL"
        report["checks"] = proof.checks
        if report["verdict"] == "PASS":
            shutil.rmtree(root)
        else:
            report["diagnosticDirectory"] = str(root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"verdict": report["verdict"], "passed": sum(proof.checks.values()),
        "checks": len(proof.checks), "error": report.get("error"), "evidence": str(args.output)}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
