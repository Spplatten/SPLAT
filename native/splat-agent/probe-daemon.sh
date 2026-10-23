#!/usr/bin/env bash
# Exercise a RUNNING splat-agent over its JSON line protocol and report what the kernel actually did.
#
# The daemon must already be running as root in another terminal:
#     bash run-daemon.sh
#
# This is only a client, but it does need to READ the daemon's token: every request proves the
# root-owned 0600 secret - protocol 3 never sends it - so the one privileged step here is `sudo cat`
# on that file.
#
# Usage:  bash probe-daemon.sh [host:port] [token-file]
# Root lifecycle proof (stop the service/manual daemon first):
#   sudo env SPLAT_PROBE_DAEMON=/absolute/path/to/splat-agent bash probe-daemon.sh
# This mode owns the daemon it kills/restarts, retains its pins, and requires bpftool. Without it
# persistence checks remain false. Neither a replay nor an ordinary client run proves persistence.
set -uo pipefail
cd "$(dirname "$0")"
ADDR="${1:-127.0.0.1:50051}"
HOST="${ADDR%%:*}"
PORT="${ADDR##*:}"
TOKEN_FILE="${2:-/etc/splat/agent.token}"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

# Readable directly when the daemon was started with a token file in user space; otherwise this
# is the password prompt. Failing to read it is not fatal here - the probe goes on to be refused
# and says so plainly, which beats a silent run scoring six False against the wrong cause.
if [ -r "$TOKEN_FILE" ]; then
    TOKEN="$(cat "$TOKEN_FILE")"
else
    echo "  reading the daemon token from $TOKEN_FILE (needs sudo - it is root-owned 0600)"
    TOKEN="$(sudo cat "$TOKEN_FILE" 2>/dev/null || true)"
fi
[ -n "$TOKEN" ] || echo "  WARNING: no token read from $TOKEN_FILE - every EXECUTE_TOOL will be refused."

python3 - "$HOST" "$PORT" "$TOKEN" "$TOKEN_FILE" <<'PY'
import atexit, base64, errno, hashlib, hmac, json, os, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

host, port = sys.argv[1], int(sys.argv[2])
token = sys.argv[3] if len(sys.argv) > 3 else ""
token_file = sys.argv[4] if len(sys.argv) > 4 else "/etc/splat/agent.token"

# One entry per session: its label, and whether the daemon proved it holds the token. Kept out of the
# messages, which the checks below read as the daemon's own words.
handshakes = []

# One entry per session that asked for proven frames: its label, and whether the daemon agreed; and
# every frame that then failed to prove itself for its place. Since 2026-09-23 (roadmap 2.6).
frame_sessions = []
frame_failures = []

# ------------------------------------------------------------------------------------------------
# REPLAY: the scoring below, run against recorded frames instead of a live daemon.
#
# The two defects the 2026-09-26 root run exposed were both in the scoring, not the kernel: the
# datagram claim read a lost frame instead of the kernel's own counter, and a five-part AND recorded
# nothing but its False. Finding those cost a root run each - a stopped service, a rebuild, two probe
# runs and an operator's attention - to learn that this script could not read evidence it already had.
#
# A fixture naming what the daemon said, per session label, makes that class of defect reachable from
# the test suite. Everything downstream runs unchanged: the same `call` contract, the same `show`, the
# same forty checks, the same verdict. It is the shipping scoring code that gets tested, not a copy of
# it - the distinction that mattered when a base64 NameError passed a test whose namespace supplied
# what the script lacked, then died on the operator's run.
#
# What a replay CANNOT establish: anything read from this machine rather than from a frame. The
# handshake list stays empty unless the fixture supplies it, `/home` and `/mnt` are the host's, and a
# workspace path either exists here or does not. Those checks are the live daemon's to answer, and a
# replay verdict is therefore never evidence about a kernel. SPLAT_EVIDENCE_DIR should point somewhere
# disposable, and the run announces itself so no reader mistakes its output for a proof.
# ------------------------------------------------------------------------------------------------
replay = None
replay_path = os.environ.get("SPLAT_PROBE_REPLAY")
if replay_path:
    with open(replay_path) as f:
        fixture = json.load(f)
    replay = fixture.get("sessions", {})
    handshakes.extend((label, bool(proven)) for label, proven in fixture.get("handshakes", []))
    frame_sessions.extend((label, bool(agreed)) for label, agreed in fixture.get("frameSessions", []))
    frame_failures.extend(fixture.get("frameFailures", []))
    print(f"== REPLAY: scoring {len(replay)} recorded session(s) from {replay_path} ==")
    print("   No daemon is contacted. This output is a test of the checks, never evidence about a kernel.")
    print()

managed_binary = os.environ.get("SPLAT_PROBE_DAEMON") if replay is None else None
managed_process = None
managed_log = None
managed_args = None
managed_policy = None

def stop_owned():
    if managed_process is not None and managed_process.poll() is None:
        managed_process.terminate()
        try:
            managed_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            managed_process.kill()
            managed_process.wait(timeout=5)

def log_tail():
    managed_log.seek(0)
    return managed_log.read().decode(errors="replace")[-4000:]

def launch_owned():
    global managed_process
    managed_log.seek(0)
    managed_log.truncate()
    managed_process = subprocess.Popen(managed_args, stdout=managed_log, stderr=subprocess.STDOUT)
    return managed_process

def start_owned():
    proc = launch_owned()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("probe daemon did not start: " + log_tail())
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    stop_owned()
    raise RuntimeError("probe daemon did not listen within 30 seconds")

if managed_binary:
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or host not in ("127.0.0.1", "localhost"):
        sys.exit("SPLAT_PROBE_DAEMON requires root and a loopback address")
    if not os.path.isabs(managed_binary) or not os.access(managed_binary, os.X_OK):
        sys.exit("SPLAT_PROBE_DAEMON must name an absolute executable path")
    # Never signal an existing daemon, and never race systemd's automatic restart. The daemon's
    # singleton lock is a second guard when another instance listens on a different port.
    try:
        with socket.create_connection((host, port), timeout=0.2):
            sys.exit("stop the existing daemon before running the owned lifecycle probe")
    except OSError:
        pass
    managed_log = tempfile.TemporaryFile()
    managed_args = [managed_binary, "--listen", f"{host}:{port}", "--auth-token-file", token_file]
    # The owned probe explicitly exercises executable scratch without editing the installed
    # operator policy. Keep every existing ceiling, adding only this test's opt-in grant.
    policy_path = Path("/etc/splat/policy.json")
    probe_policy = json.loads(policy_path.read_text()) if policy_path.exists() else {
        "schema": 1, "allowedExecPrefixes": ["/"]}
    probe_policy["allowScratchExec"] = True
    managed_policy = tempfile.NamedTemporaryFile(mode="w", prefix="splat-probe-policy-", suffix=".json")
    json.dump(probe_policy, managed_policy)
    managed_policy.flush()
    managed_args.extend(["--policy-file", managed_policy.name])
    atexit.register(stop_owned)
    start_owned()
    with open(token_file) as f:
        token = f.read().strip()

def read_line(s, buf):
    """One frame from the socket, and whatever arrived after it."""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return line, rest

def prove(key, label, client_nonce, server_nonce, tail=b""):
    return hmac.new(key, label + bytes([0]) + client_nonce + server_nonce + tail, hashlib.sha256).hexdigest()

def call(req, label, settle=2.0, forge=None, clear=False):
    """Open a protocol 3 session, send one request, collect every response line until the daemon stops talking.

    The token never crosses the wire. The daemon proves it holds it first - recorded in `handshakes`
    and nothing is sent to a daemon that cannot - and the request carries a proof back. `forge`
    makes that proof under another key, as a caller without the token would; `clear` sends the request with
    the token in it instead, as a protocol 2 caller did.

    Under a replay fixture this returns what the daemon said in a recorded run and opens no socket. The
    hook sits here, at the one funnel every scoring input passes through, so a fixture reaches all
    forty checks without a single call site knowing about it. A label the fixture does not name returns
    None, which is the same thing a real failure to connect returns - so a fixture missing a session
    scores as "no daemon", never as "a daemon that said nothing".
    """
    if replay is not None:
        return replay.get(label)

    # Injected here rather than at the call sites, so no future probe can forget it.
    if req.get("type") == "EXECUTE_TOOL":
        req = dict(req, protocolVersion=3)
    out = []
    proves = False
    client_nonce = server_nonce = b""
    try:
        s = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"  [{label}] CANNOT CONNECT: {e}")
        return None
    with s:
        buf = b""
        try:
            if clear:
                s.sendall((json.dumps(dict(req, authToken=token)) + "\n").encode())
            else:
                client_nonce = os.urandom(32)
                # Ask for the daemon's frames to be proven, as the bridge does since 2026-09-23.
                hello = {"type": "HELLO", "protocolVersion": 3, "clientNonce": client_nonce.hex(), "proveFrames": True}
                s.sendall((json.dumps(hello) + "\n").encode())
                first, buf = read_line(s, buf)
                try:
                    challenge = json.loads(first)
                except ValueError:
                    challenge = {"type": "RAW", "data": first.decode(errors="replace")}
                if challenge.get("type") != "CHALLENGE":
                    out.append(challenge)
                    return out
                try:
                    server_nonce = bytes.fromhex(str(challenge.get("serverNonce", "")))
                except ValueError:
                    server_nonce = b""
                # A daemon that agrees to prove its frames proves the CHALLENGE under a label of its
                # own, so the agreement cannot be stripped off in transit; one that predates the field
                # answers under the plain label and unwrapped, and is scored below as not proving.
                proves = challenge.get("framesProven") is True
                daemon_label = b"splat-agent/3 daemon+frames" if proves else b"splat-agent/3 daemon"
                expected = prove(token.encode(), daemon_label, client_nonce, server_nonce)
                proven = len(server_nonce) == 32 and hmac.compare_digest(
                    expected.encode(), str(challenge.get("serverProof", "")).encode(errors="replace"))
                handshakes.append((label, proven))
                frame_sessions.append((label, proves))
                if not proven:
                    return out
                body = json.dumps(req)
                proof = prove((forge or token).encode(), b"splat-agent/3 request", client_nonce, server_nonce,
                              (0).to_bytes(8, "big") + body.encode())
                s.sendall((json.dumps({"type": "AUTHENTICATED", "proof": proof, "request": body}) + "\n").encode())
        except socket.timeout:
            out.append({"type": "RAW", "data": "no answer to the handshake"})
            return out
        s.settimeout(settle)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                # EXIT is the daemon's last word on a request, but it keeps the connection open for
                # the next one - so waiting for the socket to go quiet meant every call paid the
                # full settle timeout. That made elapsed time meaningless: the expiry probe read
                # 25.7s for a workload the reaper had killed at about 7.
                # Inside a PROVEN wrapper the frame's quotes are escaped, so the EXIT is looked for
                # in that spelling too.
                if b'"EXIT"' in buf or b'"type": "EXIT"' in buf or b'\\"type\\":\\"EXIT\\"' in buf:
                    break
        except socket.timeout:
            pass
    seq = 0
    for line in buf.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if proves:
            # On a session the daemon agreed to prove, every frame after the CHALLENGE travels in a
            # PROVEN wrapper, proven over both nonces, its number and its exact bytes. One that does
            # not, or whose proof does not hold for its place, is a finding rather than a frame.
            try:
                wrapper = json.loads(line)
            except json.JSONDecodeError:
                wrapper = None
            inner = wrapper.get("frame") if isinstance(wrapper, dict) and wrapper.get("type") == "PROVEN" else None
            if not isinstance(inner, str):
                frame_failures.append((label, "a frame arrived unwrapped: " + line[:80]))
                out.append({"type": "RAW", "data": line})
                continue
            expected = prove(token.encode(), b"splat-agent/3 frame", client_nonce, server_nonce,
                             seq.to_bytes(8, "big") + inner.encode())
            if not hmac.compare_digest(expected, str(wrapper.get("proof", ""))):
                frame_failures.append((label, f"frame {seq} did not prove itself for its place"))
            seq += 1
            line = inner
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"type": "RAW", "data": line})
    return out

def show(msgs, label):
    # Must hand back None, not []. Flattening "could not connect" into "connected and said
    # nothing" defeated the `allowed is None` guard below, so a run that reached no daemon at
    # all still scored every check False and wrote INCOMPLETE over committed PASS evidence.
    if msgs is None:
        return None
    print(f"  [{label}] {len(msgs)} message(s)")
    for m in msgs:
        t = m.get("type", "?")
        d = str(m.get("data", m.get("detail", m.get("exitCode", "")))).rstrip()
        if d:
            d = d if len(d) < 160 else d[:157] + "..."
            print(f"    {t}: {d}")
        else:
            print(f"    {t}")
    return msgs

print("== 1. health check ==")
health = show(call({"type": "HEALTH_CHECK"}, "health"), "health")

print()
# Arguments travel as an explicit argv array. The daemon used to receive one string and split it
# on whitespace, so `-c cat /etc/shadow` became `sh -c cat` with the path as $0 and cat then read
# stdin and hung - which is why every probe here used to be restricted to single-token arguments.
# Each request also names its own allowedExecPaths rather than relying on the daemon's legacy
# default set, so what each probe permits is stated here rather than inherited.
print("== 2. PERMITTED: run the requested tool itself ==")
print("   The lease allow-lists the command it was asked to run, so this must succeed.")
allowed = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-allowed",
    "command": "/usr/bin/id", "argv": [],
    "allowedExecPaths": ["/usr/bin/id"],
    "leaseDurationSeconds": 20,
}, "allowed"), "allowed")

print()
print("== 3. FORBIDDEN: read a protected inode ==")
print("   /etc/shadow is the wrong file for this now. The workload runs as nobody, so mode 640")
print("   denies the read in the DAC check before security_file_open is ever reached - the probe")
print("   passed for a reason that had nothing to do with the lease. /etc/hostname is 644, so")
print("   nobody CAN read it, and only the LSM can stop them. Control first, then the test.")

readable_control = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-readable",
    "command": "/bin/cat", "argv": ["/etc/hostname"],
    "allowedExecPaths": ["/bin/cat"],
    "leaseDurationSeconds": 20,
}, "readable-control"), "readable-control")

shadow = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-shadow",
    "command": "/bin/cat", "argv": ["/etc/hostname"],
    "allowedExecPaths": ["/bin/cat"],
    "protectedPaths": ["/etc/hostname"],
    "leaseDurationSeconds": 20,
}, "protected"), "protected")

print()
print("== 4. FORBIDDEN: an ALLOWED tool reaching for an unleased binary ==")
print("   /bin/sh is the ONLY entry in this lease's allow-list; dpkg is not. sh runs, then its")
print("   exec of dpkg must be refused. Requesting dpkg directly would not test this - the lease")
print("   has to stop the SECOND exec, which is the one the caller never declared.")
dpkg = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-exec",
    "command": "/bin/sh", "argv": ["-c", "dpkg --version"],
    "allowedExecPaths": ["/bin/sh"],
    "leaseDurationSeconds": 20,
}, "exec"), "exec")

print()
print("== 5. EGRESS: allow-list, with the network switch ON ==")
print("   allowNetwork must be true or the lease seeds NO addresses and denies everything -")
print("   which would make the 1.1.1.1 case pass for the wrong reason. With it on, 127.0.0.1:80 is")
print("   the one permitted endpoint (a refused connection is fine: the kernel PERMITTED the")
print("   syscall), and 1.1.1.1 must be refused by the allow-list itself.")
egress_ok = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-ok",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "http://127.0.0.1/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [80],
    "leaseDurationSeconds": 20,
}, "egress-allowed", settle=6.0), "egress-allowed")

egress_bad = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-bad",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "http://1.1.1.1/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [80],
    "leaseDurationSeconds": 20,
}, "egress-denied", settle=6.0), "egress-denied")

print()
print("== 6. EGRESS: the network switch OFF denies even the permitted address ==")
print("   The lease names 127.0.0.1:80 and the switch is off, so deny-by-default must hold even")
print("   for the endpoint the request declared.")
egress_off = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-off",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "http://127.0.0.1/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": False, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [80],
    "leaseDurationSeconds": 20,
}, "egress-off", settle=6.0), "egress-off")

print()
print("== 7. PRIVILEGE: the workload must not be running as root ==")
print("   The daemon needs root to load BPF and write the cgroup tree; the TOOL needs none of it.")
print("   It used to inherit uid 0, so every hook was being asked to hold against a root process.")
priv = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-priv",
    "command": "/usr/bin/id", "argv": ["-u"],
    "allowedExecPaths": ["/usr/bin/id"],
    "leaseDurationSeconds": 20,
}, "priv"), "priv")

print()
print("== 8. ISOLATION: one lease must not lend its permissions to another (F06) ==")
print("   A allow-lists /bin/cat and holds its lease open; B allow-lists only /bin/sh and tries")
print("   to exec cat while A is still live. Keyed by resource alone, B would inherit A's grant.")

concurrent = {}

def hold_lease_a():
    # Long enough that B runs entirely inside A's lease. /bin/sleep must be in A's allow-list
    # too, since a leased process may only exec what its own lease names.
    concurrent["a"] = call({
        "type": "EXECUTE_TOOL", "missionId": "probe-iso-a",
        "command": "/bin/sh", "argv": ["-c", "sleep 4"],
        "allowedExecPaths": ["/bin/sh", "/bin/cat", "/bin/sleep", "/usr/bin/sleep"],
        "leaseDurationSeconds": 20,
    }, "iso-a", settle=8.0)

t = threading.Thread(target=hold_lease_a, daemon=True)
t.start()
time.sleep(1.5)  # let A's lease install before B asks

iso_b = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-iso-b",
    "command": "/bin/sh", "argv": ["-c", "cat /etc/hostname"],
    "allowedExecPaths": ["/bin/sh"],
    "leaseDurationSeconds": 20,
}, "iso-b", settle=6.0), "iso-b")
t.join(timeout=15)
iso_a = show(concurrent.get("a"), "iso-a")

print()
print("== 9. EGRESS PORT: an approved host is not approved on every port (F08) ==")
print("   The lease names 127.0.0.1:80. A connect to 127.0.0.1:9999 must be refused - the key")
print("   used to carry no port at all, so approving a host approved every port it listened on.")
port_bad = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-port",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "http://127.0.0.1:9999/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [80],
    "leaseDurationSeconds": 20,
}, "port-denied", settle=6.0), "port-denied")

print()
print("== 10. EGRESS IPv6: denied outright, since the lease has no v6 vocabulary (F08) ==")
print("   This used to fall through to ALLOW, which made allowNetwork mean 'no IPv4'.")
v6 = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-v6",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "-6", "http://[::1]:80/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [80],
    "leaseDurationSeconds": 20,
}, "ipv6-denied", settle=6.0), "ipv6-denied")

print()
print("== 11. EXPIRY: an overrunning workload is KILLED, not merely unpoliced (F05) ==")
print("   A 5s lease around a 60s sleep. The reaper must kill the cgroup inside its policy;")
print("   before this it deleted the map entries and left the process running, unwatched.")
expiry_start = time.time()
expiry = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-expiry",
    "command": "/bin/sh", "argv": ["-c", "sleep 60"],
    "allowedExecPaths": ["/bin/sh", "/bin/sleep", "/usr/bin/sleep"],
    "leaseDurationSeconds": 5,
}, "expiry", settle=25.0), "expiry")
expiry_elapsed = time.time() - expiry_start

print()
print("== 12. UNDECLARED POLICY: a lease that names nothing is refused, not defaulted ==")
print("   An absent allowedEgressIps used to mean 127.0.0.1 and ports 80/443, and an absent")
print("   allowedExecPaths meant sh, ping and curl. A caller that forgot a field was handed a")
print("   lease wider than it asked for. Both must now be refused before any lease exists.")
undeclared_egress = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-undeclared-egress",
    "command": "/usr/bin/curl",
    "argv": ["--max-time", "3", "-s", "-o", "/dev/null", "http://127.0.0.1/"],
    "allowedExecPaths": ["/usr/bin/curl"],
    "allowNetwork": True, "leaseDurationSeconds": 20,
}, "undeclared-egress"), "undeclared-egress")

undeclared_exec = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-undeclared-exec",
    "command": "/usr/bin/id", "argv": [],
    "leaseDurationSeconds": 20,
}, "undeclared-exec"), "undeclared-exec")

print()
print("== 13. HEALTH CHECK: the state of this host is not public either ==")
print("   It answers with `enforcing`, the kernel version and the live lease count. A request whose")
print("   proof was made without the token is refused. Check 1 above is the control, and its session")
print("   also records that the daemon proved it holds the token before anything was sent to it.")
unauth_health = show(call({"type": "HEALTH_CHECK"}, "health-unauthenticated", forge="not the daemon's token"), "health-unauthenticated")

print()
print("== 14. PROTOCOL 2: the token in the clear is refused, even the right one ==")
print("   Protocol 2 put the token in every request, so a caller handed it to whatever held the port.")
print("   A daemon that still accepted that form would make capturing the token worth something.")
clear_health = show(call({"type": "HEALTH_CHECK"}, "health-protocol-2", clear=True), "health-protocol-2")

print()
print("== 15. UDP: a datagram names its own destination, and is judged like a connection ==")
print("   sendto() on an unconnected socket never reaches socket_connect, so every leased process")
print("   had a full UDP path out - DNS included - while allowNetwork:false read as 'no network'.")
print("   Both halves, because refusals alone would also be what a broken chain produces.")
# The sentinel is assembled at runtime so it does not appear in the source line. When sendto is
# refused, python's traceback echoes the statement it died on - and on 2026-09-29 that echo carried the
# literal 'SENT', so the "did it go out" guard matched the error message rather than any output and
# scored a refusal the kernel had made as a send it had allowed. Split here, so the only way the word
# reaches a frame whole is print() actually running.
udp_bad = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-udp-bad",
    "command": "/usr/bin/python3",
    "argv": ["-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                   "print('SE'+'NT' if s.sendto(b'x',('1.1.1.1',53)) else 'NOTHI'+'NG')"],
    "allowedExecPaths": ["/usr/bin/python3"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [53],
    "leaseDurationSeconds": 20,
}, "udp-outside"), "udp-outside")
udp_ok = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-udp-ok",
    "command": "/usr/bin/python3",
    "argv": ["-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                   "print('SE'+'NT' if s.sendto(b'x',('127.0.0.1',53)) else 'NOTHI'+'NG')"],
    "allowedExecPaths": ["/usr/bin/python3"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [53],
    "leaseDurationSeconds": 20,
}, "udp-inside"), "udp-inside")

print()
print("== 16. JAIL: the workload's root holds the system, the workdir and nothing else ==")
print("   /home and /mnt are not hidden by a deny-list; they are absent from the root the workload")
print("   sees. The system directories are read-only, /tmp is fresh and writable, the working")
print("   directory is writable unless readOnlyFs says otherwise. All from sh builtins, so each")
print("   lease needs nothing but /bin/sh. The host's own /home and /mnt are the control.")
jail_ws = "/tmp/splat-probe-ws"
os.makedirs(jail_ws, exist_ok=True)
os.chmod(jail_ws, 0o777)  # the workload is nobody, and the write below is the measurement
jail_absent = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-jail-absent",
    "command": "/bin/sh",
    "argv": ["-c", "for d in /home /mnt /root /var /sys; do [ -e \"$d\" ] && echo \"VISIBLE $d\" || echo \"ABSENT $d\"; done"],
    "allowedExecPaths": ["/bin/sh"], "workingDirectory": jail_ws,
    "leaseDurationSeconds": 20,
}, "jail-absent"), "jail-absent")
jail_ro = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-jail-ro",
    "command": "/bin/sh",
    "argv": ["-c", "( echo x > /usr/bin/splat-probe-write ) 2>&1; [ -e /usr/bin/splat-probe-write ] && echo WROTE_SYSTEM || echo SYSTEM_READONLY"],
    "allowedExecPaths": ["/bin/sh"], "workingDirectory": jail_ws,
    "leaseDurationSeconds": 20,
}, "jail-ro"), "jail-ro")
jail_rw = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-jail-rw",
    "command": "/bin/sh",
    "argv": ["-c", "echo x > ./probe-rw && echo WROTE_WORKDIR; echo y > /tmp/probe-tmp && echo WROTE_TMP; [ -e /etc/hostname ] && echo ETC_VISIBLE"],
    "allowedExecPaths": ["/bin/sh"], "workingDirectory": jail_ws,
    "leaseDurationSeconds": 20,
}, "jail-rw"), "jail-rw")
jail_rofs = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-jail-rofs",
    "command": "/bin/sh",
    "argv": ["-c", "( echo x > ./probe-ro ) 2>&1; [ -e ./probe-ro ] && echo WROTE_WORKDIR || echo WORKDIR_READONLY"],
    "allowedExecPaths": ["/bin/sh"], "workingDirectory": jail_ws, "readOnlyFs": True,
    "leaseDurationSeconds": 20,
}, "jail-readonly"), "jail-readonly")
host_has_the_dirs = os.path.isdir("/home") and os.path.isdir("/mnt")
import shutil
shutil.rmtree(jail_ws, ignore_errors=True)

print()
print("== 17. THE MISSION WORKSPACE: made by the daemon for the lease, and gone with it ==")
print("   A governed mission from Windows cannot make a directory in the guest; the lease asks the")
print("   daemon to, under its missions root only. The LEASE frame says it was made, the tool")
print("   writes in it, EXIT says it went, and the host's view is the control.")
missions_root = "/var/lib/splat/missions"
mission_ws = missions_root + "/probe-workspace"
shutil.rmtree(mission_ws, ignore_errors=True)
workspace = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-workspace",
    # Shell builtins and a redirection only. `touch` and `ls` are separate binaries and this lease
    # allow-lists /bin/sh alone, so on 2026-09-29 the kernel refused both - correctly - and the check
    # read that as the daemon failing to make a usable workspace. The test was asking for execs it had
    # not declared. `: > file` creates it with no exec at all, which is the discipline check 16 already
    # follows: a lease that needs nothing but /bin/sh tests the jail rather than the allow-list.
    "command": "/bin/sh", "argv": ["-c", "pwd; : > made-here && echo WROTE_WORKSPACE"],
    "allowedExecPaths": ["/bin/sh"],
    "workingDirectory": mission_ws, "ephemeralWorkspace": True,
    "leaseDurationSeconds": 20,
}, "workspace"), "workspace")
workspace_gone_after = not os.path.exists(mission_ws)
# And one that asks for a workspace somewhere else, which must be refused before anything is made.
elsewhere = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-workspace-elsewhere",
    "command": "/bin/sh", "argv": ["-c", "echo RAN"],
    "allowedExecPaths": ["/bin/sh"],
    "workingDirectory": "/tmp/splat-probe-elsewhere", "ephemeralWorkspace": True,
    "leaseDurationSeconds": 20,
}, "workspace-elsewhere"), "workspace-elsewhere")
elsewhere_not_made = not os.path.exists("/tmp/splat-probe-elsewhere")
# And one refused AFTER the workspace was made: a protected path the guest does not hold fails the
# lease install, which comes after the directory exists. The refusal must take the directory with
# it and the EXIT frame must say so; three refused missions left theirs behind on 2026-09-24.
refused_ws = missions_root + "/probe-workspace-refused"
shutil.rmtree(refused_ws, ignore_errors=True)
refused_after = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-workspace-refused",
    "command": "/bin/sh", "argv": ["-c", "echo RAN"],
    "allowedExecPaths": ["/bin/sh"],
    "protectedPaths": ["/nonexistent/splat-probe-never-here"],
    "workingDirectory": refused_ws, "ephemeralWorkspace": True,
    "leaseDurationSeconds": 20,
}, "workspace-refused-after-creation"), "workspace-refused-after-creation")
refused_ws_gone = not os.path.exists(refused_ws)

def had(msgs, t):
    return any(m.get("type") == t for m in (msgs or []))

def text(msgs):
    return " ".join(str(m.get("data", "")) for m in (msgs or []))

def stdout_text(msgs):
    """Only what the workload PRINTED, never what failed about it.

    `text` joins every frame, error text included. A check that asks "did the tool report X" and reads
    that is asking "does X appear anywhere, including in the message explaining why it did not happen".
    On 2026-09-29 the datagram check paid for exactly that: python's traceback echoed the statement it
    died on, the echo carried the sentinel, and a refusal the kernel had made scored as a send.
    """
    return " ".join(str(m.get("data", "")) for m in (msgs or []) if m.get("type") == "STDOUT")

print()
print("=" * 68)
print("READING")
print("=" * 68)

if allowed is None:
    print("  Daemon not reachable - start it as root first, then run this client against it.")
    sys.exit(2)

# A request refused at the daemon's gate - wrong credential, unsupported protocol version - is
# turned away before any lease is installed. That is not a containment measurement: every check
# below would read False and the verdict written would describe this probe's own envelope rather
# than the kernel. Stop before the evidence write, and name the gate that refused.
refusal = text(allowed)
if "SPLAT refused the request" in refusal:
    print("  Refused at the daemon's gate - no lease was installed, so nothing here is a")
    print("  measurement of containment:")
    print(f"    {refusal.strip()}")
    sys.exit(3)

shadow_text = text(shadow)
control_text = text(readable_control)
# The control has to actually read the file, or the "protected" case proves nothing: a denial is
# only evidence when the same read succeeds without the protection.
control_read_it = bool(control_text.strip()) and "Permission denied" not in control_text
leaked = control_read_it and control_text.strip() in shadow_text
mode_denied = "Permission denied" in shadow_text and not had(shadow, "VIOLATION")

print(f"  permitted tool ran             : {'uid=' in text(allowed)}")
print(f"  control read the file unprotected : {control_read_it}")
print(f"  protected file contents leaked : {leaked}")
print(f"  kernel VIOLATION for the read  : {had(shadow, 'VIOLATION')}")
if mode_denied:
    print("    ^ denied by file mode, not by the lease - the read was refused before the hook ran")
if not control_read_it:
    print("    ^ the CONTROL could not read it either, so the denial above proves nothing")
print(f"  unleased second exec blocked   : {had(dpkg, 'VIOLATION')}")
print(f"  dpkg output leaked             : {'dpkg' in text(dpkg).lower() and 'version' in text(dpkg).lower()}")
print()
# "No violation" is not the same as "allowed" - a request that never answered also has no
# violation. Require the daemon to have actually said something before scoring it as permitted.
def answered(msgs):
    return bool(msgs)

silent = [n for n, m in (("egress-allowed", egress_ok), ("egress-denied", egress_bad), ("egress-off", egress_off)) if not answered(m)]
if silent:
    print(f"  !! no response at all from: {', '.join(silent)} - cannot score these, raise settle")
print(f"  egress to 127.0.0.1 permitted  : {answered(egress_ok) and not had(egress_ok, 'VIOLATION')}")
print(f"  egress to 1.1.1.1 refused      : {had(egress_bad, 'VIOLATION')}")
print(f"  network OFF denies 127.0.0.1   : {had(egress_off, 'VIOLATION')}")
print(f"  every request sent EXIT        : {all(had(m, 'EXIT') for m in (allowed, shadow, dpkg, egress_ok, egress_bad, egress_off))}")

# The tool prints its own numeric uid; anything but 0 is the property, and an empty answer is not
# evidence of anything.
priv_uid = text(priv).strip().splitlines()
priv_uid = priv_uid[0].strip() if priv_uid else ""
workload_not_root = priv_uid.isdigit() and priv_uid != "0"
print()
print(f"  workload uid (not 0)           : {workload_not_root}  (reported: {priv_uid or 'nothing'})")
# B must be refused. Its own output must NOT contain the file it tried to read through cat.
iso_holds = had(iso_b, "VIOLATION") and "localhost" not in text(iso_b)
print(f"  B denied A's executable        : {iso_holds}")
print(f"  A itself still ran             : {had(iso_a, 'EXIT')}")
print(f"  wrong port refused             : {had(port_bad, 'VIOLATION')}")
print(f"  IPv6 refused                   : {had(v6, 'VIOLATION')}")
# A killed workload exits by SIGNAL, so the daemon reports no exit code and sends -1; a sleep that
# ran its full 60s exits 0. Both the code and the clock have to agree, because -1 is also what a
# refused request returns - and a refusal arrives with STDERR text, which this checks for too.
expiry_code = next((m.get("exitCode") for m in (expiry or []) if m.get("type") == "EXIT"), None)
expiry_refused = "SPLAT refused" in text(expiry)
expiry_killed = (
    had(expiry, "EXIT")
    and not expiry_refused
    and expiry_code == -1
    and expiry_elapsed < 30
)
print(f"  expiry killed the workload     : {expiry_killed}  (exit {expiry_code} after {expiry_elapsed:.1f}s of a 60s sleep)")

# The refusal must name the field that was missing, and it must arrive INSTEAD of a run: a daemon
# that refused and executed anyway would still show the refusal text.
def refused_naming(msgs, field):
    body = text(msgs)
    return "SPLAT refused the request" in body and field in body and not had(msgs, "STDOUT")

undeclared_egress_refused = refused_naming(undeclared_egress, "allowedEgressIps")
undeclared_exec_refused = refused_naming(undeclared_exec, "allowedExecPaths")
print(f"  undeclared egress refused      : {undeclared_egress_refused}")
print(f"  undeclared exec list refused   : {undeclared_exec_refused}")

# Both halves, or neither is a measurement: a daemon that answered nobody would also score the
# refusal True.
health_answered = had(health, "HEALTH_RESPONSE")
unauth_health_refused = not had(unauth_health, "HEALTH_RESPONSE") and "proof" in text(unauth_health)
daemon_proved_itself = bool(handshakes) and all(proven for _, proven in handshakes)
clear_token_refused = not had(clear_health, "HEALTH_RESPONSE") and "protocol 3" in text(clear_health)
# Every session that asked was agreed to, and every frame on them proved itself for its place.
daemon_frames_proven = bool(frame_sessions) and all(p for _, p in frame_sessions) and not frame_failures
print(f"  health check answers a holder  : {health_answered}")
print(f"  health check refuses a stranger: {unauth_health_refused}")
print(f"  daemon proved it holds token   : {daemon_proved_itself}")
print(f"  token in the clear refused     : {clear_token_refused}")
print(f"  daemon frames proven           : {daemon_frames_proven}")
for session_label, why in frame_failures:
    print(f"    [{session_label}] {why}")

# The jail. Absence is only a measurement when the host has the directory: a guest with no /mnt
# would score "absent" for the wrong reason, so the host's own view is the control.
jail_absent_text = text(jail_absent)
jail_hides_host = (
    host_has_the_dirs
    and "ABSENT /home" in jail_absent_text
    and "ABSENT /mnt" in jail_absent_text
    and "VISIBLE" not in jail_absent_text
)
jail_system_ro = "SYSTEM_READONLY" in text(jail_ro) and "WROTE_SYSTEM" not in text(jail_ro)
jail_rw_text = text(jail_rw)
jail_workdir_rw = "WROTE_WORKDIR" in jail_rw_text and "WROTE_TMP" in jail_rw_text and "ETC_VISIBLE" in jail_rw_text
jail_readonly_fs = "WORKDIR_READONLY" in text(jail_rofs) and "WROTE_WORKDIR" not in text(jail_rofs)
# The LEASE frame: what the daemon installed, told before the tool ran. Scored on the permitted
# session, where a real cgroup under live hooks must report itself as enforcing.
def lease_frame(msgs):
    return next((m for m in (msgs or []) if m.get("type") == "LEASE"), None)
lease_reports_enforcing = bool(lease_frame(allowed)) and lease_frame(allowed).get("enforcing") is True
# The mission workspace: made for the lease (the frame says so and the tool wrote in it), gone
# after it (EXIT says so and the host agrees), and refused anywhere but under the missions root.
ws_frame = lease_frame(workspace) or {}
ws_exit = next((m for m in (workspace or []) if m.get("type") == "EXIT"), {})
# Five separate measurements rather than one conjunction. The 2026-09-26 run scored this False and
# the evidence recorded nothing but the False, so the next root run - which costs the operator a
# service stop and two probe runs - would have had to be spent finding out which half was wrong.
# A composite that cannot say where it broke turns one expensive run into two.
workspace_frame_says_created = ws_frame.get("workspaceCreated") is True
workspace_path_announced = mission_ws in text(workspace)
workspace_tool_wrote_in_it = "WROTE_WORKSPACE" in text(workspace)
workspace_exit_says_removed = ws_exit.get("workspaceRemoved") is True
workspace_made_and_removed = (
    workspace_frame_says_created
    and workspace_path_announced
    and workspace_tool_wrote_in_it
    and workspace_exit_says_removed
    and workspace_gone_after
)
workspace_elsewhere_refused = (
    "SPLAT refused the request" in text(elsewhere)
    and "ephemeralWorkspace" in text(elsewhere)
    and "RAN" not in text(elsewhere)
    and elsewhere_not_made
)
refused_exit = next((m for m in (refused_after or []) if m.get("type") == "EXIT"), {})
workspace_removed_on_refusal = (
    "could not be installed" in text(refused_after)
    and "RAN" not in text(refused_after)
    and refused_exit.get("workspaceRemoved") is True
    and refused_ws_gone
)
# The datagram hook. The permitted half is the control: a lease that refused every datagram would
# score the refusal True and prove only that nothing works.
udp_frame_reached_the_session = had(udp_bad, "VIOLATION")
udp_allowed = "SENT" in stdout_text(udp_ok) and not had(udp_ok, "VIOLATION")

# The receipt, not the wall. A lease's EXIT carries the kernel's own count for its cgroup, how
# many VIOLATION frames the caller was sent, and whether those agree. This exists because on
# 2026-09-25 udp_blocked scored false while the run's violation list held the denial: the kernel
# refused the datagram and the frame missed its session, and nothing in the result said so. A
# short receipt that announces itself is recoverable; a silent one is not.
def exit_frame(msgs):
    return next((m for m in (msgs or []) if m.get("type") == "EXIT"), {})

udp_bad_exit = exit_frame(udp_bad)
refusal_receipt_counted = udp_bad_exit.get("violationsCounted", 0) >= 1
refusal_receipt_complete = udp_bad_exit.get("violationsComplete") is True
# The permitted half refused nothing, and its receipt must say zero rather than stay silent:
# a field that only ever appears after a denial cannot be read as "nothing was denied".
clean_receipt_counted_zero = exit_frame(udp_ok).get("violationsCounted") == 0

# The datagram claim, assembled from BOTH signals now that the receipt exists.
#
# On 2026-09-25 and again on 2026-09-26 this scored False while the kernel had refused the
# datagram: the VIOLATION frame missed its session, and frame delivery was the only thing being
# read. A proof harness that reports a working denial as broken is worse than one that reports
# nothing, because the repair gets aimed at the kernel instead of at the messenger.
#
# So the claim is scored from the receipt - the per-cgroup counter read out of the BPF map, which
# `violationsComplete` asserts is a complete count - OR from a delivered frame, and in either case
# only when the datagram did not go out. The "SENT" guard is what keeps this from being a weaker
# test: a counted violation from something unrelated cannot stand in for a send that succeeded.
#
# Frame delivery stays recorded on its own below. Folding it into the claim would have hidden the
# race rather than measured it, and the race is a real defect in the return path.
udp_blocked = (
    (refusal_receipt_counted and refusal_receipt_complete) or udp_frame_reached_the_session
) and "SENT" not in stdout_text(udp_bad)

# Roadmap 2.5: the guest signs what the lease did, so a record cannot claim more than the guest
# said. Verified here the way a stranger's script verifies it - PKCS#1 v1.5 over the exact text the
# daemon signed - and in both directions, because a signature nobody can forge proves nothing if an
# edited outcome passes it too.
signed_exit = exit_frame(allowed)
signed_text = signed_exit.get("outcomeCanonical")
signed_sig = signed_exit.get("outcomeSignature")
signed_key = signed_exit.get("outcomePublicKey")

def rsa_pkcs1_verifies(public_der_b64, message, signature_b64):
    der = base64.b64decode(public_der_b64)
    def length(at):
        size = der[at]; at += 1
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(der[at:at + count], 'big'); at += count
        return size, at
    if der[0] != 0x30:
        return False
    _, at = length(1)
    numbers = []
    for _ in range(2):
        if der[at] != 0x02:
            return False
        size, at = length(at + 1)
        numbers.append(int.from_bytes(der[at:at + size], 'big')); at += size
    modulus, exponent = numbers
    signature = base64.b64decode(signature_b64)
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    decrypted = pow(int.from_bytes(signature, 'big'), exponent, modulus).to_bytes(size, 'big')
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(message).digest()
    padding = bytes([255]) * (size - len(digest_info) - 3)
    expected = bytes([0, 1]) + padding + bytes([0]) + digest_info
    return decrypted == expected

outcome_signed = bool(signed_text and signed_sig and signed_key)
outcome_verifies = outcome_signed and rsa_pkcs1_verifies(signed_key, signed_text.encode('utf-8'), signed_sig)
outcome_edit_refused = outcome_signed and not rsa_pkcs1_verifies(
    signed_key, signed_text.replace('exit=0', 'exit=1').encode('utf-8'), signed_sig)
print()
print(f"  UDP outside the lease refused  : {udp_blocked}")
print(f"  ... its VIOLATION frame arrived : {udp_frame_reached_the_session}  "
      f"(False = the kernel refused it but the caller was not told in-session)")
print(f"  UDP inside the lease permitted : {udp_allowed}  (the control)")

print()
print(f"  host has /home and /mnt        : {host_has_the_dirs}  (the control for the line below)")
print(f"  jail hides /home and /mnt      : {jail_hides_host}")
print(f"  system dirs read-only in jail  : {jail_system_ro}")
print(f"  workdir, /tmp writable, /etc visible : {jail_workdir_rw}")
print(f"  readOnlyFs makes workdir read-only   : {jail_readonly_fs}")
print()
print(f"  LEASE frame reports enforcing  : {lease_reports_enforcing}")
print(f"  workspace made, used, removed  : {workspace_made_and_removed}")
print(f"  workspace elsewhere refused    : {workspace_elsewhere_refused}")
print(f"  workspace removed on refusal   : {workspace_removed_on_refusal}")

# These are separate from the historical checks: an older PASS contains no evidence for either
# feature. Unrun root measurements stay false, and fixture replay never executes this block.
feature_checks = dict.fromkeys([
    "cow_overlay_in_child", "cow_host_unchanged", "cow_no_host_mount", "cow_concurrent_isolation",
    "cow_scratch_removed", "cow_read_only_honored", "cow_bad_options_refused", "cow_inode_overlap_refused",
    "scratch_exec_inside", "scratch_exec_outside_denied", "scratch_exec_default_denied",
    "scratch_exec_other_lease_denied", "scratch_exec_fd_scoped", "scratch_exec_map_removed",
    "scratch_exec_layer_removed", "scratch_exec_requires_cow", "scratch_exec_ceiling_refused",
    "pins_survive_sigkill", "pins_exec_denied_during_outage", "pins_file_denied_during_outage",
    "pins_allowed_exec_during_outage", "pins_no_daemon_during_measurement", "pins_same_ids_after_restart",
    "pins_restart_enforces", "pins_orphans_drained", "pins_wrong_hash_refused",
    "pins_partial_set_refused", "pins_foreign_map_refused",
    "expiry_no_daemon_during_measurement", "expiry_allowed_until_deadline",
    "expiry_exec_denied_without_daemon", "expiry_open_denied_without_daemon", "expiry_overrun_within_1s",
], False)
feature_observations = {"errors": [], "lifecycle_requested": bool(managed_binary)}

# Cross-lease reach between two ORDINARY leases. True means the operation SUCCEEDED from lease A
# against lease B - the isolation gap is present. These are kept apart from feature_checks on
# purpose: feature_checks read True == contained, but here True == reachable, so folding them into
# the PASS conjunction with that polarity would score a confirmed gap as a clean run. They are raw
# facts about an area SUPPORTED_POLICY.md's "Not policed" table governs, recorded and never gated,
# the same shape as udp_violation_frame_reached_the_session below. Initialised False so a non-root
# or replay run records them False, the rule every other root-only measurement already follows.
cross_lease = dict.fromkeys([
    "control_ops_possible", "signal_reaches_peer", "proc_cwd_readlinked",
    "proc_root_readlinked", "peer_workspace_read", "peer_workspace_written",
], False)
cross_lease_observations = {}

def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False

def completed(msgs):
    return exit_frame(msgs).get("exitCode") == 0 and (lease_frame(msgs) or {}).get("enforcing") is True

def probe_cow():
    host_overlays = lambda: {line for line in Path("/proc/self/mountinfo").read_text().splitlines() if " - overlay " in line}
    overlays_before = host_overlays()
    ws = Path(tempfile.mkdtemp(prefix="splat-probe-cow-"))
    ws.chmod(0o777)
    mission = "probe-cow-" + ws.name
    scratch = Path("/run/splat/cow") / ("mission_" + mission)
    target = "/run/splat/roots/mission_" + mission + str(ws)
    for name in ("existing", "deleted"):
        (ws / name).write_text("LOWER")
        (ws / name).chmod(0o666)

    def cow_call(label, code, **extra):
        req = {"type": "EXECUTE_TOOL", "missionId": label, "command": "/usr/bin/python3",
               "argv": ["-c", code], "allowedExecPaths": ["/usr/bin/python3"],
               "workingDirectory": str(ws), "overlayFs": {"enableCow": True}, "leaseDurationSeconds": 20}
        req.update(extra)
        return call(req, label, settle=12)

    code = """from pathlib import Path
import os, time
p = Path.cwd()
mounts = Path('/proc/self/mountinfo').read_text().splitlines()
assert any(line.split()[4] == str(p) and ' - overlay ' in line for line in mounts)
Path('existing').write_text('CHILD')
Path('deleted').unlink()
Path('new').write_text('NEW')
assert Path('existing').read_text() == 'CHILD' and not Path('deleted').exists()
print('COW_OVERLAY_WRITES', flush=True)
time.sleep(5)
"""
    frames = []
    worker = threading.Thread(target=lambda: frames.extend(cow_call(mission, code) or []))
    worker.start()
    try:
        ready = wait_for(lambda: (scratch / "upper/new").is_file())
        lower_intact = lambda: ((ws / "existing").read_text() == "LOWER"
                                and (ws / "deleted").read_text() == "LOWER" and not (ws / "new").exists())
        intact_during = ready and lower_intact()
        feature_checks["cow_no_host_mount"] = ready and host_overlays() == overlays_before and not any(
            line.split()[4] == target for line in Path("/proc/self/mountinfo").read_text().splitlines())
        isolated = cow_call(mission + "-isolated", "from pathlib import Path; assert not Path('new').exists(); print('ISOLATED')")
        feature_checks["cow_concurrent_isolation"] = ready and scratch.exists() and completed(isolated) and "ISOLATED" in text(isolated)
        worker.join(timeout=15)
        feature_checks["cow_overlay_in_child"] = completed(frames) and "COW_OVERLAY_WRITES" in text(frames)
        feature_checks["cow_host_unchanged"] = intact_during and lower_intact()
        feature_checks["cow_scratch_removed"] = not worker.is_alive() and wait_for(lambda: not scratch.exists())
        readonly = cow_call(mission + "-ro", """from pathlib import Path
import errno
try:
    Path('ro-new').write_text('BAD')
except OSError as e:
    assert e.errno == errno.EROFS
    print('COW_READONLY')
else:
    raise AssertionError('write succeeded')
""", readOnlyFs=True)
        feature_checks["cow_read_only_honored"] = completed(readonly) and "COW_READONLY" in text(readonly) and not (ws / "ro-new").exists()
        invalid = ws / "bad,options"
        invalid.mkdir()
        refused = cow_call(mission + "-bad", "print('RAN')", workingDirectory=str(invalid))
        feature_checks["cow_bad_options_refused"] = "mount-option separator" in text(refused) and not had(refused, "STDOUT") and exit_frame(refused).get("exitCode") == -1
        refused = cow_call(mission + "-inode", "print('RAN')", protectedPaths=[str(ws / "existing")])
        feature_checks["cow_inode_overlap_refused"] = "overlaps workingDirectory" in text(refused) and not had(refused, "STDOUT") and exit_frame(refused).get("exitCode") == -1
    finally:
        worker.join(timeout=15)
        if not worker.is_alive():
            shutil.rmtree(ws)

def probe_scratch_exec():
    ws = Path(tempfile.mkdtemp(prefix="splat-probe-exec-"))
    ws.chmod(0o777)
    mission = "probe-exec-" + ws.name
    scratch = Path("/run/splat/cow") / ("mission_" + mission)
    # A minimal static x86-64 ELF exits 23. Generate it here so the positive control has no
    # pre-existing allow-listed inode, interpreter, dynamic linker or multicall-name behaviour.
    import platform, struct
    if platform.machine() != 'x86_64':
        raise RuntimeError('the generated scratch ELF probe requires x86_64')
    machine_code = bytes.fromhex('b83c000000bf170000000f05')
    payload = (struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
        2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 120 + len(machine_code),
                      120 + len(machine_code), 4096) + machine_code)
    payload_setup = 'payload = bytes.fromhex(' + repr(payload.hex()) + ')\n'
    code = payload_setup + """import errno, os, subprocess, time
from pathlib import Path
inside = Path.cwd() / 'scratch-bin'
outside = Path('/tmp/outside-bin')
for path in (inside, outside):
    path.write_bytes(payload)
    path.chmod(0o755)
def denied(path, **kw):
    try:
        subprocess.run([str(path)], capture_output=True, **kw)
    except OSError as e:
        assert e.errno == errno.EPERM
        return
    raise AssertionError('ungranted executable ran')
assert subprocess.run([str(inside)], capture_output=True).returncode == 23
assert os.getuid() != 0
print('SCRATCH_INSIDE', flush=True)
denied(outside)
Path('outside-link').symlink_to(outside)
denied(Path.cwd() / 'outside-link')
print('SCRATCH_OUTSIDE_DENIED', flush=True)
for path, allowed in ((inside, True), (outside, False)):
    fd = os.open(path, os.O_RDONLY)
    try:
        alias = '/proc/self/fd/' + str(fd)
        if allowed:
            assert subprocess.run([alias], pass_fds=(fd,), capture_output=True).returncode == 23
        else:
            denied(alias, pass_fds=(fd,))
    finally:
        os.close(fd)
print('SCRATCH_FD_SCOPED', flush=True)
Path('ready').write_text('ready')
time.sleep(4)
"""
    def run(label, body, overlay):
        return call({"type": "EXECUTE_TOOL", "missionId": label, "command": "/usr/bin/python3",
            "argv": ["-c", body], "allowedExecPaths": ["/usr/bin/python3"],
            "workingDirectory": str(ws), "overlayFs": overlay, "leaseDurationSeconds": 20}, label, settle=12)
    refused_code = payload_setup + """import errno, subprocess
from pathlib import Path
p = Path.cwd() / 'scratch-bin'
p.write_bytes(payload)
p.chmod(0o755)
try:
    subprocess.run([str(p)], capture_output=True)
except OSError as e:
    assert e.errno == errno.EPERM
    print('SCRATCH_DEFAULT_DENIED')
else:
    raise AssertionError('scratch execution was implicitly allowed')
"""
    frames = []
    worker = threading.Thread(target=lambda: frames.extend(run(mission, code,
        {"enableCow": True, "allowScratchExec": True}) or []))
    try:
        default = run(mission + '-default', refused_code, {"enableCow": True})
        feature_checks["scratch_exec_default_denied"] = completed(default) and 'SCRATCH_DEFAULT_DENIED' in text(default) and had(default, 'VIOLATION')
        worker.start()
        ready = wait_for(lambda: (scratch / 'upper/ready').exists())
        other = run(mission + '-other', refused_code, {"enableCow": True})
        feature_checks["scratch_exec_other_lease_denied"] = ready and scratch.exists() and completed(other) and 'SCRATCH_DEFAULT_DENIED' in text(other)
        worker.join(timeout=20)
        feature_observations['scratch_exec_frames'] = frames
        for check, marker in (("scratch_exec_inside", "SCRATCH_INSIDE"),
                              ("scratch_exec_outside_denied", "SCRATCH_OUTSIDE_DENIED"),
                              ("scratch_exec_fd_scoped", "SCRATCH_FD_SCOPED")):
            feature_checks[check] = completed(frames) and marker in text(frames)
        feature_checks["scratch_exec_outside_denied"] &= had(frames, 'VIOLATION')
        feature_checks["scratch_exec_layer_removed"] = not worker.is_alive() and wait_for(lambda: not scratch.exists()) and not (ws / 'scratch-bin').exists()
        digest = hashlib.sha256(Path('src/bpf/lease_lsm.bpf.c').read_bytes()).hexdigest()
        pin = Path('/sys/fs/bpf/splat') / digest / 'map_scratch_exec_devs'
        feature_checks["scratch_exec_map_removed"] = bpftool('map', 'dump', 'pinned', pin) == []
        no_cow = run(mission + '-no-cow', "print('RAN')", {"allowScratchExec": True})
        feature_checks["scratch_exec_requires_cow"] = exit_frame(no_cow).get('exitCode') == -1 and 'requires overlayFs.enableCow' in text(no_cow) and not had(no_cow, 'STDOUT')
        if managed_policy:
            stop_owned()
            probe_policy['allowScratchExec'] = False
            managed_policy.seek(0)
            managed_policy.truncate()
            json.dump(probe_policy, managed_policy)
            managed_policy.flush()
            try:
                start_owned()
                closed = run(mission + '-ceiling', "print('RAN')", {"enableCow": True, "allowScratchExec": True})
                feature_checks["scratch_exec_ceiling_refused"] = exit_frame(closed).get('exitCode') == -1 and 'scratch execution is outside the exec ceiling' in text(closed) and not had(closed, 'STDOUT')
            finally:
                stop_owned()
                probe_policy['allowScratchExec'] = True
                managed_policy.seek(0)
                managed_policy.truncate()
                json.dump(probe_policy, managed_policy)
                managed_policy.flush()
                start_owned()
    finally:
        if worker.ident is not None:
            worker.join(timeout=20)
        if not worker.is_alive():
            shutil.rmtree(ws)

def bpftool(*args):
    result = subprocess.run(["bpftool", "-j", *map(str, args)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f"bpftool {args}: {result.stderr.strip() or result.stdout.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else None

def pin_snapshot(directory):
    snapshot = {}
    # bpftool 7.7 can emit a valid tracing-link object but exit 255 for "show pinned".
    # Its full inventory succeeds and carries the pin paths with -f. Require that successful
    # query and an unambiguous path match instead of ignoring a failed command's exit status.
    links = bpftool("-f", "link", "show")
    for path in sorted(directory.iterdir()):
        kind = "link" if path.name.startswith("link_") else "map"
        info = ([link for link in links if str(path) in link.get("pinned", [])]
                if kind == "link" else bpftool(kind, "show", "pinned", path))
        if isinstance(info, list):
            if len(info) != 1:
                raise RuntimeError("ambiguous pinned object: " + str(path))
            info = info[0]
        snapshot[path.name] = {key: info[key] for key in ("id", "prog_id") if key in info}
    if len(snapshot) != 12 or not all("id" in info for info in snapshot.values()):
        raise RuntimeError("expected eight pinned maps and four pinned links")
    return snapshot

def refuses_owned_start(reason):
    proc = launch_owned()
    try:
        code = proc.wait(timeout=10)
        output = log_tail()
        feature_observations.setdefault("pin_startup_refusals", {})[reason] = {"exit_code": code, "log": output}
        refused = code != 0 and reason in output
    except subprocess.TimeoutExpired:
        refused = False
    finally:
        stop_owned()
    return refused

def probe_pins():
    source = Path("src/bpf/lease_lsm.bpf.c")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    directory = Path("/sys/fs/bpf/splat") / digest
    before = pin_snapshot(directory)
    feature_observations.update(pin_directory=str(directory), pin_ids_before=before,
        daemon_binary_sha256=hashlib.sha256(Path(managed_binary).read_bytes()).hexdigest())
    ws = Path(tempfile.mkdtemp(prefix="splat-probe-pins-"))
    ws.chmod(0o777)
    mission = "probe-pins-" + ws.name
    cg = Path("/sys/fs/cgroup/splat_leases") / ("mission_" + mission)
    code = """import errno, json, os, subprocess, time
from pathlib import Path
def denied(action):
    try:
        action()
    except OSError as e:
        return e.errno == errno.EPERM
    return False
def record(name):
    allowed = subprocess.run(['/usr/bin/id', '-u'], capture_output=True, text=True)
    result = {'allowed': allowed.returncode == 0 and allowed.stdout.strip() == str(os.getuid()) and os.getuid() != 0,
              'exec_denied': denied(lambda: subprocess.run(['/usr/bin/dpkg', '--version'], capture_output=True)),
              'file_denied': denied(lambda: Path('/etc/hostname').read_text())}
    Path(name + '.tmp').write_text(json.dumps(result))
    os.replace(name + '.tmp', name)
record('before.json')
while not Path('continue').exists():
    time.sleep(0.05)
record('after.json')
time.sleep(60)
"""
    worker = threading.Thread(target=lambda: call({
        "type": "EXECUTE_TOOL", "missionId": mission, "command": "/usr/bin/python3", "argv": ["-c", code],
        "allowedExecPaths": ["/usr/bin/python3", "/usr/bin/id"], "protectedPaths": ["/etc/hostname"],
        "workingDirectory": str(ws), "leaseDurationSeconds": 60,
    }, mission, settle=90))
    # Outside the lease the exact denied executable and file must be usable.
    # Ubuntu's multicall coreutils can give id and uname the SAME inode. An inode allow-list
    # correctly admits both; the negative control must be a different executable image.
    distinct = all(not os.path.samefile("/usr/bin/dpkg", allowed) for allowed in ("/usr/bin/python3", "/usr/bin/id"))
    feature_observations["pin_control_distinct_inode"] = distinct
    control = distinct and subprocess.run(["/usr/bin/dpkg", "--version"], capture_output=True).returncode == 0 and bool(Path("/etc/hostname").read_text())
    worker.start()
    try:
        if not wait_for(lambda: (ws / "before.json").exists()):
            raise RuntimeError("pinning workload did not reach its pre-kill control")
        pre = json.loads((ws / "before.json").read_text())
        feature_observations["pin_workload_before"] = pre
        managed_process.kill()  # This Popen is ours, never a PID discovered on the host.
        killed = managed_process.wait(timeout=5) == -9
        worker.join(timeout=5)
        (ws / "continue").touch()
        if not wait_for(lambda: (ws / "after.json").exists()):
            raise RuntimeError("pinning workload did not survive the daemon's SIGKILL")
        post = json.loads((ws / "after.json").read_text())
        feature_observations["pin_workload_after"] = post
        no_listener = False
        try:
            with socket.create_connection((host, port), timeout=0.2):
                pass
        except OSError:
            no_listener = True
        outage = killed and no_listener and control and all(pre.values())
        feature_checks["pins_no_daemon_during_measurement"] = outage
        feature_checks["pins_exec_denied_during_outage"] = outage and post.get("exec_denied") is True
        feature_checks["pins_file_denied_during_outage"] = outage and post.get("file_denied") is True
        feature_checks["pins_allowed_exec_during_outage"] = outage and post.get("allowed") is True
        after_kill = pin_snapshot(directory)
        feature_observations["pin_ids_after_sigkill"] = after_kill
        feature_checks["pins_survive_sigkill"] = outage and before == after_kill
        start_owned()
        after_restart = pin_snapshot(directory)
        feature_observations["pin_ids_after_restart"] = after_restart
        feature_checks["pins_same_ids_after_restart"] = before == after_restart
        feature_checks["pins_orphans_drained"] = not cg.exists() and bpftool("map", "dump", "pinned", directory / "map_leased_cgroups") == []
        allowed_again = call({"type": "EXECUTE_TOOL", "missionId": mission + "-allow", "command": "/usr/bin/id",
                              "argv": ["-u"], "allowedExecPaths": ["/usr/bin/id"], "leaseDurationSeconds": 20}, "pins-restart-allow")
        denied_again = call({"type": "EXECUTE_TOOL", "missionId": mission + "-deny", "command": "/bin/sh",
                             "argv": ["-c", "/usr/bin/uname -s"], "allowedExecPaths": ["/bin/sh"],
                             "leaseDurationSeconds": 20}, "pins-restart-deny")
        feature_checks["pins_restart_enforces"] = completed(allowed_again) and had(denied_again, "VIOLATION") and exit_frame(denied_again).get("exitCode") not in (None, 0)
        stop_owned()
        wrong = directory.with_name("0" * 64)
        directory.rename(wrong)
        try:
            feature_checks["pins_wrong_hash_refused"] = refuses_owned_start("foreign or incomplete BPF pin set")
        finally:
            wrong.rename(directory)
        pin = directory / "map_leased_cgroups"
        missing = directory / "withheld_map"
        pin.rename(missing)
        try:
            feature_checks["pins_partial_set_refused"] = refuses_owned_start("incomplete BPF pin set")
        finally:
            missing.rename(pin)
        # A same-shaped empty map under the RIGHT hash must still fail: the surviving link uses
        # a different map ID. Accepting it would make new lease writes invisible to enforcement.
        backup = directory.parent.parent / ("splat_probe_saved_" + str(os.getpid()))
        info = bpftool("map", "show", "pinned", pin)
        info = info[0] if isinstance(info, list) else info
        pin.rename(backup)
        try:
            bpftool("map", "create", pin, "type", "hash", "key", "8", "value", "8",
                    "entries", info["max_entries"], "name", info["name"], "flags", info.get("flags", 0))
            feature_checks["pins_foreign_map_refused"] = refuses_owned_start("pinned hook does not match")
        finally:
            if pin.exists():
                pin.unlink()
            backup.rename(pin)
    finally:
        # A valid set is always restored before restart. Startup drains the probe's surviving
        # workload, so its directory is removed only after that drain has succeeded.
        if managed_process.poll() is not None:
            start_owned()
        worker.join(timeout=10)
        if not cg.exists():
            shutil.rmtree(ws)

def probe_expiry_outage():
    # The deadline used to live only in the daemon's reaper, so a daemon that died left a lease its
    # full authority with no end. The kernel now holds the deadline itself. This kills the daemon
    # mid-lease and measures when the kernel cuts the workload off, against the deadline it holds.
    # The workload opens its result file BEFORE the deadline: past it, every new open is refused.
    ws = Path(tempfile.mkdtemp(prefix="splat-probe-expiry-"))
    ws.chmod(0o777)
    mission = "probe-expiry-" + ws.name
    cg = Path("/sys/fs/cgroup/splat_leases") / ("mission_" + mission)
    duration = 8
    code = """import errno, json, os, subprocess, time
from pathlib import Path
out = os.open('result.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
def emit(**kw):
    os.write(out, (json.dumps(kw) + '\\n').encode())
def exec_ok():
    try:
        return subprocess.run(['/usr/bin/id', '-u'], capture_output=True).returncode == 0
    except OSError as e:
        return False if e.errno == errno.EPERM else None
def open_ok():
    try:
        os.close(os.open('/etc/os-release', os.O_RDONLY))
        return True
    except OSError as e:
        return False if e.errno == errno.EPERM else None
emit(phase='ready', exec_ok=exec_ok(), open_ok=open_ok())
while not os.path.exists('continue'):
    time.sleep(0.02)
first_exec = first_open = None
allowed_after_kill = exec_ok() and open_ok()
until = now() + __WINDOW__
while now() < until and (first_exec is None or first_open is None):
    if first_exec is None and exec_ok() is False:
        first_exec = now()
    if first_open is None and open_ok() is False:
        first_open = now()
    time.sleep(0.02)
emit(phase='done', allowed_after_kill=allowed_after_kill, first_exec_denied_ns=first_exec, first_open_denied_ns=first_open)
time.sleep(60)
""".replace("__WINDOW__", str((duration + 20) * 1_000_000_000))
    worker = threading.Thread(target=lambda: call({
        "type": "EXECUTE_TOOL", "missionId": mission, "command": "/usr/bin/python3", "argv": ["-c", code],
        "allowedExecPaths": ["/usr/bin/python3", "/usr/bin/id"], "workingDirectory": str(ws),
        "leaseDurationSeconds": duration,
    }, mission, settle=duration + 40))
    result = ws / "result.jsonl"
    def phases():
        return [json.loads(l) for l in result.read_text().splitlines() if l.strip()] if result.exists() else []
    worker.start()
    try:
        if not wait_for(lambda: any(p["phase"] == "ready" for p in phases())):
            raise RuntimeError("expiry workload did not reach its pre-kill control")
        ready = next(p for p in phases() if p["phase"] == "ready")
        # The deadline exactly as the kernel holds it, read from the pinned map before the kill.
        directory = Path("/sys/fs/bpf/splat") / hashlib.sha256(Path("src/bpf/lease_lsm.bpf.c").read_bytes()).hexdigest()
        cgid = cg.stat().st_ino
        deadline = None
        for entry in bpftool("map", "dump", "pinned", directory / "map_leased_cgroups") or []:
            key, value = entry.get("key"), entry.get("value")
            if isinstance(key, list):
                key = int.from_bytes(bytes(int(b, 16) for b in key), "little")
            if key == cgid:
                deadline = value["deadline_ns"] if isinstance(value, dict) else int.from_bytes(bytes(int(b, 16) for b in value), "little")
        managed_process.kill()  # Our own Popen, never a PID discovered on the host.
        killed = managed_process.wait(timeout=5) == -9
        worker.join(timeout=5)
        no_listener = False
        try:
            with socket.create_connection((host, port), timeout=0.2):
                pass
        except OSError:
            no_listener = True
        (ws / "continue").touch()
        if not wait_for(lambda: any(p["phase"] == "done" for p in phases()), seconds=duration + 30):
            raise RuntimeError("expiry workload did not finish its measurement")
        done = next(p for p in phases() if p["phase"] == "done")
        outage = killed and no_listener and deadline is not None and ready.get("exec_ok") is True and ready.get("open_ok") is True
        first = done.get("first_exec_denied_ns")
        overrun_ms = (first - deadline) / 1e6 if outage and first else None
        feature_observations["expiry_outage"] = {"deadline_ns": deadline, "ready": ready, "done": done,
                                                 "overrun_ms": overrun_ms, "lease_seconds": duration}
        feature_checks["expiry_no_daemon_during_measurement"] = outage
        feature_checks["expiry_allowed_until_deadline"] = outage and done.get("allowed_after_kill") is True
        feature_checks["expiry_exec_denied_without_daemon"] = outage and first is not None and first >= deadline
        feature_checks["expiry_open_denied_without_daemon"] = outage and done.get("first_open_denied_ns") is not None \
            and done["first_open_denied_ns"] >= deadline
        feature_checks["expiry_overrun_within_1s"] = overrun_ms is not None and 0 <= overrun_ms <= 1000
        print(f"  lease cut off without a daemon : overrun {overrun_ms} ms past the kernel's deadline")
    finally:
        if managed_process.poll() is not None:
            start_owned()  # Startup drains the surviving workload before serving.
        worker.join(timeout=10)
        if not cg.exists():
            shutil.rmtree(ws, ignore_errors=True)

def probe_cross_lease():
    # Two ORDINARY leases, concurrent. B sleeps in its own ephemeral workspace; A, a second
    # ordinary lease, reaches for B's process and that workspace. Every ordinary workload runs at
    # the daemon's one default workload uid - only a secret step is handed a private uid and a
    # private IPC namespace - and the jail unshares the mount namespace alone, so A and B share one
    # pid namespace and a procfs mounted with no hidepid. That is enough for A to see B in /proc and,
    # at the same uid, pass ptrace_may_access(PTRACE_MODE_READ_FSCREDS) for B's magic links.
    #
    # The control is A running the SAME four operations against its OWN process and cwd first: if
    # that fails, a failed peer result is a broken probe rather than isolation, so the peer booleans
    # are only evidence of a gap when the control says the operations are mechanically possible.
    feature_observations["cross_lease"] = cross_lease_observations
    secret = "xlease-" + os.urandom(8).hex()
    b_ws = Path(missions_root) / "probe-xlease-b"
    a_ws = Path(missions_root) / "probe-xlease-a"
    for ws in (b_ws, a_ws):
        shutil.rmtree(ws, ignore_errors=True)
    # B publishes its pid into its own workspace (root, orchestrating, reads it there) and holds a
    # private 0700 canary the attacker must not know in advance, then sleeps inside its lease.
    b_code = """import os, time
from pathlib import Path
Path('canary').write_text('__SECRET__')
Path('pid').write_text(str(os.getpid()))
print('PEER_READY', flush=True)
time.sleep(14)
""".replace("__SECRET__", secret)
    frames_b = []
    worker = threading.Thread(target=lambda: frames_b.extend(call({
        "type": "EXECUTE_TOOL", "missionId": "probe-xlease-b",
        "command": "/usr/bin/python3", "argv": ["-c", b_code],
        "allowedExecPaths": ["/usr/bin/python3"],
        "workingDirectory": str(b_ws), "ephemeralWorkspace": True,
        "leaseDurationSeconds": 20,
    }, "crosslease-b", settle=18.0) or []))
    worker.start()
    try:
        if not wait_for(lambda: (b_ws / "pid").is_file(), seconds=15):
            raise RuntimeError("peer lease B never published its pid; A had no target to reach")
        peer_pid = int((b_ws / "pid").read_text().strip())
        cross_lease_observations["peer_pid"] = peer_pid
        # Values are spliced by name, never %-formatted, so the many % and quotes in A's own print
        # statements cannot collide with the injection.
        a_code = """import os
pid = __PID__
ctrl = []
try:
    os.kill(os.getpid(), 0); ctrl.append('kill')
    os.readlink('/proc/self/cwd'); ctrl.append('cwd')
    os.readlink('/proc/self/root'); ctrl.append('root')
    open('self-file', 'w').write('x'); open('self-file').read(); ctrl.append('rw')
except Exception as exc:
    print('CONTROL_FAIL=' + repr(exc), flush=True)
print('CONTROL_OK' if len(ctrl) == 4 else 'CONTROL_PARTIAL=' + repr(ctrl), flush=True)
print('SELF_UID=' + str(os.getuid()), flush=True)
try:
    status = open('/proc/' + str(pid) + '/status').read()
    print('PEER_UID=' + next(l for l in status.splitlines() if l.startswith('Uid:')).split()[1], flush=True)
except OSError as exc:
    print('PEER_STATUS_FAIL=' + str(exc.errno), flush=True)
try:
    os.kill(pid, 0); print('KILL0_OK', flush=True)
except OSError as exc:
    print('KILL0_FAIL=' + str(exc.errno), flush=True)
for n in ('cwd', 'root'):
    try:
        print('LINK_' + n + '=' + os.readlink('/proc/' + str(pid) + '/' + n), flush=True)
    except OSError as exc:
        print('LINK_' + n + '_FAIL=' + str(exc.errno), flush=True)
try:
    print('PEER_READ=' + open('/proc/' + str(pid) + '/cwd/canary').read(), flush=True)
except OSError as exc:
    print('PEER_READ_FAIL=' + str(exc.errno), flush=True)
try:
    open('/proc/' + str(pid) + '/cwd/injected-by-a', 'w').write('A reached B')
    print('PEER_WRITE_OK', flush=True)
except OSError as exc:
    print('PEER_WRITE_FAIL=' + str(exc.errno), flush=True)
""".replace("__PID__", str(peer_pid))
        frames_a = call({
            "type": "EXECUTE_TOOL", "missionId": "probe-xlease-a",
            "command": "/usr/bin/python3", "argv": ["-c", a_code],
            "allowedExecPaths": ["/usr/bin/python3"],
            "workingDirectory": str(a_ws), "ephemeralWorkspace": True,
            "leaseDurationSeconds": 20,
        }, "crosslease-a", settle=12.0)
        out = stdout_text(frames_a)
        cross_lease_observations["attacker_stdout"] = out
        # The host's own view of B's workspace while B still sleeps: the one write signal that does
        # not depend on A's self-report, since root can see the file A left in B's private directory.
        injected_on_host = (b_ws / "injected-by-a").is_file()
        cross_lease_observations["injected_file_present_on_host"] = injected_on_host
        for part in out.split():
            for marker in ("SELF_UID=", "PEER_UID="):
                if part.startswith(marker):
                    cross_lease_observations[marker.rstrip("=").lower()] = part.split("=", 1)[1]
        cross_lease["control_ops_possible"] = "CONTROL_OK" in out
        cross_lease["signal_reaches_peer"] = "KILL0_OK" in out
        cross_lease["proc_cwd_readlinked"] = "LINK_cwd=" in out
        cross_lease["proc_root_readlinked"] = "LINK_root=" in out
        # A never held B's secret; reading it back out of out is reach into B's 0700 workspace.
        cross_lease["peer_workspace_read"] = secret in out
        cross_lease["peer_workspace_written"] = "PEER_WRITE_OK" in out and injected_on_host
    finally:
        worker.join(timeout=25)
        for ws in (b_ws, a_ws):
            shutil.rmtree(ws, ignore_errors=True)

if replay is None and hasattr(os, "geteuid") and os.geteuid() == 0:
    print("\n== 18. CoW: private overlay writes, unchanged lowerdir, teardown ==")
    try:
        probe_cow()
    except Exception as e:
        feature_observations["errors"].append("CoW: " + str(e))
    print("\n== 18b. Scratch execution: explicit grant, mount boundary, lease isolation, teardown ==")
    try:
        probe_scratch_exec()
    except Exception as e:
        feature_observations["errors"].append("scratch exec: " + str(e))
    print("\n== 19. Cross-lease reach: one ordinary lease against another's process and workspace ==")
    try:
        probe_cross_lease()
    except Exception as e:
        feature_observations["errors"].append("cross-lease: " + str(e))
    if managed_binary:
        print("\n== 20. Pins: SIGKILL, surviving denials, restart identity, rejected foreign state ==")
        try:
            probe_pins()
        except Exception as e:
            feature_observations["errors"].append("pins: " + str(e))
        print("\n== 21. Expiry without a daemon: the kernel ends a lease at its deadline ==")
        try:
            probe_expiry_outage()
        except Exception as e:
            feature_observations["errors"].append("expiry outage: " + str(e))
for name, passed in feature_checks.items():
    print(f"  {name}: {passed}")
for error in feature_observations["errors"]:
    print("  root probe error: " + error)
# Cross-lease reach. The control gates the reading of the rest: with it True, a True below is lease A
# genuinely reaching lease B; with it False, the probe could not perform the operations at all.
print(f"  cross-lease control (A on itself) : {cross_lease['control_ops_possible']}")
print(f"  cross-lease kill -0 reaches peer  : {cross_lease['signal_reaches_peer']}")
print(f"  cross-lease /proc/<peer>/cwd link : {cross_lease['proc_cwd_readlinked']}")
print(f"  cross-lease /proc/<peer>/root link: {cross_lease['proc_root_readlinked']}")
print(f"  cross-lease read peer workspace   : {cross_lease['peer_workspace_read']}")
print(f"  cross-lease wrote peer workspace  : {cross_lease['peer_workspace_written']}")
daemon_proved_itself = bool(handshakes) and all(proven for _, proven in handshakes)
daemon_frames_proven = bool(frame_sessions) and all(p for _, p in frame_sessions) and not frame_failures

# A run that is not recorded is not proof - the same rule the canary follows.
import datetime
# Hash the daemon's kernel program into the record. Without it a months-old PASS kept standing
# over a rewritten BPF program - which is exactly what happened when the policy maps were re-keyed
# per lease, and why the README's enforcement claim had to be withdrawn by hand.
import hashlib
bpf_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "bpf", "lease_lsm.bpf.c")
try:
    with open(bpf_src, "rb") as f:
        bpf_sha = hashlib.sha256(f.read()).hexdigest()
except OSError:
    bpf_sha = "unreadable"

evidence = {
    "schema": 4,
    "bpf_source_sha256": bpf_sha,
    # The kernel the daemon enforced under, as the canary and the last-hop probe already record:
    # a claim about "a stock kernel" needs the record to say which one.
    # A real run is always in the guest, where uname exists; the fallback is only reachable under a
    # replay on a host that has none, and a replay's verdict is REPLAY rather than a kernel claim
    # anyway. Guarded rather than branched on `replay`, so the recorded field never depends on which
    # mode wrote it.
    "kernel_release": os.uname().release if hasattr(os, "uname") else "unavailable-no-uname",
    # The userland the run proved, for the same reason: the 2026-10-23 run on the shipped SPLAT Guest
    # and the 2026-10-22 run on a development Ubuntu wrote records nothing could tell apart.
    "guest_os": next((line.split("=", 1)[1].strip().strip('"')
                      for line in (open("/etc/os-release").read().splitlines() if os.path.exists("/etc/os-release") else [])
                      if line.startswith("PRETTY_NAME=")), "unknown"),
    "protocol_version": 3,
    "recorded_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "subject": "splat-agent daemon (end-to-end over the JSON protocol)",
    "root_feature_observations": feature_observations,
    "results": {
        **feature_checks,
        "permitted_tool_ran": "uid=" in text(allowed),
        "protected_inode_control_could_read_it": control_read_it,
        "protected_inode_leaked": leaked,
        "protected_inode_violation": had(shadow, "VIOLATION"),
        "unleased_second_exec_blocked": had(dpkg, "VIOLATION"),
        "egress_permitted_destination_allowed": answered(egress_ok) and not had(egress_ok, "VIOLATION"),
        "egress_unleased_destination_blocked": had(egress_bad, "VIOLATION"),
        "egress_denied_when_network_off": had(egress_off, "VIOLATION"),
        # The daemon once never sent EXIT at all: its violation forwarder held the stream open
        # forever, so requests hung and the lease was only reclaimed by the expiry reaper.
        "every_request_completed": all(
            had(m, "EXIT") for m in (allowed, shadow, dpkg, egress_ok, egress_bad, egress_off)
        ),
        # F07: the drop actually transitions when the daemon is root.
        "workload_not_root": workload_not_root,
        "workload_uid_reported": priv_uid,
        # F06: concurrent leases do not lend each other permissions.
        "concurrent_lease_isolation_held": iso_holds,
        # F08: the endpoint key carries the port, and IPv6 is denied rather than waved through.
        "unapproved_port_refused": had(port_bad, "VIOLATION"),
        "ipv6_refused": had(v6, "VIOLATION"),
        # F05: expiry kills the workload rather than unpolicing it.
        "expiry_killed_the_workload": expiry_killed,
        "expiry_elapsed_seconds": round(expiry_elapsed, 1),
        # An absent policy key is the absence of a decision, so it is refused rather than defaulted.
        "undeclared_egress_refused": undeclared_egress_refused,
        "undeclared_exec_list_refused": undeclared_exec_refused,
        # The substrate's own state is not public: `enforcing` says when this daemon would run work
        # it cannot contain, which is the one thing an attacker most wants to know.
        "health_check_answers_a_token_holder": health_answered,
        "unauthenticated_health_check_refused": unauth_health_refused,
        # Protocol 3: the token never crosses the wire. The daemon proves it holds it before a caller
        # sends anything, and the old form that carried it - which whatever held the port could
        # collect - is refused even with the right token.
        "daemon_proved_it_holds_the_token": daemon_proved_itself,
        "protocol_2_token_in_the_clear_refused": clear_token_refused,
        # Roadmap 2.6: the answers prove themselves too. Every session here asked, so a daemon that
        # answered one unwrapped, or proved a frame for the wrong place, fails this.
        "daemon_frames_proven": daemon_frames_proven,
        # A datagram that names its own destination never reaches socket_connect; socket_sendmsg
        # judges it against the same allow-list.
        "udp_outside_the_lease_blocked": udp_blocked,
        # Recorded, not gated: a refusal the kernel made and the caller never heard about is a
        # defect in the return path, and it must stay visible now that the claim no longer rests
        # on it. See the note above udp_blocked.
        "udp_violation_frame_reached_the_session": udp_frame_reached_the_session,
        "udp_inside_the_lease_allowed": udp_allowed,
        # The lease says what the kernel counted for it, and whether the caller heard all of it.
        "refusal_receipt_counts_the_denial": refusal_receipt_counted,
        "refusal_receipt_says_it_is_complete": refusal_receipt_complete,
        "a_clean_lease_reports_zero_refusals": clean_receipt_counted_zero,
        # The guest's own signature over the outcome, and that an edited outcome fails it.
        "lease_outcome_is_signed_by_the_guest": outcome_signed,
        "lease_outcome_signature_verifies": outcome_verifies,
        "an_edited_outcome_fails_the_signature": outcome_edit_refused,
        # P2: the workload's root is its own mount namespace, not the host's tree minus a deny-list.
        "jail_control_host_has_home_and_mnt": host_has_the_dirs,
        "jail_hides_home_and_mnt": jail_hides_host,
        "jail_system_dirs_read_only": jail_system_ro,
        "jail_workdir_and_tmp_writable": jail_workdir_rw,
        "read_only_fs_makes_workdir_read_only": jail_readonly_fs,
        # 2026-09-24: the daemon tells the bridge what it installed, and makes a governed mission's
        # workspace under its missions root only.
        "lease_frame_reports_enforcing": lease_reports_enforcing,
        "mission_workspace_made_and_removed": workspace_made_and_removed,
        # The conjuncts behind it, so a False names its own cause. The daemon's word and the host's
        # are kept apart on purpose: "EXIT said removed" and "the path is gone" failing separately
        # is the difference between a daemon that lied and a daemon that could not finish.
        "mission_workspace_frame_says_created": workspace_frame_says_created,
        "mission_workspace_path_announced": workspace_path_announced,
        "mission_workspace_tool_wrote_in_it": workspace_tool_wrote_in_it,
        "mission_workspace_exit_says_removed": workspace_exit_says_removed,
        "mission_workspace_gone_from_the_host": workspace_gone_after,
        "mission_workspace_elsewhere_refused": workspace_elsewhere_refused,
        "mission_workspace_removed_on_refusal": workspace_removed_on_refusal,
        # Cross-lease reach between two ordinary leases. Recorded, never gated into the verdict: True
        # means lease A reached lease B (the gap is present), the opposite polarity from every check
        # above, so the PASS conjunction must not read these. The control says the operations are
        # mechanically possible; the peer booleans are only a finding when it is True. See the note
        # where `cross_lease` is defined, and the "Not policed" table in SUPPORTED_POLICY.md.
        "cross_lease_control_ops_possible": cross_lease["control_ops_possible"],
        "cross_lease_signal_reaches_a_peer_lease": cross_lease["signal_reaches_peer"],
        "cross_lease_peer_proc_cwd_readlinked": cross_lease["proc_cwd_readlinked"],
        "cross_lease_peer_proc_root_readlinked": cross_lease["proc_root_readlinked"],
        "cross_lease_peer_workspace_read_via_proc": cross_lease["peer_workspace_read"],
        "cross_lease_peer_workspace_written_via_proc": cross_lease["peer_workspace_written"],
    },
    "violations": [
        {k: m.get(k) for k in ("hook", "pid", "detail", "detailText", "comm") if k in m}
        for m in (shadow or []) + (dpkg or []) + (egress_bad or []) + (egress_off or [])
              + (iso_b or []) + (port_bad or []) + (v6 or []) + (udp_bad or [])
        if m.get("type") == "VIOLATION"
    ],
}
# Every permitted action must succeed AND every forbidden one must be refused. Leaving the
# permitted-egress check out of this - as the first version of this verdict did - let a lease that
# denied EVERYTHING report PASS, which is the same "harness that cannot fail" the canary was fixed
# for. Refusals alone prove the hooks fire, not that the policy is right.
evidence["verdict"] = "PASS" if (
    all(feature_checks.values())
    and not feature_observations["errors"]
    and
    evidence["results"]["permitted_tool_ran"]
    # Without the control the protected-file result is not a measurement.
    and evidence["results"]["protected_inode_control_could_read_it"]
    and evidence["results"]["egress_permitted_destination_allowed"]
    and not evidence["results"]["protected_inode_leaked"]
    and evidence["results"]["protected_inode_violation"]
    and evidence["results"]["unleased_second_exec_blocked"]
    and evidence["results"]["egress_unleased_destination_blocked"]
    and evidence["results"]["egress_denied_when_network_off"]
    and evidence["results"]["every_request_completed"]
    # Everything Wave 3 changed has to hold in the same run, or the run has not closed it.
    and evidence["results"]["workload_not_root"]
    and evidence["results"]["concurrent_lease_isolation_held"]
    and evidence["results"]["unapproved_port_refused"]
    and evidence["results"]["ipv6_refused"]
    and evidence["results"]["expiry_killed_the_workload"]
    and evidence["results"]["undeclared_egress_refused"]
    and evidence["results"]["undeclared_exec_list_refused"]
    and evidence["results"]["health_check_answers_a_token_holder"]
    and evidence["results"]["unauthenticated_health_check_refused"]
    and evidence["results"]["daemon_proved_it_holds_the_token"]
    and evidence["results"]["protocol_2_token_in_the_clear_refused"]
    and evidence["results"]["daemon_frames_proven"]
    and evidence["results"]["udp_outside_the_lease_blocked"]
    and evidence["results"]["udp_inside_the_lease_allowed"]
    and evidence["results"]["refusal_receipt_counts_the_denial"]
    and evidence["results"]["refusal_receipt_says_it_is_complete"]
    and evidence["results"]["a_clean_lease_reports_zero_refusals"]
    and evidence["results"]["lease_outcome_is_signed_by_the_guest"]
    and evidence["results"]["lease_outcome_signature_verifies"]
    and evidence["results"]["an_edited_outcome_fails_the_signature"]
    # The jail, with its control: hidden directories only count when the host has them to hide.
    and evidence["results"]["jail_control_host_has_home_and_mnt"]
    and evidence["results"]["jail_hides_home_and_mnt"]
    and evidence["results"]["jail_system_dirs_read_only"]
    and evidence["results"]["jail_workdir_and_tmp_writable"]
    and evidence["results"]["read_only_fs_makes_workdir_read_only"]
    and evidence["results"]["lease_frame_reports_enforcing"]
    and evidence["results"]["mission_workspace_made_and_removed"]
    and evidence["results"]["mission_workspace_elsewhere_refused"]
    and evidence["results"]["mission_workspace_removed_on_refusal"]
) else "INCOMPLETE"

if replay is not None:
    # A replay contacted no daemon, so its verdict describes the checks and not a kernel. It is marked
    # rather than suppressed, because a test needs to read the same structure a real run produces - and
    # a file that says REPLAY can never be mistaken for a proof, whereas a file that merely says
    # INCOMPLETE could be read as a run that tried and fell short.
    evidence["verdict"] = "REPLAY"
    evidence["replay_fixture"] = replay_path

out_dir = os.environ.get("SPLAT_EVIDENCE_DIR", "/mnt/c/C_AGENT_BUILDER/native/splat-agent/evidence")
try:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "daemon-probe.json")
    # A failed run must not erase a passing one. The README's enforcement claim is bound to this
    # file, so an INCOMPLETE landing on top of a PASS silently withdraws a proven claim - and the
    # runs most likely to do it failed for reasons that say nothing about the kernel: daemon not
    # started, wrong token, older protocol. A downgrade goes to its own file and announces itself.
    if evidence["verdict"] != "PASS" and os.path.exists(path):
        try:
            with open(path) as f:
                standing = json.load(f).get("verdict")
        except (OSError, ValueError):
            standing = None
        if standing == "PASS":
            path = os.path.join(out_dir, "daemon-probe.INCOMPLETE.json")
            print()
            print("  NOT overwriting the standing PASS evidence with this INCOMPLETE run.")
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2)
        f.write(chr(10))
    print()
    print(f"  evidence written: {path}  (verdict {evidence['verdict']})")
except OSError as e:
    print()
    print(f"  could not write evidence: {e}")

print()
if had(dpkg, "VIOLATION"):
    print("  >> Unleased exec was refused by the kernel. The pre_exec cgroup join is working:")
    print("     the tool is inside its lease before bprm_check_security runs.")
elif not had(shadow, "VIOLATION"):
    print("  >> Nothing was refused by the kernel at all. Either this daemon is not running as")
    print("     root, or no lease reached the maps - check its log for 'kernel enforcement is live'.")
else:
    print("  >> File access was policed but the unleased exec was NOT. The tool is inside its")
    print("     cgroup by the time it opens files, yet its own exec escaped the allow-list.")
    print("     Capture this: it means the pre_exec join did not take effect before exec.")
PY
