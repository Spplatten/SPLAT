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
set -uo pipefail
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

python3 - "$HOST" "$PORT" "$TOKEN" <<'PY'
import base64, hashlib, hmac, json, os, socket, sys, threading, time

host, port = sys.argv[1], int(sys.argv[2])
token = sys.argv[3] if len(sys.argv) > 3 else ""

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
udp_bad = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-udp-bad",
    "command": "/usr/bin/python3",
    "argv": ["-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                   "print('SENT' if s.sendto(b'x',('1.1.1.1',53)) else 'NOTHING')"],
    "allowedExecPaths": ["/usr/bin/python3"],
    "allowNetwork": True, "allowedEgressIps": ["127.0.0.1"], "allowedEgressPorts": [53],
    "leaseDurationSeconds": 20,
}, "udp-outside"), "udp-outside")
udp_ok = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-udp-ok",
    "command": "/usr/bin/python3",
    "argv": ["-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                   "print('SENT' if s.sendto(b'x',('127.0.0.1',53)) else 'NOTHING')"],
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
    "command": "/bin/sh", "argv": ["-c", "pwd; touch made-here && echo WROTE_WORKSPACE; ls -ld ."],
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
udp_allowed = "SENT" in text(udp_ok) and not had(udp_ok, "VIOLATION")

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
) and "SENT" not in text(udp_bad)

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
    "schema": 3,
    "bpf_source_sha256": bpf_sha,
    # The kernel the daemon enforced under, as the canary and the last-hop probe already record:
    # a claim about "a stock kernel" needs the record to say which one.
    # A real run is always in the guest, where uname exists; the fallback is only reachable under a
    # replay on a host that has none, and a replay's verdict is REPLAY rather than a kernel claim
    # anyway. Guarded rather than branched on `replay`, so the recorded field never depends on which
    # mode wrote it.
    "kernel_release": os.uname().release if hasattr(os, "uname") else "unavailable-no-uname",
    "protocol_version": 3,
    "recorded_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "subject": "splat-agent daemon (end-to-end over the JSON protocol)",
    "results": {
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
