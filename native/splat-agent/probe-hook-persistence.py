#!/usr/bin/env python3
"""Roadmap 2.7's acceptance test: kill -9 the daemon mid-lease, and an exec outside the lease is
still refused before the unit restarts.

Run it as root in the guest, against a daemon this script starts itself:

    sudo python3 probe-hook-persistence.py

It needs a built binary at ~/.cache/splat-pin-target/debug/splat-agent - build it with
`CARGO_TARGET_DIR=$HOME/.cache/splat-pin-target cargo build` from this directory. Everything else it
touches is under /tmp: its own bpffs mount, its own state, its own ports. The daemon on 50051 is not
disturbed.

One variable. The same binary, the same lease, the same workload, run twice - once with the hooks
pinned and once with --no-bpf-pin. A busy workload holds the lease open so its cgroup is still in
the map when the daemon dies. After the kill a fresh process joins that cgroup, which is not an exec
and so is not checked, and then reaches for a binary the lease never allowed - which is.

Without the unpinned control this proves nothing: an exec that fails could be failing for a reason
that has nothing to do with the lease. The control is what makes the pinned run evidence.
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

BIN = os.path.expanduser("~/.cache/splat-pin-target/debug/splat-agent")
ROOT = "/tmp/splat-midlease"
BPFFS = ROOT + "/bpffs"
STATE = ROOT + "/state"
# The workload is jailed in a mount namespace, so a file it writes is not a file this script can
# read. The process table is: an exec that succeeds leaves a process behind, and one the kernel
# refuses leaves none. SENTINEL is the argument that makes it findable.
# A duration nothing else on the box would sleep for, so pgrep finds this exec and no
# other. It was a word until 2026-09-29, and `sleep 300 <word>` is a usage error - so the
# control's exec SUCCEEDED, exited instantly on the bad argument, and scored as refused.
SENTINEL = "271828"


def prove(key, label, client_nonce, server_nonce, tail=b""):
    return hmac.new(key, label + bytes([0]) + client_nonce + server_nonce + tail, hashlib.sha256).hexdigest()


def read_line(sock, buf):
    while b"\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return buf, b""
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return line, rest


def execute_tool(port, token, request, settle=3.0):
    """One protocol 3 session. Returns the daemon's frames; the socket is left open by the caller's
    context so a long lease keeps running after this returns."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    buf = b""
    client_nonce = os.urandom(32)
    hello = {"type": "HELLO", "protocolVersion": 3, "clientNonce": client_nonce.hex(), "proveFrames": False}
    sock.sendall((json.dumps(hello) + "\n").encode())
    first, buf = read_line(sock, buf)
    challenge = json.loads(first)
    assert challenge.get("type") == "CHALLENGE", challenge
    server_nonce = bytes.fromhex(challenge["serverNonce"])
    expected = prove(token.encode(), b"splat-agent/3 daemon", client_nonce, server_nonce)
    assert hmac.compare_digest(expected, challenge["serverProof"]), "the daemon did not prove the token"

    body = json.dumps(dict(request, protocolVersion=3))
    proof = prove(token.encode(), b"splat-agent/3 request", client_nonce, server_nonce,
                  (0).to_bytes(8, "big") + body.encode())
    sock.sendall((json.dumps({"type": "AUTHENTICATED", "proof": proof, "request": body}) + "\n").encode())
    return sock


def start_daemon(port, pinned):
    args = [BIN, "--listen", f"127.0.0.1:{port}",
            "--auth-token-file", f"{STATE}/agent.token",
            "--outcome-key-file", f"{STATE}/outcome.pem"]
    args += ["--bpf-pin-root", f"{BPFFS}/splat"] if pinned else ["--no-bpf-pin"]
    log = open(f"{STATE}/daemon.log", "w")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(150):
        time.sleep(0.2)
        try:
            with open(f"{STATE}/daemon.log") as f:
                if "listening and ready" in f.read():
                    return proc
        except FileNotFoundError:
            pass
    proc.kill()
    raise SystemExit("the daemon never became ready")


def lsm_links():
    out = subprocess.run(["bpftool", "link", "list"], capture_output=True, text=True).stdout
    return len(re.findall(r"lsm", out))


def run(pinned, port):
    label = "PINNED" if pinned else "CONTROL (--no-bpf-pin)"
    print(); print(f"=== {label} ===")

    shutil.rmtree(STATE, ignore_errors=True)
    os.makedirs(STATE, exist_ok=True)
    subprocess.run(["pkill", "-9", "-f", SENTINEL], capture_output=True)

    proc = start_daemon(port, pinned)
    token = open(f"{STATE}/agent.token").read().strip()
    print(f"  lsm links with the daemon up: {lsm_links()}")

    # A workload that stays busy, so the lease is still installed when the daemon dies: nothing has
    # withdrawn its cgroup from the map. Whether this shell survives is not what is being measured.
    mission = "pinmidlease"
    busy = "i=0; while [ $i -lt 400000000 ]; do i=$((i+1)); done"
    sock = execute_tool(port, token, {
        "type": "EXECUTE_TOOL",
        "missionId": mission,
        "command": "/bin/sh",
        "argv": ["-c", busy],
        "allowedExecPaths": ["/bin/sh"],
        "leaseDurationSeconds": 120,
    })

    cgroup = f"/sys/fs/cgroup/splat_leases/mission_{mission}"
    for _ in range(50):
        if os.path.isdir(cgroup):
            break
        time.sleep(0.2)
    if not os.path.isdir(cgroup):
        print("  the lease cgroup never appeared - INCONCLUSIVE")
        proc.kill()
        sock.close()
        return None

    print("  --- SIGKILL, with the lease still installed ---")
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    sock.close()
    time.sleep(1.0)
    print(f"  lsm links after kill -9:      {lsm_links()}")
    print(f"  the lease cgroup still there: {os.path.isdir(cgroup)}")

    # Join the leased cgroup and then reach for a binary the lease never allowed. Joining is not an
    # exec, so nothing checks it; the exec that follows is the only thing under test, and by now
    # there is no daemon left - only whatever the kernel still holds.
    script = f"echo $$ > {cgroup}/cgroup.procs && exec /bin/sleep {SENTINEL}"
    # Popen, not run(): when the exec is ALLOWED the child becomes a long sleep and a blocking wait
    # would hang the harness on the very outcome it is trying to record.
    attempt = subprocess.Popen(["/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = attempt.communicate(timeout=4)
        exec_survived = False
    except subprocess.TimeoutExpired:
        # Still there four seconds later, which a refused exec never is.
        attempt.kill()
        out, err = attempt.communicate()
        exec_survived = True

    found = subprocess.run(["pgrep", "-f", f"sleep {SENTINEL}"], capture_output=True, text=True)
    still_running = found.returncode == 0 and found.stdout.strip() != ""
    subprocess.run(["pkill", "-9", "-f", f"sleep {SENTINEL}"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "400000000"], capture_output=True)

    # The shell's own words decide it. pgrep alone cannot tell "the kernel refused the exec" from
    # "the exec ran and the program exited", and reading the second as the first is how the control
    # scored a pass it had not earned.
    said = ((err or "") + (out or "")).strip()
    refused = ("not permitted" in said or "Permission denied" in said) and not exec_survived
    last = said.splitlines()[-1] if said else "<no output>"
    print(f"  exec of an unleased binary:   {'REFUSED' if refused else 'RAN'}  ({last})")
    print(f"  it was still running at 4s:   {exec_survived or still_running}")
    return refused


def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root")

    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(BPFFS, exist_ok=True)
    if subprocess.run(["mount", "-t", "bpf", "bpf", BPFFS]).returncode != 0:
        raise SystemExit("could not mount bpffs")

    try:
        control = run(pinned=False, port=50096)
        pinned = run(pinned=True, port=50097)
    finally:
        subprocess.run(["umount", BPFFS])
        shutil.rmtree(ROOT, ignore_errors=True)

    print()
    print("=== verdict ===")
    print(f"  unpinned daemon killed mid-lease: exec outside the lease {'refused' if control else 'RAN'}")
    print(f"  pinned   daemon killed mid-lease: exec outside the lease {'refused' if pinned else 'RAN'}")
    ok = control is False and pinned is True
    print(f"  {'PASS' if ok else 'FAIL'}: the lease is enforced past the daemon's death only when the hooks are pinned")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
