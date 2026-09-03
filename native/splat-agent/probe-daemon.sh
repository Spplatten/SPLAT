#!/usr/bin/env bash
# Exercise a RUNNING splat-agent over its JSON line protocol and report what the kernel actually did.
#
# The daemon must already be running as root in another terminal:
#     sudo /tmp/splat_agent_target/release/splat-agent
#
# This does NOT need root itself - it is only a client. Usage:  bash probe-daemon.sh [host:port]
set -uo pipefail
ADDR="${1:-127.0.0.1:50051}"
HOST="${ADDR%%:*}"
PORT="${ADDR##*:}"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

python3 - "$HOST" "$PORT" <<'PY'
import json, socket, sys

host, port = sys.argv[1], int(sys.argv[2])

def call(req, label, settle=2.0):
    """Send one request, collect every response line until the daemon stops talking."""
    out = []
    try:
        s = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"  [{label}] CANNOT CONNECT: {e}")
        return None
    with s:
        s.sendall((json.dumps(req) + "\n").encode())
        s.settimeout(settle)
        buf = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
    for line in buf.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"type": "RAW", "data": line})
    return out

def show(msgs, label):
    if msgs is None:
        return []
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
show(call({"type": "HEALTH_CHECK"}, "health"), "health")

print()
# NOTE: the daemon splits `arguments` on whitespace, so no single argument may contain a
# space - `-c cat /etc/shadow` becomes `sh -c cat` with the path as $0, and cat then reads
# stdin and hangs. Every probe below therefore uses single-token arguments.
print("== 2. PERMITTED: run the requested tool itself ==")
print("   The lease allow-lists the command it was asked to run, so this must succeed.")
allowed = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-allowed",
    "command": "/usr/bin/id", "arguments": "",
    "leaseDurationSeconds": 20,
}, "allowed"), "allowed")

print()
print("== 3. FORBIDDEN: read a protected inode (/etc/shadow) ==")
print("   The lease protects /etc/shadow. Expect a VIOLATION and no file contents.")
shadow = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-shadow",
    "command": "/bin/cat", "arguments": "/etc/shadow",
    "leaseDurationSeconds": 20,
}, "shadow"), "shadow")

print()
print("== 4. FORBIDDEN: an ALLOWED tool reaching for an unleased binary ==")
print("   /bin/sh is leased; dpkg is not. sh runs, then its exec of dpkg must be refused.")
print("   Requesting dpkg directly would no longer test this - the daemon allow-lists whatever")
print("   command it is asked to run, which is why the lease has to stop the SECOND exec.")
dpkg = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-exec",
    "command": "/bin/sh", "arguments": "-c dpkg",
    "leaseDurationSeconds": 20,
}, "exec"), "exec")

print()
print("== 5. EGRESS: allow-list, with the network switch ON ==")
print("   allowNetwork must be true or the lease seeds NO addresses and denies everything -")
print("   which would make the 1.1.1.1 case pass for the wrong reason. With it on, 127.0.0.1 is")
print("   the one permitted destination (a refused connection is fine: the kernel PERMITTED the")
print("   syscall), and 1.1.1.1 must be refused by the allow-list itself.")
egress_ok = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-ok",
    "command": "/usr/bin/curl", "arguments": "--max-time 3 -s -o /dev/null http://127.0.0.1/",
    "allowNetwork": True, "leaseDurationSeconds": 20,
}, "egress-allowed", settle=6.0), "egress-allowed")

egress_bad = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-bad",
    "command": "/usr/bin/curl", "arguments": "--max-time 3 -s -o /dev/null http://1.1.1.1/",
    "allowNetwork": True, "leaseDurationSeconds": 20,
}, "egress-denied", settle=6.0), "egress-denied")

print()
print("== 6. EGRESS: the network switch OFF denies even the permitted address ==")
print("   allowNetwork false seeds no addresses at all, so deny-by-default must hold.")
egress_off = show(call({
    "type": "EXECUTE_TOOL", "missionId": "probe-egress-off",
    "command": "/usr/bin/curl", "arguments": "--max-time 3 -s -o /dev/null http://127.0.0.1/",
    "allowNetwork": False, "leaseDurationSeconds": 20,
}, "egress-off", settle=6.0), "egress-off")

def had(msgs, t):
    return any(m.get("type") == t for m in (msgs or []))

def text(msgs):
    return " ".join(str(m.get("data", "")) for m in (msgs or []))

print()
print("=" * 68)
print("READING")
print("=" * 68)

if allowed is None:
    print("  Daemon not reachable - start it as root first.")
    sys.exit(2)

shadow_text = text(shadow)
leaked = "root:" in shadow_text
# A non-root daemon proves nothing here: /etc/shadow is mode 640, so ordinary file permissions
# deny the read and it LOOKS contained. Only a kernel VIOLATION distinguishes the lease doing
# its job from the filesystem doing it - which is why this probe is only meaningful against a
# daemon running as root.
mode_denied = "Permission denied" in shadow_text and not had(shadow, "VIOLATION")

print(f"  permitted tool ran             : {'uid=' in text(allowed)}")
print(f"  /etc/shadow contents leaked    : {leaked}")
print(f"  kernel VIOLATION for the read  : {had(shadow, 'VIOLATION')}")
if mode_denied:
    print("    ^ denied by file mode, not by the lease - is this daemon running as root?")
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

# A run that is not recorded is not proof - the same rule the canary follows.
import datetime, os
evidence = {
    "schema": 1,
    "recorded_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "subject": "splat-agent daemon (end-to-end over the JSON protocol)",
    "results": {
        "permitted_tool_ran": "uid=" in text(allowed),
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
    },
    "violations": [
        {k: m.get(k) for k in ("hook", "pid", "detail", "detailText", "comm") if k in m}
        for m in (shadow or []) + (dpkg or []) + (egress_bad or []) + (egress_off or [])
        if m.get("type") == "VIOLATION"
    ],
}
# Every permitted action must succeed AND every forbidden one must be refused. Leaving the
# permitted-egress check out of this - as the first version of this verdict did - let a lease that
# denied EVERYTHING report PASS, which is the same "harness that cannot fail" the canary was fixed
# for. Refusals alone prove the hooks fire, not that the policy is right.
evidence["verdict"] = "PASS" if (
    evidence["results"]["permitted_tool_ran"]
    and evidence["results"]["egress_permitted_destination_allowed"]
    and not evidence["results"]["protected_inode_leaked"]
    and evidence["results"]["protected_inode_violation"]
    and evidence["results"]["unleased_second_exec_blocked"]
    and evidence["results"]["egress_unleased_destination_blocked"]
    and evidence["results"]["egress_denied_when_network_off"]
    and evidence["results"]["every_request_completed"]
) else "INCOMPLETE"

out_dir = os.environ.get("SPLAT_EVIDENCE_DIR", "/mnt/c/C_AGENT_BUILDER/native/splat-agent/evidence")
try:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "daemon-probe.json")
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
