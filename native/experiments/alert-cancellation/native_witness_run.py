#!/usr/bin/env python3
"""Run the deployed witness against real pidfds and cgroups on this kernel. Root only.

The witness's drain logic had only injected-OS tests. This drives the exact reviewed bytes through
their stdin protocol with live processes in disposable mission cgroups under the daemon's base:
two drains it must accept (killed, and killed then removed) and five cases it must refuse. It runs
the public fixture as an unprivileged user, born inside each cgroup, touches no cgroup it did not
create, and removes every one it did. It does not exercise a SPLAT lease, A2A, a signed receipt or
a sensor event: those belong to the cancellation pilot, not to this kernel check.

Usage: python3 -I native_witness_run.py <witness.py> <workload_fixture.py> <evidence.json>
"""
import errno
import hashlib
import json
import os
import platform
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

BASE = "/sys/fs/cgroup/splat_leases"
NOBODY = 65534


def write(path, text):
    with open(path, "w", encoding="ascii") as stream:
        stream.write(text)


def populated(path):
    with open(os.path.join(path, "cgroup.events"), encoding="ascii") as stream:
        return dict(line.split() for line in stream.read().splitlines())["populated"] == "1"


def wait_until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= end:
            raise TimeoutError(what)
        time.sleep(0.02)


def start_ticks(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
        return int(stream.read().rpartition(")")[2].split()[19])


class Lease:
    """One disposable mission cgroup holding one fixture role, launched unprivileged inside it."""

    def __init__(self, run, role):
        self.run = run
        self.task = uuid.uuid4().hex
        self.path = f"{BASE}/mission_{uuid.UUID(hex=self.task)}"
        os.mkdir(self.path)
        run.owned.append(self.path)
        # The launcher waits on stdin until it has been moved into the cgroup, so the fixture
        # and the descendant it forks are born inside it rather than migrated after the fork.
        self.proc = subprocess.Popen(
            ["/bin/sh", "-c", 'read go; exec "$0" -I "$1" "$2" --seconds 60', sys.executable, run.fixture, role],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            user=NOBODY, group=NOBODY, extra_groups=[], cwd="/")
        run.procs.append(self.proc)
        write(os.path.join(self.path, "cgroup.procs"), str(self.proc.pid))
        self.proc.stdin.write(b"go\n")
        self.proc.stdin.close()
        if (not select.select([self.proc.stdout], [], [], 10)[0]
                or self.proc.stdout.readline() != f"SPLAT_PUBLIC_PILOT_READY {role}\n".encode()):
            raise RuntimeError("fixture did not start")
        if role == "target":
            wait_until(lambda: len(self.members()) == 2, 5, "descendant did not start")
        self.identity = {"taskId": self.task, "cgroup": os.stat(self.path).st_ino, "pid": self.proc.pid,
                         "startTicks": start_ticks(self.proc.pid)}

    def members(self):
        with open(os.path.join(self.path, "cgroup.procs"), encoding="ascii") as stream:
            return stream.read().split()

    def drain(self):
        write(os.path.join(self.path, "cgroup.kill"), "1")
        wait_until(lambda: not populated(self.path), 5, "cgroup did not drain")

    def kill_root(self):
        os.kill(self.identity["pid"], signal.SIGKILL)
        self.proc.wait(timeout=5)

    def remove(self):
        os.rmdir(self.path)
        self.run.owned.remove(self.path)

    def rename(self):
        moved = self.path + "_renamed"
        try:
            os.rename(self.path, moved)
        except PermissionError:
            # cgroup v2 has no rename operation and kernfs answers EPERM (first native run,
            # 2026-11-06): a survivor cannot be hidden behind a new name at all. The scenario then
            # still checks that the visible survivor is refused; the witness's own rename defense
            # is exercised wherever a kernel allows the rename.
            self.run.facts["cgroupRename"] = "EPERM"
            return
        self.run.facts["cgroupRename"] = "allowed"
        self.run.owned[self.run.owned.index(self.path)] = moved

    def replace(self):
        # Same pathname, new kernel object: the inode the witness pinned no longer names it.
        os.mkdir(self.path)
        self.run.owned.append(self.path)


class Run:
    def __init__(self, witness, fixture):
        self.owned = []
        self.procs = []
        self.facts = {}
        self.created_base = False
        self.deploy = tempfile.mkdtemp(prefix="splat-witness-", dir="/run")
        os.chmod(self.deploy, 0o755)
        # Deployed root-owned and read-only, as the pilot runbook requires; the pin is the hash of
        # these bytes, which is what the witness compares against its own file.
        self.witness = os.path.join(self.deploy, "witness.py")
        self.fixture = os.path.join(self.deploy, "workload_fixture.py")
        for source, target in ((witness, self.witness), (fixture, self.fixture)):
            shutil.copyfile(source, target)
            os.chmod(target, 0o644)
        self.witness_sha = hashlib.sha256(open(self.witness, "rb").read()).hexdigest()
        self.fixture_sha = hashlib.sha256(open(self.fixture, "rb").read()).hexdigest()
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
            self.boot = stream.read().strip()
        if not os.path.isdir(BASE):
            os.mkdir(BASE)
            self.created_base = True

    def cleanup(self):
        for path in reversed(self.owned):
            try:
                if os.path.isdir(path):
                    write(os.path.join(path, "cgroup.kill"), "1")
                    wait_until(lambda: not populated(path), 5, "cleanup drain")
                    os.rmdir(path)
            except OSError:
                pass
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if self.created_base:
            try:
                os.rmdir(BASE)
            except OSError:
                pass
        shutil.rmtree(self.deploy, ignore_errors=True)

    def witness_session(self, target, control, mutate, spec_edit=None):
        spec = {"version": 1, "boot": self.boot, "target": target.identity, "control": control.identity,
                "sourceSha256": self.witness_sha}
        if spec_edit:
            spec = spec_edit(spec)
        observer = subprocess.Popen([sys.executable, "-I", self.witness], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        phases = []

        def send(data):
            try:
                observer.stdin.write(data)
                observer.stdin.flush()
                return True
            except BrokenPipeError:
                return False

        def receive():
            line = observer.stdout.readline()
            if line:
                phases.append(json.loads(line))
            return bool(line)

        try:
            if send((json.dumps(spec) + "\n").encode()) and receive() and send(b"check\n") and receive():
                mutate()
                if send(b"after\n"):
                    receive()
            try:
                observer.stdin.close()
            except BrokenPipeError:
                pass
            code = observer.wait(timeout=20)
            refusal = observer.stderr.read().decode("utf-8", "replace").strip()
            return code, phases, refusal
        finally:
            if observer.poll() is None:
                observer.kill()
                observer.wait()


def removed_cgroup_probe(lease):
    """What this kernel serves through a held directory fd once the cgroup is gone."""
    held = os.open(lease.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        lease.drain()
        lease.remove()
        try:
            fd = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC, dir_fd=held)
            with os.fdopen(fd, encoding="ascii") as stream:
                events = "readable: " + " ".join(stream.read().split())
        except OSError as error:
            events = errno.errorcode.get(error.errno, str(error.errno))
        marked = os.readlink(f"/proc/self/fd/{held}") == lease.path + " (deleted)"
        return {"eventsThroughHeldFd": events, "heldPathMarkedDeleted": marked}
    finally:
        os.close(held)


def main():
    if os.geteuid() != 0 or sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        raise SystemExit("Run as root on Linux with pidfd support.")
    witness, fixture, evidence = sys.argv[1:4]
    run = Run(witness, fixture)
    results, probe = [], None
    # name, expected outcome, mutation between 'check' and 'after', optional spec edit
    scenarios = [
        ("killed cgroup drains", "accept", lambda t, c: t.drain(), None),
        ("removed cgroup drains", "accept", None, None),
        ("root exits, descendant survives", "refuse", lambda t, c: t.kill_root(), None),
        ("rename cannot hide a survivor", "refuse", lambda t, c: (t.rename(), t.kill_root()), None),
        ("pathname replaced by a new cgroup", "refuse", lambda t, c: (t.drain(), t.remove(), t.replace()), None),
        ("control stops progressing", "refuse", lambda t, c: (os.kill(c.identity["pid"], signal.SIGSTOP), t.drain()), None),
        ("recycled PID: start ticks differ", "refuse at start", lambda t, c: None,
         lambda spec: {**spec, "target": {**spec["target"], "startTicks": spec["target"]["startTicks"] + 1}}),
    ]
    try:
        for name, expect, mutate, spec_edit in scenarios:
            try:
                target, control = Lease(run, "target"), Lease(run, "control")
                if mutate is None:
                    def mutate(t, c):
                        nonlocal probe
                        probe = removed_cgroup_probe(t)
                code, phases, refusal = run.witness_session(target, control, lambda: mutate(target, control), spec_edit)
            except Exception as error:
                # A harness failure is recorded as a failed scenario, never as a witness verdict.
                results.append({"scenario": name, "expect": expect, "harnessError": f"{type(error).__name__}: {error}",
                                "passed": False})
                continue
            seen = [phase["phase"] for phase in phases]
            if expect == "accept":
                last = phases[-1] if phases else {}
                passed = (code == 0 and seen == ["before", "check", "after"] and last.get("targetCgroupDrained") is True
                          and last.get("controlAdvanced") is True)
            elif expect == "refuse":
                passed = code == 2 and seen == ["before", "check"]
            else:
                passed = code == 2 and seen == []
            results.append({"scenario": name, "expect": expect, "exit": code, "phases": seen,
                            "refusal": refusal or None, "passed": passed})
    finally:
        run.cleanup()
    with open("/etc/os-release", encoding="utf-8") as stream:
        distro = dict(line.split("=", 1) for line in stream.read().splitlines() if "=" in line).get("PRETTY_NAME", "")
    record = {
        "schema": 1, "recordedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": "PASS" if results and all(r["passed"] for r in results) else "FAIL",
        "scope": "Witness only: real pidfds and cgroup v2 on this kernel, fixture as uid 65534. "
                 "No SPLAT lease, A2A, signed receipt or sensor event.",
        "kernel": platform.release(), "distro": distro.strip('"'), "python": platform.python_version(),
        "boot": run.boot, "witnessSha256": run.witness_sha, "fixtureSha256": run.fixture_sha,
        "removedCgroupProbe": probe, "kernelFacts": run.facts, "scenarios": results,
    }
    with open(evidence, "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(record["verdict"], f"{sum(r['passed'] for r in results)}/{len(results)} scenarios")
    return 0 if record["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
