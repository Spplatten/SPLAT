#!/usr/bin/env python3
"""Read-only Linux witness. Kernel observations, never a PID-directed cancellation helper.

Run under the trusted guest owner. stdin first carries the expected identities, then 'check'
or 'after'. The process holds pidfds and cgroup directory descriptors until EOF. It does not
mint/revoke leases, alter maps, move processes or signal a workload. A root compromise is outside
this observer's trust boundary. JSON output is observation evidence, not a cryptographic quote.
"""
import hashlib
import errno
import json
import os
import select
import stat
import sys
import time
import uuid

BASE = "/sys/fs/cgroup/splat_leases"


def read_command(stream):
    command = stream.readline(32)
    if command == b"":
        return None
    if command not in (b"check\n", b"after\n"):
        raise ValueError("unknown or incomplete witness command")
    return command[:-1].decode("ascii")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def parse_stat(text, expected_pid):
    # comm is parenthesized and may itself contain spaces or ')'. Field 3 begins AFTER the
    # final ')'; naive whitespace splitting silently reads the wrong birth time.
    prefix, delimiter, suffix = text.rpartition(")")
    if not delimiter or prefix.split("(", 1)[0].strip() != str(expected_pid):
        raise ValueError("invalid proc stat identity")
    fields = suffix.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return {"startTicks": int(fields[19]), "cpuTicks": int(fields[11]) + int(fields[12]), "state": fields[0]}


def validate_spec(spec):
    if (set(spec) != {"version", "boot", "target", "control", "sourceSha256"}
            or type(spec["version"]) is not int or spec["version"] != 1):
        raise ValueError("invalid witness schema")
    if str(uuid.UUID(spec["boot"])) != spec["boot"]:
        raise ValueError("noncanonical boot ID")
    for key in ("target", "control"):
        process = spec[key]
        if set(process) != {"taskId", "cgroup", "pid", "startTicks"}:
            raise ValueError("incomplete process identity")
        if uuid.UUID(hex=process["taskId"]).hex != process["taskId"] or uuid.UUID(hex=process["taskId"]).int == 0:
            raise ValueError("noncanonical task ID")
        for number in ("cgroup", "pid", "startTicks"):
            if type(process[number]) is not int or process[number] <= 0:
                raise ValueError("invalid native identity")
            if process[number] >= (1 << (31 if number == "pid" else 64)):
                raise ValueError("native identity overflow")
    if any(spec["target"][key] == spec["control"][key] for key in ("taskId", "cgroup", "pid")):
        raise ValueError("target/control overlap")
    if (not isinstance(spec["sourceSha256"], str) or len(spec["sourceSha256"]) != 64
            or any(char not in "0123456789abcdef" for char in spec["sourceSha256"])):
        raise ValueError("invalid source hash")


class HeldProcess:
    def __init__(self, expected):
        self.expected = expected
        self.pidfd = self.cgroup_fd = None
        self.group_name = "mission_" + str(uuid.UUID(hex=expected["taskId"]))
        self.path = BASE + "/" + self.group_name
        try:
            self.pidfd = os.pidfd_open(expected["pid"], 0)
            self.poller = select.poll()
            self.poller.register(self.pidfd, select.POLLIN)
            # A retained directory fd distinguishes the original cgroup from a replacement at
            # the same pathname. Unlike a nonce printed by telemetry, this handle is kernel-owned.
            self.cgroup_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            if os.fstat(self.cgroup_fd).st_ino != expected["cgroup"]:
                raise ValueError("wrong cgroup inode")
            self.before = self.live_sample()
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("pidfd", "cgroup_fd"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def exited(self):
        return bool(self.poller.poll(0))

    def read_at(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.cgroup_fd)
        with os.fdopen(fd, "r", encoding="ascii") as stream:
            result = stream.read(65537)
        if len(result) > 65536:
            raise ValueError("cgroup read budget")
        return result

    def populated(self):
        fields = dict(line.split() for line in self.read_at("cgroup.events").splitlines())
        if fields.get("populated") not in ("0", "1"):
            raise ValueError("missing populated state")
        return fields["populated"] == "1"

    def live_sample(self):
        if self.exited():
            raise ValueError("original process has exited")
        with open(f'/proc/{self.expected["pid"]}/stat', encoding="utf-8") as stream:
            sample = parse_stat(stream.read(65536), self.expected["pid"])
        with open(f'/proc/{self.expected["pid"]}/cgroup', encoding="ascii") as stream:
            membership = stream.read(65536).splitlines()
        if sample["startTicks"] != self.expected["startTicks"] or sample["state"] == "Z":
            raise ValueError("process birth mismatch")
        if membership != ["0::/splat_leases/" + self.group_name]:
            raise ValueError("process escaped its expected cgroup")
        if os.stat(self.path, follow_symlinks=False).st_ino != self.expected["cgroup"] or not self.populated() or self.exited():
            raise ValueError("process/cgroup changed during capture")
        return {**self.expected, **sample, "cgroupPopulated": True, "originalPidfdAlive": True}

    def drained(self):
        if not self.exited():
            return False
        try:
            info = os.stat(self.path, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_ino != self.expected["cgroup"]):
            raise ValueError("cgroup path was replaced")
        try:
            # Read relative to the original held fd even if the pathname vanished. A rename
            # with surviving children must return populated, never become a deletion proof.
            return not self.populated()
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ENODEV):
                raise
            # kernfs may stop serving interfaces after removal. Only accept that case if
            # procfs identifies THIS retained directory as deleted at its original pathname.
            # Unreadable files, a renamed handle, or an extant/replacement pathname are unknown.
            if os.readlink(f"/proc/self/fd/{self.cgroup_fd}") != self.path + " (deleted)":
                raise ValueError("held cgroup deletion not established") from error
            try:
                os.stat(self.path, follow_symlinks=False)
            except FileNotFoundError:
                return True
            raise ValueError("cgroup pathname remains or was replaced") from error


def main():
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        raise RuntimeError("Linux pidfd support required")
    line = sys.stdin.buffer.readline(16385)
    if len(line) > 16384 or not line.endswith(b"\n"):
        raise ValueError("witness request budget")
    spec = json.loads(line, object_pairs_hook=strict_object)
    validate_spec(spec)
    with open(__file__, "rb") as stream:
        source_hash = hashlib.sha256(stream.read()).hexdigest()
    if source_hash != spec["sourceSha256"]:
        raise ValueError("observer source differs from pin")
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
        boot = stream.read().strip()
    if boot != spec["boot"]:
        raise ValueError("boot mismatch")
    target = control = None
    try:
        target = HeldProcess(spec["target"])
        control = HeldProcess(spec["control"])
        def emit(phase, **values):
            print(json.dumps(dict(version=1, phase=phase, ok=True, boot=boot, sourceSha256=source_hash,
                                  targetTask=spec["target"]["taskId"], controlTask=spec["control"]["taskId"], **values)), flush=True)
        emit("before", target=target.before, control=control.before)
        while True:
            command = read_command(sys.stdin.buffer)
            if command is None:
                return
            if command == "check":
                emit("check", target=target.live_sample(), control=control.live_sample())
            elif command == "after":
                # This command arrives only AFTER the verifier accepted the cancellation
                # receipt. Require new control progress after this barrier, not CPU time
                # accumulated during setup or negative controls.
                after_start_cpu = control.live_sample()["cpuTicks"]
                end = time.monotonic() + 5
                while True:
                    live_control = control.live_sample()
                    if target.drained() and live_control["cpuTicks"] > after_start_cpu:
                        emit("after", originalTargetExited=True, targetCgroupDrained=True,
                             controlAdvanced=True, controlCpuAtAfterStart=after_start_cpu, control=live_control)
                        return
                    if time.monotonic() >= end:
                        raise ValueError("native drain/control progress not established")
                    time.sleep(0.05)
            else:
                raise ValueError("unknown witness command")
    finally:
        if target is not None:
            target.close()
        if control is not None:
            control.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No process contents, tokens or arbitrary exception text are exported on failure.
        print("Native witness refused: " + type(error).__name__, file=sys.stderr)
        sys.exit(2)
