#!/usr/bin/python3 -I
"""Admission gate for thesis experiment 8.4.2: collect the enforcing program's live map state and decide.

The daemon runs this between its last policy-map write and the workload's fork, holding its map-write
lock, and spawns the workload only on exit 0. One collector serves every variant, so B2 and B3 differ
only in what they compare the captured state against:

    OFF  capture only, admit                  (calibration: semantic validation absent)
    B2   kernel entries == the writer's bytes (ordinary readback)
    B3   kernel entries, decoded and interpreted as the identified program does, == the approval

Nothing here imports, calls or copies the daemon's encoder. The kernel state comes from bpftool, the
expected identities from os.stat on the approval's paths, and the device encoding from the kernel's
own MKDEV (include/linux/kdev_t.h, MINORBITS = 20). What the two sides still share is stated in
README.md beside this file.

Exit 0 admit, 1 reject, 2 indeterminate (also a refusal). The full record goes to the run directory.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

CONFIG = "/etc/splat-842/gate.json"
PROFILE = "/etc/splat-842/profile.json"
APPROVALS = "/etc/splat-842/approvals"
BPFTOOL = "/usr/sbin/bpftool"

ADMIT, REJECT, INDETERMINATE = 0, 1, 2


class Indeterminate(Exception):
    """A required observation could not be made. Never an admission."""


def bpftool(*args):
    out = subprocess.run([BPFTOOL, "-j", *args], capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise Indeterminate(f"bpftool {' '.join(args)} failed: {out.stderr.strip()}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def hexbytes(arr):
    # bpftool -j prints raw keys and values as arrays of "0x.." strings.
    return bytes(int(b, 16) for b in arr).hex()


def kernel_dev(st_dev):
    # The program keys on inode->i_sb->s_dev, the kernel-internal dev_t: (major << 20) | minor.
    return ((os.major(st_dev) << 20) | os.minor(st_dev)) & 0xFFFFFFFF


def btf_func_names(btf_obj_id, type_ids):
    # A link names its target as a BTF type id; the name is what says which hook it is.
    out = subprocess.run([BPFTOOL, "btf", "dump", "id", str(btf_obj_id)], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise Indeterminate(f"cannot read BTF object {btf_obj_id}: {out.stderr.strip()}")
    names = {}
    for m in re.finditer(r"^\[(\d+)\] FUNC '([^']*)'", out.stdout, re.MULTILINE):
        if int(m.group(1)) in type_ids:
            names[int(m.group(1))] = m.group(2)
    return names


def programs_held_by(pid):
    # The kernel's own account of which BPF programs a process holds open: fdinfo of each bpf-prog fd.
    held = set()
    fd_dir = f"/proc/{pid}/fdinfo"
    for fd in os.listdir(fd_dir):
        try:
            with open(os.path.join(fd_dir, fd)) as f:
                m = re.search(r"^prog_id:\s+(\d+)", f.read(), re.MULTILINE)
        except OSError:
            continue
        if m:
            held.add(int(m.group(1)))
    return held


def observe_deployment(profile, daemon_pid):
    """The program that decides exec for this daemon's workloads, and the maps IT references.

    Not a map found at a pin path, and not a program found by name: the shared WSL kernel can carry
    another SPLAT deployment's programs on the same hook. The admitting daemon's program is the one it
    holds open; any other program on the hook takes part in the decision under semantics this
    profile does not describe, so its presence makes the check indeterminate rather than guessed.
    """
    want = profile["execProgram"]
    lsm_links = [l for l in (bpftool("link", "show") or []) if l.get("attach_type") == "lsm_mac"]
    by_obj = {}
    for l in lsm_links:
        by_obj.setdefault(l["target_obj_id"], set()).add(l["target_btf_id"])
    names = {}
    for obj, ids in by_obj.items():
        names.update({(obj, i): n for i, n in btf_func_names(obj, ids).items()})
    at_hook = [l for l in lsm_links if names.get((l["target_obj_id"], l["target_btf_id"])) == want["attachFunc"]]
    held = programs_held_by(daemon_pid)
    ours = [l for l in at_hook if l["prog_id"] in held]
    others = [l for l in at_hook if l["prog_id"] not in held]
    if len(ours) != 1:
        raise Indeterminate(f"the admitting daemon holds {len(ours)} of the {len(at_hook)} programs on {want['attachFunc']}")
    if others:
        described = [{"link": l["id"], "prog": l["prog_id"], "name": bpftool("prog", "show", "id", str(l["prog_id"])).get("name")}
                     for l in others]
        raise Indeterminate(f"other programs also decide {want['attachFunc']}: {described}")
    prog = bpftool("prog", "show", "id", str(ours[0]["prog_id"]))
    if prog.get("name") != want["name"] or prog.get("type") != want["progType"]:
        raise Indeterminate(f"the daemon's program on the hook is {prog.get('type')}/{prog.get('name')}, not the profiled one")
    found = {"link": ours[0], "prog": prog, "attachFunc": want["attachFunc"], "daemonPid": daemon_pid,
             "programsHeldByDaemon": sorted(held)}

    maps = {}
    for map_id in found["prog"].get("map_ids", []):
        info = bpftool("map", "show", "id", str(map_id))
        for role, spec in profile["maps"].items():
            if info.get("name") == spec["name"]:
                if role in maps:
                    raise Indeterminate(f"the program references two maps named {spec['name']}")
                if (info.get("type"), info.get("bytes_key"), info.get("bytes_value")) != (spec["type"], spec["key"], spec["value"]):
                    raise Indeterminate(f"map {spec['name']} has layout {info.get('type')}/{info.get('bytes_key')}/"
                                        f"{info.get('bytes_value')}, profile says {spec['type']}/{spec['key']}/{spec['value']}")
                maps[role] = info
    missing = sorted(set(profile["maps"]) - set(maps))
    if missing:
        raise Indeterminate(f"the attached program does not reference {missing}")
    return dict(found, maps=maps)


def dump(map_id):
    return sorted((hexbytes(e["key"]), hexbytes(e["value"])) for e in (bpftool("map", "dump", "id", str(map_id)) or []))


def capture(deployment):
    # Two passes over every map; a hash map iterated while it changes can repeat or skip keys, so a
    # snapshot is only accepted when both passes agree. The daemon's lock makes that the expected case.
    passes = [{role: dump(info["id"]) for role, info in deployment["maps"].items()} for _ in range(2)]
    if passes[0] != passes[1]:
        raise Indeterminate("map contents changed between two capture passes")
    return passes[0]


def entries_for(entries, cgroup_id):
    prefix = cgroup_id.to_bytes(8, "little").hex()
    return [(k, v) for k, v in entries if k.startswith(prefix)]


def check_b2(state, written, cgroup_id):
    """Ordinary readback: does the kernel hold exactly the bytes the writer says it wrote, for this lease?"""
    reasons = []
    exec_entries = entries_for(state["allowed_exec"], cgroup_id)
    if sorted(k for k, _ in exec_entries) != sorted(written["allowedExec"]):
        reasons.append("allowed_exec_inodes keys for this cgroup differ from the written keys")
    if any(v != "01" for _, v in exec_entries):
        reasons.append("an allowed_exec_inodes value differs from the written 01")
    lease = dict(entries_for(state["leased_cgroups"], cgroup_id))
    if lease.get(written["leasedCgroup"]["key"]) != written["leasedCgroup"]["value"]:
        reasons.append("leased_cgroups value differs from the written deadline")
    if bool(entries_for(state["scratch_exec_devs"], cgroup_id)) != bool(written["scratchExec"]):
        reasons.append("scratch_exec_devs presence differs from the writer's scratchExec")
    return reasons


def resolve_approved(approval):
    """Identities of the approved executables, from the filesystem, bound to the content that was approved."""
    identities = {}
    for item in approval["executables"]:
        st = os.lstat(item["path"])
        if not os.path.isfile(item["path"]) or os.path.islink(item["path"]):
            raise Indeterminate(f"approved executable {item['path']} is not a regular file")
        with open(item["path"], "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        if digest != item["sha256"]:
            raise Indeterminate(f"approved executable {item['path']} no longer has the approved content")
        identities[(kernel_dev(st.st_dev), st.st_ino)] = item["path"]
    return identities


def check_b3(state, approval, cgroup_id, mission_id, now_boot_ns):
    """Semantic validation: what exec authority does the identified program grant this cgroup, against the approval?

    Interpretation of splat_bprm_check at the profiled source: no leased_cgroups entry means no policy;
    a deadline at or before now means every exec is refused; otherwise an exec is permitted iff its
    (cgroup, ino, dev, pad=0) key is present in allowed_exec_inodes (the value is never read), OR the
    cgroup has a scratch_exec_devs entry equal to the file's device and the file is on overlayfs.
    """
    reasons = []
    if approval.get("missionId") != mission_id:
        raise Indeterminate("the approval does not name this mission")
    with open("/proc/sys/kernel/random/boot_id") as f:
        if f.read().strip() != approval.get("bootId"):
            raise Indeterminate("the approval was made for a different boot")

    lease = entries_for(state["leased_cgroups"], cgroup_id)
    if len(lease) != 1:
        return ["the cgroup holds no lease, so the program applies no policy to it"], {}
    deadline = int.from_bytes(bytes.fromhex(lease[0][1]), "little")
    remaining = deadline - now_boot_ns
    if remaining <= 0:
        reasons.append("the installed deadline has already passed")
    if remaining > approval["leaseDurationSeconds"] * 1_000_000_000:
        reasons.append("the installed deadline is later than the approval allows")

    granted = {}
    for key, _value in entries_for(state["allowed_exec"], cgroup_id):
        raw = bytes.fromhex(key)
        ino = int.from_bytes(raw[8:16], "little")
        dev = int.from_bytes(raw[16:20], "little")
        pad = int.from_bytes(raw[20:24], "little")
        if pad != 0:
            raise Indeterminate(f"exec key {key} has nonzero padding; the program never builds such a key")
        granted[(dev, ino)] = key
    if entries_for(state["scratch_exec_devs"], cgroup_id):
        reasons.append("the cgroup holds a scratch execution grant the approval does not contain")

    approved = resolve_approved(approval)
    excess = sorted(set(granted) - set(approved))
    missing = sorted(set(approved) - set(granted))
    for dev, ino in excess:
        reasons.append(f"unauthorized exec grant: dev {dev:#x} ino {ino}")
    for ident in missing:
        reasons.append(f"approved executable not granted (over-restriction): {approved[ident]}")
    semantics = {"deadlineBootNs": deadline, "remainingNs": remaining,
                 "granted": [{"dev": d, "ino": i, "approvedPath": approved.get((d, i))} for d, i in sorted(granted)],
                 "approved": [{"dev": d, "ino": i, "path": p} for (d, i), p in sorted(approved.items())]}
    return reasons, semantics


def inject(deployment, spec):
    """Readback-corruption control: change installed data after the writer recorded its bytes."""
    st = os.lstat(spec["insertExecPath"])
    key = (spec["cgroupId"].to_bytes(8, "little") + st.st_ino.to_bytes(8, "little")
           + kernel_dev(st.st_dev).to_bytes(4, "little") + bytes(4))
    map_id = deployment["maps"]["allowed_exec"]["id"]
    out = subprocess.run([BPFTOOL, "map", "update", "id", str(map_id), "key", "hex", *[f"{b:02x}" for b in key],
                          "value", "hex", "01"], capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise Indeterminate(f"corruption injection failed: {out.stderr.strip()}")
    return {"insertedExecKey": key.hex(), "path": spec["insertExecPath"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cgroup-id", type=int, required=True)
    ap.add_argument("--cgroup-path", required=True)
    ap.add_argument("--mission-id", required=True)
    args = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", args.mission_id):
        print(json.dumps({"decision": "indeterminate", "reasons": ["unexpected mission id"]}))
        return INDETERMINATE

    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    written = json.load(sys.stdin)
    with open(CONFIG) as f:
        config = json.load(f)
    with open(PROFILE) as f:
        profile = json.load(f)
    record = {"missionId": args.mission_id, "cgroupId": args.cgroup_id, "cgroupPath": args.cgroup_path,
              "variant": config["variant"], "written": written, "gateStartedBootNs": started}
    code = INDETERMINATE
    try:
        # The cgroup the daemon names must be the directory it says: a cgroup v2 id is its inode number.
        if os.stat(args.cgroup_path).st_ino != args.cgroup_id:
            raise Indeterminate("the cgroup path's inode is not the cgroup id the daemon reported")
        with open(os.path.join(args.cgroup_path, "cgroup.procs")) as f:
            record["cgroupProcsBeforeAdmission"] = f.read().split()
        if record["cgroupProcsBeforeAdmission"]:
            raise Indeterminate("the lease cgroup already holds a process before admission")

        deployment = observe_deployment(profile, os.getppid())
        record["deployment"] = deployment
        if config.get("corrupt"):
            record["injection"] = inject(deployment, dict(config["corrupt"], cgroupId=args.cgroup_id))
        state = capture(deployment)
        record["capture"] = state
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        record["capturedBootNs"] = now

        if config["variant"] == "OFF":
            reasons = []
        elif config["variant"] == "B2":
            reasons = check_b2(state, written, args.cgroup_id)
        elif config["variant"] == "B3":
            with open(os.path.join(APPROVALS, args.mission_id + ".json")) as f:
                approval = json.load(f)
            record["approval"] = approval
            reasons, record["semantics"] = check_b3(state, approval, args.cgroup_id, args.mission_id, now)
        else:
            raise Indeterminate(f"unknown variant {config['variant']}")
        record["reasons"] = reasons
        record["decision"] = "reject" if reasons else "admit"
        code = REJECT if reasons else ADMIT
    except Indeterminate as e:
        record["reasons"] = [str(e)]
        record["decision"] = "indeterminate"
    except Exception as e:  # A gate that crashes is a refusal with its cause kept, not a silent admit.
        record["reasons"] = [f"{type(e).__name__}: {e}"]
        record["decision"] = "indeterminate"
    record["gateFinishedBootNs"] = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    with open(os.path.join(config["recordDir"], args.mission_id + ".gate.json"), "w") as f:
        json.dump(record, f, indent=2)
    print(json.dumps({"variant": config["variant"], "decision": record["decision"], "reasons": record["reasons"]}))
    return code


if __name__ == "__main__":
    sys.exit(main())
