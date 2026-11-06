#!/usr/bin/env python3
"""Public-data-only pilot fixture. Launch THROUGH an approved SPLAT lease, never as root.

The target leaves a descendant alive so the witness must check the whole cgroup. The control
advances CPU accounting at a bounded duty cycle. Neither role reads secrets or uses the network.
"""
import argparse
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("target", "control", "descendant"))
    parser.add_argument("--seconds", type=int, default=120)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 300:
        parser.error("duration must be between 10 and 300 seconds")
    end = time.monotonic() + args.seconds
    child = None
    if args.role == "target":
        child = subprocess.Popen([sys.executable, "-I", __file__, "descendant", "--seconds", str(args.seconds)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("SPLAT_PUBLIC_PILOT_READY " + args.role, flush=True)
    try:
        while time.monotonic() < end:
            if args.role == "control":
                work_until = time.monotonic() + 0.002
                while time.monotonic() < work_until:
                    pass
            time.sleep(0.02)
    finally:
        if child is not None:
            child.wait(timeout=5)


if __name__ == "__main__":
    main()
