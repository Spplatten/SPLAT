"""Measure syscall wall duration against a DUMMY fixture; never infer hook-only execution time."""
import argparse
import errno
import hashlib
import json
import os
import platform
import statistics
import time
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--expect", choices=("allow", "deny"), required=True)
    parser.add_argument("--samples", type=int, default=10000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or not 100 <= args.samples <= 1000000:
        parser.error("Linux and 100..1000000 samples required")
    # The fixture must be created by the operator and contain ONLY this public marker.
    # Verify it BEFORE moving the benchmark into the constrained cgroup. A launcher retaining
    # this fd can guard against inode recycling; this script does not serve as that launcher.
    marker = b"SPLAT_PUBLIC_DUMMY_KEY_DO_NOT_USE\n"
    expected_inode = os.stat(args.fixture)
    durations, outcomes = [], []
    for _ in range(args.samples):
        start = time.perf_counter_ns()
        error = 0
        try:
            fd = os.open(args.fixture, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as ex:
            error = ex.errno
            elapsed = time.perf_counter_ns() - start
        else:
            elapsed = time.perf_counter_ns() - start
            try:
                stat = os.fstat(fd)
                if (stat.st_dev, stat.st_ino) != (expected_inode.st_dev, expected_inode.st_ino):
                    raise RuntimeError("Fixture identity changed")
                if os.read(fd, len(marker)+1) != marker:
                    raise RuntimeError("Use only the public dummy fixture")
            finally:
                os.close(fd)
        durations.append(elapsed)
        outcomes.append(error)
    wanted = 0 if args.expect == "allow" else errno.EPERM
    ordered = sorted(durations)
    result = {"schema":1, "expect":args.expect, "passed":all(e == wanted for e in outcomes),
        "metric":"userspace-observed os.open duration; includes syscall, Python exception path on denial, scheduling and all hooks",
        "samples_ns":durations, "errno":outcomes, "median_ns":statistics.median(ordered),
        "p95_ns":ordered[int(.95*(len(ordered)-1))], "p99_ns":ordered[int(.99*(len(ordered)-1))],
        "kernel":platform.release(), "machine":platform.machine(),
        "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixture_dev":expected_inode.st_dev, "fixture_ino":expected_inode.st_ino}
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
