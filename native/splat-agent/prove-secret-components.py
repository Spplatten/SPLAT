#!/usr/bin/env python3
"""Record root component tests only. Never starts a daemon or changes BPF/service state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "root component tests require root"
    source = Path(__file__).resolve().parent
    inputs = [source / "Cargo.toml", source / "Cargo.lock", source / "build.rs", *sorted((source / "src").rglob("*.rs")),
        *sorted((source / "src" / "bpf").glob("*.c")), *sorted((source / "src" / "bpf").glob("*.h"))]
    hashes = {str(path.relative_to(source)): sha(path) for path in inputs}
    result = subprocess.run([str(args.test_binary), "--ignored", "root_secret", "--test-threads=1", "--nocapture"],
        capture_output=True, text=True, timeout=60)
    tested = re.findall(r"^test (\S+) \.\.\. ok$", result.stdout, re.MULTILINE)
    passed = result.returncode == 0 and len(tested) == 5 and all(sha(path) == hashes[str(path.relative_to(source))] for path in inputs)
    report = {"timestampUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kernel": os.uname().release,
        "boundary": "Root component tests only; no BPF or daemon lifecycle proof", "syntheticOnly": True,
        "serviceOrBpfChanged": False, "testBinarySha256": sha(args.test_binary), "sourceSha256": hashes,
        "probeSha256": sha(Path(__file__)), "tests": tested, "verdict": "PASS" if passed else "FAIL"}
    if not passed:
        report["diagnostics"] = result.stdout + result.stderr
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"verdict": report["verdict"], "passed": len(tested), "evidence": str(args.output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
