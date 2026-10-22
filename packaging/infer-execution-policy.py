#!/usr/bin/env python3
"""Extract a review candidate from saved x86_64 strace output; never execute or authorize a tool.

Capture representative cases in an existing controlled environment with strace -f -qq -o TRACE.
Supply file grants separately: an argument schema or an observed pathname is not authorization.
Unexercised paths remain unknown. The guest rejects unsupported syscalls when the reviewed policy
is launched; a candidate is never imported automatically or treated as a complete behavior proof.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

START = re.compile(r"^(?:(?:\[pid\s+\d+\]|\d+)\s+)?([a-z_][a-z_0-9]*)\(")
RESUMED = re.compile(r"^(?:(?:\[pid\s+\d+\]|\d+)\s+)?<\.\.\. ([a-z_][a-z_0-9]*) resumed>")
NOTICE = re.compile(r"^(?:(?:\[pid\s+\d+\]|\d+)\s+)?(?:--- |\+\+\+ )")
LAUNCH = {"execve", "exit_group", "write", "close"}


def observed_syscalls(trace):
    names = set()
    for index, line in enumerate(trace.splitlines(), 1):
        line = line.strip()
        if not line or NOTICE.match(line):
            continue
        match = START.match(line) or RESUMED.match(line)
        if not match:
            raise ValueError(f"Unrecognized trace line {index}; use strace -f -qq without timestamps or summaries")
        names.add(match.group(1))
    if "execve" not in names or "exit_group" not in names:
        raise ValueError("Trace must include executable launch and termination; completeness of branches is still unproven")
    return names


def candidate(trace_bytes, executable, grants):
    observed = observed_syscalls(trace_bytes.decode("utf-8", errors="strict"))
    if not isinstance(grants, list):
        raise ValueError("File grants must be an explicitly reviewed JSON array")
    return {
        "status": "candidate-needs-review",
        "limitations": "Observed calls are not a complete specification. The binary hash is measured at review, not attested by strace. Review file grants and replay positive and negative cases before adoption.",
        "executable": str(executable.resolve()),
        "executableSha256AtReview": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "traceSha256": hashlib.sha256(trace_bytes).hexdigest(),
        "addedLaunchSyscalls": sorted(LAUNCH - observed),
        "executionPolicy": {
            "schemaVersion": 1,
            "architecture": "x86_64",
            "syscalls": sorted(observed | LAUNCH),
            "fileGrants": grants,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--file-grants", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.trace.stat().st_size > 16 * 1024 * 1024:
            parser.error("Trace exceeds the 16 MiB candidate limit")
        result = candidate(args.trace.read_bytes(), args.executable, json.loads(args.file_grants.read_text(encoding="utf-8")))
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
