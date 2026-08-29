#!/bin/sh
# Runs INSIDE the leased cgroup, as the "agent". It performs one allowed action and three
# actions that step outside the lease. The allowed one must succeed; the other three must be
# stopped by the kernel with EPERM. Nothing here is an exploit — every "forbidden" line is a
# benign probe whose ONLY purpose is to demonstrate the boundary holding. No data leaves the box.

say() { printf '\n\033[36m# %s\033[0m\n' "$*"; }

say "ALLOWED: connect() to the one approved egress (127.0.0.1). Expect success or ECONNREFUSED, never EPERM."
curl --max-time 3 -s -o /dev/null -w '  curl exit=%{exitcode} http_code=%{http_code}\n' http://127.0.0.1/ \
  || echo "  (connection refused is fine — the kernel PERMITTED the connect syscall)"

say "FORBIDDEN: open() a protected inode (/etc/shadow). Expect: Permission denied."
cat /etc/shadow >/dev/null 2>&1 && echo "  !! UNEXPECTED: read succeeded" || echo "  blocked (cat could not open the inode)"

say "FORBIDDEN: connect() to an unapproved destination (1.1.1.1). Expect: Couldn't connect."
curl --max-time 3 -s -o /dev/null 1.1.1.1 && echo "  !! UNEXPECTED: connect succeeded" || echo "  blocked (egress outside the lease)"

say "FORBIDDEN: exec() a binary not on the lease allow-list (/usr/bin/dpkg). Expect: Permission denied."
if /usr/bin/dpkg --version >/dev/null 2>&1; then
  echo "  !! UNEXPECTED: exec succeeded"
else
  echo "  blocked (exec outside the lease - Permission denied)"
fi

say "canary complete — see the -EPERM lines the loader printed from the kernel ringbuf above/interleaved."
