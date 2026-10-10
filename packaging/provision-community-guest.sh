#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
set -euo pipefail
umask 022
[[ $(id -u) == 0 ]] || { echo 'Guest provisioning requires root.' >&2; exit 1; }
if [[ $# == 1 && $1 == --configure-systemd ]]; then
    # This runs only in a newly imported guest. Preserve other vendor settings and the original
    # configuration rather than replacing the distro's automount or interop policy wholesale.
    python3 - <<'PY'
import configparser
from pathlib import Path
import shutil

path = Path('/etc/wsl.conf')
config = configparser.ConfigParser(interpolation=None, strict=True)
if path.exists():
    if not Path('/etc/wsl.conf.splat-before').exists():
        shutil.copy2(path, '/etc/wsl.conf.splat-before')
    config.read(path)
if not config.has_section('boot'):
    config.add_section('boot')
config.set('boot', 'systemd', 'true')
with path.open('w') as stream:
    config.write(stream)
PY
    exit 0
fi
[[ $# == 2 && $2 =~ ^[a-f0-9]{64}$ ]] || { echo 'Expected daemon path and SHA-256.' >&2; exit 1; }
[[ $(sha256sum -- "$1" | cut -d ' ' -f 1) == "$2" ]] || { echo 'Daemon checksum mismatch.' >&2; exit 1; }
"$1" --help >/dev/null
[[ $(ps -p 1 -o comm=) == systemd ]] || { echo 'Enable systemd in this new distro and restart it before provisioning.' >&2; exit 2; }
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup v2 is required.' >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || { echo 'The WSL kernel has no active BPF-LSM; provisioning refused.' >&2; exit 2; }
[[ ! -e /opt/splat/splat-agent && ! -e /etc/systemd/system/splat-agent.service ]] || {
    echo 'Refusing to replace an existing daemon or service.' >&2; exit 1;
}
install -D -m 0755 -- "$1" /opt/splat/splat-agent
# The daemon owns cgroup creation and fail-closed kernel attachment; the installer cannot
# substitute a successful copy or an enabled unit for a healthy enforcement path.
cat > /etc/systemd/system/splat-agent.service <<'UNIT'
[Unit]
Description=SPLAT BPF-LSM lease daemon (AGPL-3.0; Platten Industries commercial licensing available)
After=network.target
[Service]
Type=simple
ExecStartPre=/bin/sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf'
ExecStart=/opt/splat/splat-agent --listen 127.0.0.1:50051
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now splat-agent.service
sleep 2
systemctl is-active --quiet splat-agent.service
printf '%s\n' 'Daemon running under this distro owner. Operator-side authorization and Row 2.4 remain unproven.'
