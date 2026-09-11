#!/usr/bin/env bash
# SPLAT canary preflight: decides whether the running WSL2 kernel can enforce BPF-LSM.
# This is the load-bearing first step — it tells you which of three worlds you're in
# BEFORE you sink time into a build. Run inside WSL:  bash preflight.sh
set -uo pipefail

green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== SPLAT canary preflight =="
echo "kernel: $(uname -r)"
echo

verdict=GREEN
note() { echo "  - $1"; }
downgrade() { # $1 = target level
  if [ "$1" = RED ]; then verdict=RED
  elif [ "$verdict" != RED ]; then verdict=YELLOW; fi
}

# --- Kernel config (BPF-LSM, BPF syscall, BTF) ---
cfg=""
if [ -r /proc/config.gz ]; then cfg="$(zcat /proc/config.gz 2>/dev/null)"
elif [ -r "/boot/config-$(uname -r)" ]; then cfg="$(cat "/boot/config-$(uname -r)")"; fi

check_cfg() { # name  expected(y|m|any)
  local name="$1" want="$2" line
  if [ -z "$cfg" ]; then note "config unavailable — cannot confirm $name"; downgrade YELLOW; return; fi
  line="$(printf '%s\n' "$cfg" | grep -E "^${name}=" || true)"
  if [ -z "$line" ]; then red "  [MISSING] $name"; [ "$name" = CONFIG_BPF_LSM ] && downgrade RED || downgrade YELLOW
  else green "  [ok] $line"; fi
}
check_cfg CONFIG_BPF_SYSCALL y
check_cfg CONFIG_BPF_LSM y
check_cfg CONFIG_DEBUG_INFO_BTF y   # needed for CO-RE vmlinux.h; missing => external BTF or custom kernel

echo

# --- Is `bpf` actually in the ACTIVE LSM list? Config=y is necessary but not sufficient. ---
if [ -r /sys/kernel/security/lsm ]; then
  lsm="$(cat /sys/kernel/security/lsm)"
  echo "active LSMs: $lsm"
  if printf '%s' "$lsm" | tr ',' '\n' | grep -qx bpf; then
    green "  [ok] bpf LSM is active"
  else
    red "  [FIX] bpf not in active LSM list — add it via kernel command line (see wslconfig.sample)"
    downgrade YELLOW
  fi
else
  # securityfs is not mounted on a fresh WSL boot, so the active list can be unreadable while bpf is
  # perfectly active. This used to report that observation gap as YELLOW and then send the operator
  # to "[FIX] lines above" it had never printed. The boot command line is world-readable and is what
  # the kernel initialised its LSMs from: a stackable LSM named in the last lsm= there, and built in,
  # was initialised. Pure-bash tests on purpose: under pipefail, `printf "$cfg" | grep -q` loses to
  # SIGPIPE on a config this size and reads a present option as absent.
  req="$(tr ' ' '
' < /proc/cmdline | sed -n 's/^lsm=//p' | tail -n1)"
  if [[ ",$req," == *,bpf,* ]] && grep -qx 'CONFIG_BPF_LSM=y' <<<"$cfg"; then
    green "  [ok] bpf requested on the boot command line, and built in"
    note "active list unreadable (securityfs not mounted); boot lsm=$req"
  else
    red "  [FIX] cannot confirm bpf is active: securityfs is not mounted and the boot command line does not settle it"
    note "read the active list: sudo mount -t securityfs securityfs /sys/kernel/security"
    note "if bpf is missing from it, add it via the kernel command line (see wslconfig.sample)"
    downgrade YELLOW
  fi
fi

echo

# --- BTF blob present at runtime? ---
if [ -r /sys/kernel/btf/vmlinux ]; then green "  [ok] /sys/kernel/btf/vmlinux present (CO-RE will work)"
else red "  [FIX] no /sys/kernel/btf/vmlinux — need CONFIG_DEBUG_INFO_BTF kernel or an external BTF (BTFHub)"; downgrade YELLOW; fi

# --- cgroup v2 unified? bpf_get_current_cgroup_id keying assumes it. ---
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ]; then
  green "  [ok] cgroup v2 (unified) mounted"
else
  red "  [FIX] not cgroup v2 — enable systemd (/etc/wsl.conf [boot] systemd=true) or cgroup v2 cmdline"
  downgrade YELLOW
fi

echo
echo "== toolchain =="
# rustup installs into ~/.cargo and puts it on PATH from .bashrc, which a non-login shell never
# reads - so `command -v cargo` reported MISSING on a machine that had 1.98 installed and sank the
# verdict to YELLOW over nothing. Source the env the same way setup-guest.sh does before deciding.
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
export PATH="$HOME/.cargo/bin:$PATH"

for t in clang bpftool cargo rustc; do
  if have "$t"; then green "  [ok] $t ($("$t" --version 2>/dev/null | head -1))"; else yellow "  [missing] $t — run setup-guest.sh"; downgrade YELLOW; fi
done

echo
case "$verdict" in
  GREEN)  green  "VERDICT: GREEN — stock kernel can enforce. Run: bash setup-guest.sh && bash run-canary.sh" ;;
  YELLOW) yellow "VERDICT: YELLOW — fixable without a custom kernel. Every line above not marked [ok] names what to resolve; then re-run." ;;
  RED)    red    "VERDICT: RED — CONFIG_BPF_LSM absent. This kernel cannot host the substrate; a custom WSL2 kernel is required (see README.md beside this script)." ;;
esac
