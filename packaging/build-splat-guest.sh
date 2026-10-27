#!/bin/sh
# Builds the SPLAT Guest: a minimal Debian 13 (trixie) root filesystem for WSL2. It holds only what
# the lease daemon, the Linux-lease templates and the root proof need, plus the licence record a
# redistributor owes for it. Run as root inside a Debian container; build-splat-guest.ps1 does that.
#
#   build-splat-guest.sh <snapshot YYYYMMDDTHHMMSSZ> <output directory> [with-sources]
#
# Every package comes from one snapshot.debian.org timestamp, and SOURCE_DATE_EPOCH is derived from
# it, so the same arguments rebuild the same filesystem. There is no kernel here: the guest runs on
# Microsoft's stock WSL2 kernel, and SPLAT's "no custom kernel" claim depends on that.
set -eu

usage='usage: build-splat-guest.sh <YYYYMMDDTHHMMSSZ> <output directory> [with-sources]'
snapshot=${1:?$usage}
out=${2:?$usage}
sources=${3:-}
case $snapshot in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
    *) echo "snapshot must look like 20261014T000000Z, not '$snapshot'" >&2; exit 2 ;;
esac
SOURCE_DATE_EPOCH=$(date -u -d "$(echo "$snapshot" | cut -c1-8)" +%s)
export SOURCE_DATE_EPOCH

# Each package is here for a reason the code states; anything not on this list is not needed.
#   systemd, systemd-sysv  provision, the managed bootstrap and doctor require systemd as PID 1
#   python3                run_code, LeasedWebProbe.py (ssl, json, http.client), provision's helper
#   procps, iproute2       ps and ss, run by the Linux-lease templates
#   ca-certificates        the leased web probes verify the publisher's certificate
#   curl, bpftool          probe-daemon.sh, so the guest that ships is the guest that is proven
packages=systemd,systemd-sysv,python3,procps,iproute2,ca-certificates,curl,bpftool
archive=http://snapshot.debian.org/archive
tab=$(printf '\t')

WORK=$(mktemp -d)
export WORK
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$out" "$WORK/hooks"

# Hooks run with the new root as $1. They are files rather than inline strings, so their quoting
# is the shell's ordinary quoting and not three nested layers of it.
cat > "$WORK/hooks/record.sh" <<'EOF'
set -eu
chroot "$1" dpkg-query -W -f='${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Installed-Size}\n' | sort > "$WORK/PACKAGES.tsv"
EOF
cat > "$WORK/hooks/trim.sh" <<'EOF'
set -eu
rm -rf "$1"/var/lib/apt/lists/* "$1"/var/cache/apt/*.bin "$1"/var/cache/debconf/*-old "$1"/var/log/apt "$1"/var/log/*.log
# Empty rather than absent: each import then gets its own identity at first boot.
: > "$1"/etc/machine-id
# WSL's kernel ships no loadable modules, so this unit can only fail and mark the system degraded.
ln -sf /dev/null "$1"/etc/systemd/system/systemd-modules-load.service
EOF
# What the daemon needs from the guest itself, so a plain import runs a lease with no installer's
# help. A fresh import on 2026-10-23 had none of the three and refused every lease until each was
# added by hand. The managed install still writes its own wsl.conf and sudoers, idempotently, so an
# archive built before this change keeps working.
cat > "$WORK/hooks/splat.sh" <<'EOF'
set -eu
# WSL starts systemd as PID 1 only when wsl.conf asks for it, and provision, the managed bootstrap and
# doctor all require it.
printf '[boot]\nsystemd=true\n' > "$1"/etc/wsl.conf
# The daemon guards /etc/sudoers in every lease and refuses a lease whose guarded path does not
# resolve. This guest has no sudo, so it gets an empty file only root may read: nothing reads it, and
# the lease has an inode to protect.
install -m 0440 -o root -g root /dev/null "$1"/etc/sudoers
# The daemon pins its hooks under /sys/fs/bpf and refuses to start unless that is bpffs. Its unit
# mounts it in ExecStartPre; this mounts it at boot, so a daemon started any other way - the root
# proof's, an operator's - finds it too. A service, not a mount unit: systemd refuses a mount unit
# for /sys/fs/bpf, an API filesystem it reserves to itself, yet under WSL it never mounted one.
# Guarded like the unit's own line, because a second bpffs mounted over the first hides the pins.
cat > "$1"/etc/systemd/system/splat-bpffs.service <<'UNIT'
[Unit]
Description=Mount bpffs at /sys/fs/bpf, where splat-agent pins its hooks
DefaultDependencies=no
Before=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf -o mode=0700 bpffs /sys/fs/bpf'

[Install]
WantedBy=sysinit.target
UNIT
mkdir -p "$1"/etc/systemd/system/sysinit.target.wants
ln -sf ../splat-bpffs.service "$1"/etc/systemd/system/sysinit.target.wants/splat-bpffs.service
EOF

# The dpkg filters stay in the image, so a package installed later also arrives without manuals,
# translations or documentation, but always with its copyright file.
mmdebstrap \
    --variant=minbase --architectures=amd64 --include="$packages" \
    --aptopt='APT::Install-Recommends "false"' \
    --aptopt='Acquire::Check-Valid-Until "false"' \
    --dpkgopt='path-exclude=/usr/share/man/*' \
    --dpkgopt='path-exclude=/usr/share/info/*' \
    --dpkgopt='path-exclude=/usr/share/locale/*' \
    --dpkgopt='path-include=/usr/share/locale/locale.alias' \
    --dpkgopt='path-exclude=/usr/share/doc/*' \
    --dpkgopt='path-include=/usr/share/doc/*/copyright' \
    --customize-hook='sh "$WORK/hooks/record.sh" "$1"' \
    --customize-hook="copy-out /usr/share/doc $WORK" \
    --customize-hook='sh "$WORK/hooks/trim.sh" "$1"' \
    --customize-hook='sh "$WORK/hooks/splat.sh" "$1"' \
    trixie "$WORK/splat-guest.tar" \
    "deb $archive/debian/$snapshot/ trixie main" \
    "deb $archive/debian/$snapshot/ trixie-updates main" \
    "deb $archive/debian-security/$snapshot/ trixie-security main"

# The licence record. Some packages ship their documentation as a symlink to a sibling from the same
# source, and the dpkg filter drops that symlink, so such a package is covered by the first sibling
# that kept a copyright file.
mkdir -p "$out/licenses"
cp "$WORK/PACKAGES.tsv" "$out/PACKAGES.tsv"
copyright_for() {
    if [ -f "$WORK/doc/$1/copyright" ]; then echo "$1"; return; fi
    awk -F"$tab" -v s="$2" '$3 == s { print $1 }' "$WORK/PACKAGES.tsv" | while read -r sibling; do
        if [ -f "$WORK/doc/$sibling/copyright" ]; then echo "$sibling"; break; fi
    done
}
missing=0
{
    printf 'SPLAT Guest: third-party licences\n'
    printf 'Built from Debian 13 (trixie) packages at snapshot %s. Not an official Debian release.\n' "$snapshot"
    printf 'Corresponding source for every package is listed in SOURCES.tsv.\n\n'
    while IFS="$tab" read -r pkg version src srcversion size; do
        owner=$(copyright_for "$pkg" "$src")
        printf '==== %s %s (source %s %s) ====\n' "$pkg" "$version" "$src" "$srcversion"
        if [ -n "$owner" ]; then
            cp "$WORK/doc/$owner/copyright" "$out/licenses/$pkg.copyright"
            [ "$owner" = "$pkg" ] || printf '(covered by the copyright file of %s, from the same source)\n' "$owner"
            cat "$WORK/doc/$owner/copyright"
        else
            missing=$((missing + 1))
            printf 'NO COPYRIGHT FILE FOUND\n'
        fi
        printf '\n'
    done < "$WORK/PACKAGES.tsv"
} > "$out/THIRD-PARTY-LICENSES.txt"
if [ "$missing" -ne 0 ]; then
    echo "$missing package(s) have no copyright file; see THIRD-PARTY-LICENSES.txt" >&2
    exit 1
fi

# One row per source package, with where Debian archives that exact source.
cut -f3,4 "$WORK/PACKAGES.tsv" | sort -u | awk -F"$tab" '{
    url = $2; gsub(":", "%3A", url)
    printf "%s\t%s\thttps://snapshot.debian.org/package/%s/%s/\n", $1, $2, $1, url
}' > "$out/SOURCES.tsv"

if [ "$sources" = with-sources ]; then
    # GPL redistribution in a commercial product needs the corresponding source on offer.
    printf 'deb-src %s/debian/%s/ trixie main\ndeb-src %s/debian-security/%s/ trixie-security main\n' \
        "$archive" "$snapshot" "$archive" "$snapshot" > /etc/apt/sources.list.d/splat-guest-src.list
    apt-get -o Acquire::Check-Valid-Until=false update -qq
    mkdir -p "$out/sources"
    (cd "$out/sources" && cut -f1,2 ../SOURCES.tsv | while IFS="$tab" read -r src version; do
        apt-get -qq source --download-only "$src=$version"
    done)
fi

xz -9e -T1 -c "$WORK/splat-guest.tar" > "$out/splat-guest.tar.xz"
(cd "$out" && sha256sum splat-guest.tar.xz > splat-guest.tar.xz.sha256)
tar_bytes=$(stat -c %s "$WORK/splat-guest.tar")
xz_bytes=$(stat -c %s "$out/splat-guest.tar.xz")
sha=$(cut -d' ' -f1 "$out/splat-guest.tar.xz.sha256")
count=$(wc -l < "$WORK/PACKAGES.tsv" | tr -d ' ')
printf '{\n  "name": "SPLAT Guest",\n  "base": "Debian 13 (trixie) packages, minbase",\n  "snapshot": "%s",\n  "sourceDateEpoch": %s,\n  "builder": "%s",\n  "explicitPackages": "%s",\n  "packageCount": %s,\n  "tarBytes": %s,\n  "xzBytes": %s,\n  "sha256": "%s"\n}\n' \
    "$snapshot" "$SOURCE_DATE_EPOCH" "$(mmdebstrap --version | head -n1)" "$packages" "$count" "$tar_bytes" "$xz_bytes" "$sha" > "$out/BUILD.json"

echo "SPLAT Guest: $count packages, $((tar_bytes / 1048576)) MiB unpacked as tar, $((xz_bytes / 1048576)) MiB as xz"
echo "Largest packages (KiB installed):"
sort -t"$tab" -k5,5nr "$WORK/PACKAGES.tsv" | head -n 20 | awk -F"$tab" '{ printf "  %8d  %s %s\n", $5, $1, $2 }'
