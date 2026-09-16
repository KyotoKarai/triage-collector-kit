#!/usr/bin/env bash
#
# install_deps.sh
# Triage Collector Kit - dependency installer for unix_triage.sh
#
# Detects the package manager and installs required (and optionally
# recommended) packages. Usage:
#   sudo ./install_deps.sh            # required + optional
#   sudo ./install_deps.sh --minimal  # required only

set -u

MINIMAL=0
[ "${1:-}" = "--minimal" ] && MINIMAL=1

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Run as root or install sudo." >&2
        exit 1
    fi
else
    SUDO=""
fi

REQUIRED=""
OPTIONAL=""
INSTALL_CMD=""

if command -v apt-get >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO apt-get install -y"
    REQUIRED="coreutils findutils grep sed gawk procps iproute2 util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables nftables auditd"
elif command -v dnf >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO dnf install -y"
    REQUIRED="coreutils findutils grep sed gawk procps-ng iproute util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables nftables audit"
elif command -v yum >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO yum install -y"
    REQUIRED="coreutils findutils grep sed gawk procps-ng iproute util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables nftables audit"
elif command -v pacman >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO pacman -S --needed --noconfirm"
    REQUIRED="coreutils findutils grep sed gawk procps-ng iproute2 util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables-nft audit"
elif command -v apk >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO apk add"
    REQUIRED="bash coreutils findutils grep sed gawk procps iproute2 util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables nftables audit"
elif command -v zypper >/dev/null 2>&1; then
    INSTALL_CMD="$SUDO zypper install -y"
    REQUIRED="coreutils findutils grep sed gawk procps iproute2 util-linux tar gzip"
    OPTIONAL="lsof tcpdump iptables nftables audit"
else
    echo "Unsupported package manager. Install dependencies manually, see docs/UNIX_TRIAGE.md" >&2
    exit 1
fi

echo "Installing required packages: $REQUIRED"
# shellcheck disable=SC2086
$INSTALL_CMD $REQUIRED

if [ "$MINIMAL" -eq 0 ]; then
    echo "Installing optional packages: $OPTIONAL"
    # shellcheck disable=SC2086
    $INSTALL_CMD $OPTIONAL || echo "Some optional packages failed to install - continuing."
fi

echo ""
echo "Availability check:"
for c in ps ss ip last who w df mount lsblk lsof tcpdump journalctl systemctl; do
    if command -v "$c" >/dev/null 2>&1; then
        echo "  OK       $c"
    else
        echo "  MISSING  $c"
    fi
done
