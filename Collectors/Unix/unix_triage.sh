#!/usr/bin/env bash
#
# unix_triage.sh
# Triage Collector Kit - Linux/Unix collector.
#
# Read-only artifact collection for incident response:
# processes, network, users, persistence, logs, configs, optional pcap.
# Nothing is modified or deleted on the host.

set -u
export LC_ALL=C

VERSION="0.1.0"
ORIG_ARGS="$*"

usage() {
    cat <<EOF
Usage:
  sudo ./unix_triage.sh [options]

Options:
  --output DIR               Output directory. Default: current directory.
  --pcap SECONDS             Record network capture for N seconds (needs tcpdump + root).
  --full-journal             Collect full journald in export format (can be large).
  --include-shell-history    Collect .bash_history / .zsh_history (may contain secrets).
  --include-shadow           Copy /etc/shadow (only if really needed).
  --recent-files             Find files modified in last 3 days in sensitive dirs.
  --app-logs                 Collect nginx / apache2 / httpd logs (can be large).
  -h, --help                 Show this help.

Examples:
  sudo ./unix_triage.sh
  sudo ./unix_triage.sh --pcap 30
  sudo ./unix_triage.sh --output /mnt/evidence --recent-files --app-logs
EOF
}

# ----------------------------------------------------------------------------
# Arguments
# ----------------------------------------------------------------------------

PCAP_SECONDS=0
FULL_JOURNAL=0
INCLUDE_HISTORY=0
INCLUDE_SHADOW=0
RECENT_FILES=0
APP_LOGS=0
OUT_ROOT="$PWD"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            OUT_ROOT="${2:-$PWD}"
            shift 2 || { echo "--output requires a value"; exit 1; }
            ;;
        --pcap)
            PCAP_SECONDS="${2:-0}"
            shift 2 || { echo "--pcap requires a value"; exit 1; }
            ;;
        --full-journal)       FULL_JOURNAL=1; shift ;;
        --include-shell-history) INCLUDE_HISTORY=1; shift ;;
        --include-shadow)     INCLUDE_SHADOW=1; shift ;;
        --recent-files)       RECENT_FILES=1; shift ;;
        --app-logs)           APP_LOGS=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        *)
            echo "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Preparation
# ----------------------------------------------------------------------------

umask 077

HOST="$(hostname 2>/dev/null || echo unknown_host)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$OUT_ROOT/triage_${HOST}_${TS}"

mkdir -p "$OUT_DIR"/{00_meta,01_processes,02_network,03_users,04_persistence,05_logs,06_filesystem,07_packages,08_config,09_pcap}
chmod 700 "$OUT_DIR"

LOG="$OUT_DIR/00_meta/collection.log"

section() {
    printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"
}

run_cmd() {
    # run_cmd <outfile> <command> [args...]
    local outfile="$OUT_DIR/$1"
    shift
    local cmd="$1"

    if command -v "$cmd" >/dev/null 2>&1; then
        "$@" > "$outfile" 2>"$outfile.err"
        local rc=$?
        if [ $rc -ne 0 ]; then
            echo "EXIT_CODE=$rc" >> "$outfile.err"
        fi
    else
        echo "COMMAND_NOT_FOUND: $cmd" > "$outfile"
    fi
}

copy_file() {
    # copy_file <src> <subdir>
    local src="$1"
    local subdir="$2"

    [ -f "$src" ] || return 0
    mkdir -p "$OUT_DIR/$subdir"

    local dest_name
    dest_name="$(echo "$src" | sed 's|^/||; s|/|_|g')"
    cp -a "$src" "$OUT_DIR/$subdir/$dest_name" 2>>"$LOG" || true
}

copy_glob() {
    # copy_glob <pattern> <subdir>
    local pattern="$1"
    local subdir="$2"
    local f

    for f in $pattern; do
        [ -f "$f" ] || continue
        copy_file "$f" "$subdir"
    done
}

section "Triage collection started"

{
    echo "Script version: $VERSION"
    echo "Collection time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Hostname: $HOST"
    echo "Arguments: $ORIG_ARGS"
    echo "User: $(id -un 2>/dev/null || echo unknown)"
    echo "UID: $(id -u 2>/dev/null || echo unknown)"
    echo "Output directory: $OUT_DIR"
} > "$OUT_DIR/00_meta/script_info.txt"

if [ "$(id -u)" -ne 0 ]; then
    section "WARNING: not running as root, some artifacts will be unavailable"
    echo "WARNING: not root. Some artifacts may be unavailable." >> "$OUT_DIR/00_meta/warnings.txt"
fi

# ----------------------------------------------------------------------------
# Dependency check (result saved into the archive for transparency)
# ----------------------------------------------------------------------------

section "Dependency check"

REQUIRED_COMMANDS=(bash hostname date cp tar sha256sum find grep sed awk ps ss ip last who w df mount lsblk)
OPTIONAL_COMMANDS=(lsof tcpdump journalctl systemctl netstat iptables-save ip6tables-save nft crontab atq dpkg rpm pacman apk pkg auditctl timeout shasum)

: > "$OUT_DIR/00_meta/dependencies.txt"

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "REQUIRED OK       $cmd" >> "$OUT_DIR/00_meta/dependencies.txt"
    else
        echo "REQUIRED MISSING  $cmd" >> "$OUT_DIR/00_meta/dependencies.txt"
    fi
done

for cmd in "${OPTIONAL_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "OPTIONAL OK       $cmd" >> "$OUT_DIR/00_meta/dependencies.txt"
    else
        echo "OPTIONAL MISSING  $cmd" >> "$OUT_DIR/00_meta/dependencies.txt"
    fi
done

# ----------------------------------------------------------------------------
# 00_meta: system info
# ----------------------------------------------------------------------------

section "Collecting system info"

run_cmd "00_meta/date_utc.txt" date -u
run_cmd "00_meta/date_local.txt" date
run_cmd "00_meta/uname_a.txt" uname -a
run_cmd "00_meta/hostname.txt" hostname
run_cmd "00_meta/id.txt" id
run_cmd "00_meta/uptime.txt" uptime
run_cmd "00_meta/os_release.txt" cat /etc/os-release
run_cmd "00_meta/proc_cmdline.txt" cat /proc/cmdline
run_cmd "00_meta/free_h.txt" free -h
run_cmd "00_meta/timedatectl.txt" timedatectl status
run_cmd "00_meta/chronyc_tracking.txt" chronyc tracking
run_cmd "00_meta/ntpq_p.txt" ntpq -p

copy_file /proc/1/cgroup 00_meta
copy_file /.dockerenv 00_meta

# ----------------------------------------------------------------------------
# 01_processes
# ----------------------------------------------------------------------------

section "Collecting processes"

run_cmd "01_processes/ps_auxww.txt" ps auxww
run_cmd "01_processes/ps_ef_forest.txt" ps -ef --forest
run_cmd "01_processes/ps_full.txt" ps -ww -eo pid,ppid,user,group,lstart,etime,stat,pcpu,pmem,args --no-headers
run_cmd "01_processes/proc_modules.txt" cat /proc/modules
run_cmd "01_processes/lsmod.txt" lsmod

if command -v lsof >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
        section "Collecting open files via lsof (120s limit)"
        timeout 120 lsof -nPl > "$OUT_DIR/01_processes/lsof_nPl.txt" 2>"$OUT_DIR/01_processes/lsof_nPl.err" || true
    else
        echo "lsof found but timeout missing; lsof skipped to avoid hanging." \
            > "$OUT_DIR/01_processes/lsof_skipped.txt"
    fi
fi

# ----------------------------------------------------------------------------
# 02_network
# ----------------------------------------------------------------------------

section "Collecting network information"

run_cmd "02_network/ss_tulnp.txt" ss -tulnp
run_cmd "02_network/ss_tunap.txt" ss -tunap
run_cmd "02_network/netstat_tulnp.txt" netstat -tulnp
run_cmd "02_network/netstat_tunap.txt" netstat -tunap
run_cmd "02_network/ip_addr.txt" ip -d addr
run_cmd "02_network/ip_route.txt" ip route
run_cmd "02_network/ip_neigh.txt" ip neigh
run_cmd "02_network/arp_an.txt" arp -an

copy_file /proc/net/tcp 02_network
copy_file /proc/net/tcp6 02_network
copy_file /proc/net/udp 02_network
copy_file /proc/net/udp6 02_network
copy_file /etc/resolv.conf 02_network
copy_file /etc/hosts 02_network

run_cmd "02_network/iptables_save.txt" iptables-save
run_cmd "02_network/ip6tables_save.txt" ip6tables-save
run_cmd "02_network/nft_list_ruleset.txt" nft list ruleset

# ----------------------------------------------------------------------------
# 03_users
# ----------------------------------------------------------------------------

section "Collecting users and sessions"

run_cmd "03_users/who_a.txt" who -a
run_cmd "03_users/w.txt" w
run_cmd "03_users/last_a.txt" last -a
run_cmd "03_users/lastb_a.txt" lastb -a
run_cmd "03_users/getent_passwd.txt" getent passwd
run_cmd "03_users/getent_group.txt" getent group

awk -F: '$3 == 0 {print $1}' /etc/passwd > "$OUT_DIR/03_users/uid0_accounts.txt" 2>/dev/null || true

if [ -r /etc/shadow ]; then
    awk -F: '$2 ~ /^!/ || $2 ~ /^\*/ {print $1}' /etc/shadow > "$OUT_DIR/03_users/locked_or_disabled_accounts.txt" 2>/dev/null || true
fi

run_cmd "03_users/sensitive_file_permissions.txt" \
    stat -c '%n %a %U %G' /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config

section "Collecting SSH artifacts"

copy_file /etc/ssh/sshd_config 03_users/ssh
copy_file /etc/ssh/ssh_config 03_users/ssh

find /root /home -type f \( -name authorized_keys -o -name authorized_keys2 \) -print0 2>/dev/null |
while IFS= read -r -d '' f; do
    copy_file "$f" "03_users/ssh/authorized_keys"
done

if [ "$INCLUDE_HISTORY" -eq 1 ]; then
    section "Collecting shell history"
    find /root /home -maxdepth 2 -type f \
        \( -name .bash_history -o -name .zsh_history -o -name .sh_history -o -name .history \) \
        -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        copy_file "$f" "03_users/history"
    done
fi

# ----------------------------------------------------------------------------
# 04_persistence
# ----------------------------------------------------------------------------

section "Collecting persistence artifacts"

if command -v crontab >/dev/null 2>&1; then
    run_cmd "04_persistence/crontab_root.txt" crontab -l

    while IFS=: read -r user _; do
        safe_user="$(printf '%s' "$user" | tr -c 'a-zA-Z0-9._-' '_')"
        outfile="$OUT_DIR/04_persistence/crontab_user_${safe_user}.txt"

        if crontab -u "$user" -l > "$outfile" 2>"$outfile.err"; then
            :
        else
            rm -f "$outfile" "$outfile.err"
        fi
    done < /etc/passwd
else
    echo "crontab not found" > "$OUT_DIR/04_persistence/crontab_missing.txt"
fi

copy_file /etc/crontab 04_persistence/cron
copy_file /etc/anacrontab 04_persistence/cron
copy_file /etc/cron.allow 04_persistence/cron
copy_file /etc/cron.deny 04_persistence/cron

copy_glob '/etc/cron.d/*' 04_persistence/cron/cron.d
copy_glob '/etc/cron.hourly/*' 04_persistence/cron/cron.hourly
copy_glob '/etc/cron.daily/*' 04_persistence/cron/cron.daily
copy_glob '/etc/cron.weekly/*' 04_persistence/cron/cron.weekly
copy_glob '/etc/cron.monthly/*' 04_persistence/cron/cron.monthly

find /var/spool/cron /var/spool/cron/crontabs -type f -print0 2>/dev/null |
while IFS= read -r -d '' f; do
    copy_file "$f" "04_persistence/cron/spool"
done

run_cmd "04_persistence/atq.txt" atq
find /var/spool/at -type f -print0 2>/dev/null |
while IFS= read -r -d '' f; do
    copy_file "$f" "04_persistence/at/spool"
done

if command -v systemctl >/dev/null 2>&1; then
    section "Collecting systemd data"

    run_cmd "04_persistence/systemctl_list_unit_files.txt" systemctl list-unit-files --no-pager
    run_cmd "04_persistence/systemctl_list_units_all.txt" systemctl list-units --all --no-pager
    run_cmd "04_persistence/systemctl_list_timers_all.txt" systemctl list-timers --all --no-pager
    run_cmd "04_persistence/systemctl_list_sockets_all.txt" systemctl list-sockets --all --no-pager
    run_cmd "04_persistence/systemctl_failed.txt" systemctl --failed --no-pager

    if command -v tar >/dev/null 2>&1; then
        tar -czf "$OUT_DIR/04_persistence/etc_systemd_system.tar.gz" -C / etc/systemd/system 2>/dev/null || true
        tar -czf "$OUT_DIR/04_persistence/etc_initd_rc.tar.gz" -C / etc/init.d etc/rc.local etc/rc.d 2>/dev/null || true
    fi
else
    echo "systemctl not found" > "$OUT_DIR/04_persistence/systemctl_missing.txt"
fi

section "Collecting shell startup files"

find /root /home -maxdepth 2 -type f \
    \( -name .bashrc -o -name .bash_profile -o -name .profile -o -name .zshrc -o -name .zprofile -o -name .zlogin \) \
    -print0 2>/dev/null |
tar -czf "$OUT_DIR/04_persistence/user_shell_startup.tar.gz" --null -T - 2>/dev/null || true

# ----------------------------------------------------------------------------
# 05_logs
# ----------------------------------------------------------------------------

section "Collecting text logs"

copy_glob '/var/log/auth.log*' 05_logs
copy_glob '/var/log/secure*' 05_logs
copy_glob '/var/log/syslog*' 05_logs
copy_glob '/var/log/messages*' 05_logs
copy_glob '/var/log/kern.log*' 05_logs
copy_glob '/var/log/daemon.log*' 05_logs
copy_glob '/var/log/dmesg*' 05_logs
copy_glob '/var/log/audit/audit.log*' 05_logs/audit

copy_file /var/log/wtmp 05_logs/binary
copy_file /var/log/btmp 05_logs/binary
copy_file /var/log/faillog 05_logs/binary

if command -v journalctl >/dev/null 2>&1; then
    section "Collecting journald"

    run_cmd "05_logs/journal_boots.txt" journalctl --list-boots --no-pager

    if ! journalctl -o short-iso --since=-24h --no-pager \
        > "$OUT_DIR/05_logs/journal_24h.txt" 2>"$OUT_DIR/05_logs/journal_24h.err" ||
        [ ! -s "$OUT_DIR/05_logs/journal_24h.txt" ]; then
        journalctl -o short-iso -n 50000 --no-pager \
            > "$OUT_DIR/05_logs/journal_last_50000.txt" 2>"$OUT_DIR/05_logs/journal_last_50000.err" || true
    fi

    if [ "$FULL_JOURNAL" -eq 1 ]; then
        section "Collecting full journald export"
        journalctl -o export --no-pager \
            > "$OUT_DIR/05_logs/journal_full.export" 2>"$OUT_DIR/05_logs/journal_full.err" || true
    fi
else
    echo "journalctl not found" > "$OUT_DIR/05_logs/journalctl_missing.txt"
fi

if command -v auditctl >/dev/null 2>&1; then
    section "Collecting auditd state"
    run_cmd "05_logs/auditctl_status.txt" auditctl -s
    run_cmd "05_logs/auditctl_rules.txt" auditctl -l
else
    echo "auditctl not found" > "$OUT_DIR/05_logs/auditctl_missing.txt"
fi

if [ "$APP_LOGS" -eq 1 ]; then
    section "Collecting web application logs"
    for appdir in /var/log/nginx /var/log/apache2 /var/log/httpd; do
        if [ -d "$appdir" ]; then
            find "$appdir" -type f -print0 2>/dev/null |
            while IFS= read -r -d '' f; do
                copy_file "$f" "05_logs/app/$(basename "$appdir")"
            done
        fi
    done
fi

# ----------------------------------------------------------------------------
# 06_filesystem
# ----------------------------------------------------------------------------

section "Collecting filesystem information"

run_cmd "06_filesystem/mount.txt" mount
run_cmd "06_filesystem/df_hT.txt" df -hT
run_cmd "06_filesystem/proc_mounts.txt" cat /proc/mounts
run_cmd "06_filesystem/lsblk.txt" lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID
run_cmd "06_filesystem/blkid.txt" blkid
run_cmd "06_filesystem/findmnt.txt" findmnt

copy_file /etc/fstab 06_filesystem

if [ "$RECENT_FILES" -eq 1 ]; then
    section "Finding files modified in last 3 days"
    find /etc /usr/local/bin /usr/local/sbin /tmp /var/tmp /dev/shm \
        -type f -mtime -3 -exec ls -la {} + \
        > "$OUT_DIR/06_filesystem/recent_modified_3d.txt" 2>/dev/null || true
fi

# ----------------------------------------------------------------------------
# 07_packages
# ----------------------------------------------------------------------------

section "Collecting installed packages"

if command -v dpkg >/dev/null 2>&1; then
    run_cmd "07_packages/dpkg_l.txt" dpkg -l
    run_cmd "07_packages/apt_mark_showmanual.txt" apt-mark showmanual
fi

if command -v rpm >/dev/null 2>&1; then
    run_cmd "07_packages/rpm_qa.txt" rpm -qa
fi

if command -v pacman >/dev/null 2>&1; then
    run_cmd "07_packages/pacman_Q.txt" pacman -Q
fi

if command -v apk >/dev/null 2>&1; then
    run_cmd "07_packages/apk_info_v.txt" apk info -v
fi

if command -v pkg >/dev/null 2>&1; then
    run_cmd "07_packages/pkg_info.txt" pkg info
fi

# ----------------------------------------------------------------------------
# 08_config
# ----------------------------------------------------------------------------

section "Collecting configuration files"

copy_file /etc/passwd 08_config
copy_file /etc/group 08_config
copy_file /etc/sudoers 08_config
copy_file /etc/ssh/sshd_config 08_config
copy_file /etc/resolv.conf 08_config
copy_file /etc/hosts 08_config
copy_file /etc/fstab 08_config
copy_file /etc/hostname 08_config
copy_file /etc/hosts.allow 08_config
copy_file /etc/hosts.deny 08_config
copy_file /etc/sysctl.conf 08_config

if command -v tar >/dev/null 2>&1; then
    tar -czf "$OUT_DIR/08_config/etc_sudoers.d.tar.gz" -C / etc/sudoers.d 2>/dev/null || true
fi

if [ "$INCLUDE_SHADOW" -eq 1 ]; then
    section "Copying /etc/shadow"
    copy_file /etc/shadow 08_config/shadow
else
    echo "/etc/shadow not copied. Use --include-shadow if needed." \
        > "$OUT_DIR/08_config/shadow_not_copied.txt"
fi

# ----------------------------------------------------------------------------
# 09_pcap
# ----------------------------------------------------------------------------

if [ "$PCAP_SECONDS" -gt 0 ]; then
    section "Recording network capture for ${PCAP_SECONDS}s"

    if command -v tcpdump >/dev/null 2>&1; then
        PCAP_FILE="$OUT_DIR/09_pcap/network_capture.pcap"

        if command -v timeout >/dev/null 2>&1; then
            timeout "$PCAP_SECONDS" tcpdump -i any -s 0 -w "$PCAP_FILE" \
                > "$OUT_DIR/09_pcap/tcpdump.log" 2>&1 || true
        else
            tcpdump -i any -s 0 -w "$PCAP_FILE" \
                > "$OUT_DIR/09_pcap/tcpdump.log" 2>&1 &
            TCPDUMP_PID=$!
            sleep "$PCAP_SECONDS"
            kill "$TCPDUMP_PID" 2>/dev/null || true
            wait "$TCPDUMP_PID" 2>/dev/null || true
        fi
    else
        echo "tcpdump not found" > "$OUT_DIR/09_pcap/tcpdump_missing.txt"
    fi
fi

# ----------------------------------------------------------------------------
# Hashes and archive
# ----------------------------------------------------------------------------

section "Computing SHA256 hashes"

(
    cd "$OUT_DIR" || exit 1

    if command -v sha256sum >/dev/null 2>&1; then
        find . -type f ! -name SHA256SUMS -print0 |
        xargs -0 sha256sum > SHA256SUMS 2>/dev/null || true
    elif command -v shasum >/dev/null 2>&1; then
        find . -type f ! -name SHA256SUMS -print0 |
        xargs -0 shasum -a 256 > SHA256SUMS 2>/dev/null || true
    else
        echo "No sha256sum or shasum available" > SHA256SUMS_MISSING.txt
    fi
)

section "Creating archive"

ARCHIVE="${OUT_DIR}.tar.gz"

if tar -czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")" 2>>"$LOG"; then
    echo "Archive created: $ARCHIVE" | tee -a "$LOG"
else
    echo "Failed to create archive" | tee -a "$LOG"
fi

section "Collection finished"

echo "Directory: $OUT_DIR"
echo "Archive:   $ARCHIVE"
echo "Log:       $LOG"
