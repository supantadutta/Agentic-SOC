#!/bin/bash
# Wazuh active response (Linux): collect volatile evidence into a local, hashed archive.
#   process list -> network connections -> recent files -> hashes -> relevant logs
# Arguments: ["incident-<id>"]. Output: /var/lib/agentic-soc/evidence/<tag>-<UTC>.tar.gz (+ .sha256)
# Read-only with respect to the system; retrieve the archive over SSH/SCP for analysis.
set -u
LOG=/var/ossec/logs/active-responses.log
BASE=/var/lib/agentic-soc/evidence
log() { echo "$(date '+%Y/%m/%d %H:%M:%S') agentic-collect-evidence: $*" >> "$LOG"; }

read -r INPUT
TAG=$(printf '%s' "$INPUT" | sed -n 's/.*"extra_args":[[:space:]]*\["\([^"]*\)".*/\1/p' | tr -cd 'A-Za-z0-9_-' | cut -c1-64)
TAG=${TAG:-manual}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BASE/$TAG-$STAMP"
umask 077
mkdir -p "$OUT"

{
    echo "host: $(hostname -f 2>/dev/null || hostname)"
    echo "collected_utc: $STAMP"
    uname -a
    uptime
} > "$OUT/system.txt" 2>&1

ps auxww > "$OUT/process_list.txt" 2>&1
(ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null) > "$OUT/network_connections.txt"
ip addr > "$OUT/ip_addr.txt" 2>&1
ip route > "$OUT/ip_route.txt" 2>&1
who -a > "$OUT/logged_in_users.txt" 2>&1
last -n 50 > "$OUT/last_logins.txt" 2>&1

# Files changed in the last 24 h in common staging locations (capped).
find /tmp /var/tmp /dev/shm /home /root -xdev -type f -mmin -1440 \
    -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n' 2>/dev/null | head -n 2000 > "$OUT/recent_files.txt"

# Hashes of recent executables or scripts (max 500 files, 50 MB each).
find /tmp /var/tmp /dev/shm /home /root -xdev -type f -mmin -1440 -size -50M \
    \( -perm -u+x -o -name '*.sh' -o -name '*.py' -o -name '*.elf' \) 2>/dev/null \
    | head -n 500 | xargs -r -d '\n' sha256sum > "$OUT/file_hashes.txt" 2>/dev/null

for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/audit/audit.log; do
    [ -f "$f" ] && tail -n 2000 "$f" > "$OUT/$(basename "$f").tail"
done
command -v journalctl >/dev/null 2>&1 && journalctl --since "-24h" -n 5000 --no-pager > "$OUT/journal.txt" 2>&1
crontab -l -u root > "$OUT/root_crontab.txt" 2>&1
ls -la /etc/cron.* /etc/systemd/system > "$OUT/persistence_locations.txt" 2>&1

tar -czf "$OUT.tar.gz" -C "$BASE" "$(basename "$OUT")" && rm -rf "$OUT"
sha256sum "$OUT.tar.gz" > "$OUT.tar.gz.sha256"
log "evidence written to $OUT.tar.gz ($(cut -d' ' -f1 "$OUT.tar.gz.sha256"))"
exit 0
