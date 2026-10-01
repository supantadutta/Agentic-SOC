#!/bin/bash
# Wazuh active response (Linux): lock or unlock a local account.
# Arguments: ["disable", "<user>"] or ["enable", "<user>"].
# Refuses root, system accounts (UID < 1000) and malformed names.
set -u
LOG=/var/ossec/logs/active-responses.log
log() { echo "$(date '+%Y/%m/%d %H:%M:%S') agentic-disable-user: $*" >> "$LOG"; }

read -r INPUT
ARGS=$(printf '%s' "$INPUT" | sed -n 's/.*"extra_args":[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '" ' | tr ',' ' ')
set -f  # no globbing while splitting the arguments
# shellcheck disable=SC2086
set -- $ARGS
ACTION="${1:-}"
USER_NAME="${2:-}"

if ! [[ "$USER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    log "refusing: invalid user name"
    exit 1
fi
if ! USER_UID=$(id -u "$USER_NAME" 2>/dev/null); then
    log "refusing: user $USER_NAME does not exist"
    exit 1
fi
if [ "$USER_UID" -lt 1000 ]; then
    log "refusing: $USER_NAME is a system account (uid $USER_UID)"
    exit 1
fi

case "$ACTION" in
    disable)
        usermod -L "$USER_NAME" && chage -E 0 "$USER_NAME"
        pkill -KILL -u "$USER_NAME" 2>/dev/null
        log "account $USER_NAME locked, expired and sessions terminated"
        ;;
    enable)
        usermod -U "$USER_NAME" && chage -E -1 "$USER_NAME"
        log "account $USER_NAME unlocked"
        ;;
    *)
        log "refusing: unknown action '$ACTION'"
        exit 1
        ;;
esac
exit 0
