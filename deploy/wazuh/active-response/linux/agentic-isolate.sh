#!/bin/bash
# Wazuh active response (Linux): network-isolate this host, keeping only the Wazuh manager
# reachable so the SOC can still collect telemetry and release the host.
#
# Called by the orchestrator through PUT /active-response with arguments:
#   ["isolate", "<manager_ip>"]  or  ["release", "<manager_ip>"]
# Wazuh delivers them on stdin as JSON in parameters.extra_args.
# Install: /var/ossec/active-response/bin/agentic-isolate.sh (root:wazuh, mode 750).
# The agent must reach the manager by IP address (DNS is blocked while isolated).
set -u
LOG=/var/ossec/logs/active-responses.log
CHAIN_IN=AGENTIC_ISO_IN
CHAIN_OUT=AGENTIC_ISO_OUT

log() { echo "$(date '+%Y/%m/%d %H:%M:%S') agentic-isolate: $*" >> "$LOG"; }

read -r INPUT
# Parse extra_args without jq (not guaranteed to be installed on endpoints).
ARGS=$(printf '%s' "$INPUT" | sed -n 's/.*"extra_args":[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '" ' | tr ',' ' ')
set -f  # no globbing while splitting the arguments
# shellcheck disable=SC2086
set -- $ARGS
ACTION="${1:-}"
MANAGER="${2:-}"

if ! [[ "$MANAGER" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    log "refusing: invalid manager address '$MANAGER'"
    exit 1
fi

isolate() {
    for chain in "$CHAIN_IN" "$CHAIN_OUT"; do
        iptables -N "$chain" 2>/dev/null || iptables -F "$chain"
    done
    iptables -A "$CHAIN_IN" -i lo -j ACCEPT
    iptables -A "$CHAIN_IN" -s "$MANAGER" -j ACCEPT
    iptables -A "$CHAIN_IN" -j DROP
    iptables -A "$CHAIN_OUT" -o lo -j ACCEPT
    iptables -A "$CHAIN_OUT" -d "$MANAGER" -j ACCEPT
    iptables -A "$CHAIN_OUT" -j DROP
    iptables -C INPUT -j "$CHAIN_IN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN_IN"
    iptables -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN_OUT"
    if command -v ip6tables >/dev/null 2>&1; then
        for chain in "$CHAIN_IN" "$CHAIN_OUT"; do
            ip6tables -N "$chain" 2>/dev/null || ip6tables -F "$chain"
        done
        ip6tables -A "$CHAIN_IN" -i lo -j ACCEPT
        ip6tables -A "$CHAIN_IN" -j DROP
        ip6tables -A "$CHAIN_OUT" -o lo -j ACCEPT
        ip6tables -A "$CHAIN_OUT" -j DROP
        ip6tables -C INPUT -j "$CHAIN_IN" 2>/dev/null || ip6tables -I INPUT 1 -j "$CHAIN_IN"
        ip6tables -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null || ip6tables -I OUTPUT 1 -j "$CHAIN_OUT"
    fi
    log "host isolated (manager $MANAGER still reachable)"
}

release() {
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null 2>&1 || continue
        "$tool" -D INPUT -j "$CHAIN_IN" 2>/dev/null
        "$tool" -D OUTPUT -j "$CHAIN_OUT" 2>/dev/null
        for chain in "$CHAIN_IN" "$CHAIN_OUT"; do
            "$tool" -F "$chain" 2>/dev/null
            "$tool" -X "$chain" 2>/dev/null
        done
    done
    log "host released from isolation"
}

case "$ACTION" in
    isolate) isolate ;;
    release) release ;;
    *) log "refusing: unknown action '$ACTION'"; exit 1 ;;
esac
exit 0
