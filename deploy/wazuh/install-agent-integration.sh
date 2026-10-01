#!/usr/bin/env bash
# Install the Agentic SOC pieces on the Wazuh side.
#
#   ./install-agent-integration.sh manager   # run inside the wazuh.manager container (or on a package install)
#   ./install-agent-integration.sh linux     # run on each Linux agent (incl. the sensor)
#
# Docker example for the manager:
#   docker cp deploy/wazuh single-node-wazuh.manager-1:/tmp/agentic
#   docker exec -it single-node-wazuh.manager-1 bash /tmp/agentic/install-agent-integration.sh manager
# Windows agents: copy deploy/wazuh/active-response/windows/* to
#   C:\Program Files (x86)\ossec-agent\active-response\bin\  and restart the Wazuh service.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OSSEC=/var/ossec

case "${1:-}" in
    manager)
        install -o root -g wazuh -m 750 "$HERE/manager/integrations/custom-agentic-soc.py" \
            "$OSSEC/integrations/custom-agentic-soc.py"
        install -o wazuh -g wazuh -m 660 "$HERE/manager/local_rules.xml" "$OSSEC/etc/rules/agentic_soc_rules.xml"
        echo "Now merge manager/ossec-manager.xml into $OSSEC/etc/ossec.conf (set the api_key),"
        echo "validate with $OSSEC/bin/wazuh-logtest, then restart the manager."
        ;;
    linux)
        for script in "$HERE"/active-response/linux/*.sh; do
            install -o root -g wazuh -m 750 "$script" "$OSSEC/active-response/bin/$(basename "$script")"
        done
        mkdir -p /var/lib/agentic-soc/evidence && chmod 700 /var/lib/agentic-soc/evidence
        echo "Merge the matching agents/ossec-agent-*.xml into $OSSEC/etc/ossec.conf and restart wazuh-agent."
        ;;
    *)
        echo "usage: $0 manager|linux" >&2
        exit 1
        ;;
esac
