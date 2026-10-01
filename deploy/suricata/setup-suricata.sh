#!/usr/bin/env bash
# Phase 4a - Suricata IDS on the network-sensor VM (192.168.50.40).
# The sensor has a management NIC (with IP) and a capture NIC attached to the lab bridge in
# hub mode (see deploy/proxmox/README.md). Pass the capture interface name:
#
#   CAPTURE_IF=ens19 ./setup-suricata.sh
set -euo pipefail
CAPTURE_IF="${CAPTURE_IF:?set CAPTURE_IF to the capture interface, e.g. ens19}"
HERE="$(cd "$(dirname "$0")" && pwd)"

sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata jq

# Capture NIC: up, promiscuous, no IP address, no offloads that hide packets from the IDS.
sudo ip link set "$CAPTURE_IF" up promisc on
sudo ethtool -K "$CAPTURE_IF" gro off lro off 2>/dev/null || true

# Lab overrides (HOME_NET, af-packet interface, a Wazuh-only EVE file with alerts/anomalies).
sudo install -m 644 "$HERE/suricata-lab.yaml" /etc/suricata/suricata-lab.yaml
sudo sed -i "s/__CAPTURE_IF__/$CAPTURE_IF/" /etc/suricata/suricata-lab.yaml
if ! grep -q "suricata-lab.yaml" /etc/suricata/suricata.yaml; then
    echo "include: /etc/suricata/suricata-lab.yaml" | sudo tee -a /etc/suricata/suricata.yaml >/dev/null
fi

sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata
echo "Suricata running. EVE for Wazuh: /var/log/suricata/eve-wazuh.json"
