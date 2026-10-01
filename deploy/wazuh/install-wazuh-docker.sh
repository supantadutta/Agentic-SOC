#!/usr/bin/env bash
# Phase 2 - Wazuh manager, indexer and dashboard (single-node Docker deployment).
# Run on the Wazuh VM (192.168.50.10, 8 vCPU / 10-12 GB RAM / 200 GB).
#
#   WAZUH_TAG=v4.x.y ./install-wazuh-docker.sh
#
# Always cross-check the steps with the current official guide for the tag you deploy:
#   https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
set -euo pipefail

if [[ -z "${WAZUH_TAG:-}" ]]; then
    echo "Set WAZUH_TAG to the current stable release, e.g. WAZUH_TAG=v4.x.y" >&2
    echo "Available tags: git ls-remote --tags https://github.com/wazuh/wazuh-docker.git" >&2
    exit 1
fi

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y git curl ca-certificates docker.io docker-compose-v2 || \
    sudo apt-get install -y git curl ca-certificates docker.io docker-compose-plugin

# The indexer (OpenSearch) needs a larger mmap count; persist it across reboots.
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
sudo sysctl -w vm.max_map_count=262144

if [[ ! -d wazuh-docker ]]; then
    git clone https://github.com/wazuh/wazuh-docker.git
fi
cd wazuh-docker
git fetch --tags
git checkout "$WAZUH_TAG"
cd single-node

# Certificate generation (procedure used by the 4.x single-node deployment).
sudo docker compose -f generate-indexer-certs.yml run --rm generator

cat <<'EOF'
Before starting the stack:
  1. Change the default passwords (indexer admin, kibanaserver, API wazuh-wui) following the
     "Change the password of Wazuh users" section of the Docker guide for your tag.
  2. Add deploy/wazuh/manager/ossec-manager.xml to config/wazuh_cluster/wazuh_manager.conf and
     deploy/wazuh/manager/local_rules.xml to the manager rules (bind mount or docker cp).
  3. Keep 9200 (indexer), 55000 (API) and 443 (dashboard) reachable only from the lab network.
EOF

sudo docker compose up -d
sudo docker compose ps
echo "Follow logs with: sudo docker compose logs -f"
