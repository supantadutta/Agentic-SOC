#!/usr/bin/env bash
# Phase 5 - MISP threat-intelligence platform (192.168.50.30, 4 vCPU / 6 GB / 80 GB).
# Follows the misp-docker README; re-check it for the release you deploy:
#   https://github.com/MISP/misp-docker
set -euo pipefail

if [[ ! -d misp-docker ]]; then
    git clone https://github.com/MISP/misp-docker.git
fi
cd misp-docker
[[ -f .env ]] || cp template.env .env

cat <<'EOF'
Edit misp-docker/.env now and replace ALL development/default secrets
(admin e-mail/password, database passwords, encryption keys) and set BASE_URL to
https://192.168.50.30 before continuing.
EOF
read -r -p "Press Enter once .env is edited (Ctrl-C to abort)... "

docker compose pull
docker compose up -d
docker compose ps

cat <<'EOF'
Next steps (MISP web UI):
  1. Log in, change the admin password, enable the feeds you want (Sync Actions > Feeds).
  2. Create a dedicated user for the orchestrator with the "User" role (read-only use) and an
     auth key; store it as SOC_MISP_API_KEY on the Agentic SOC VM.
  3. Optional: add the lab's own IOC list as a local event so scenarios can be enriched offline.
MISP results are evidence for correlation, never an automatic block instruction.
EOF
