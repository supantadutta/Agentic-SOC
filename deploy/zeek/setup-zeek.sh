#!/usr/bin/env bash
# Phase 4b - Zeek network security monitoring on the sensor VM.
#   CAPTURE_IF=ens19 ./setup-zeek.sh
# Installs the official Zeek LTS packages from the openSUSE Build Service repository.
# Check https://docs.zeek.org/en/current/install.html for the repository line matching your
# Ubuntu release before running.
set -euo pipefail
CAPTURE_IF="${CAPTURE_IF:?set CAPTURE_IF to the capture interface, e.g. ens19}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. /etc/os-release
REPO="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}"

echo "deb ${REPO}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list >/dev/null
curl -fsSL "${REPO}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
sudo apt-get update
sudo apt-get install -y zeek-lts

ZEEK=/opt/zeek
sudo sed -i "s/^interface=.*/interface=${CAPTURE_IF}/" "$ZEEK/etc/node.cfg"
sudo sed -i 's|^Networks.*||' "$ZEEK/etc/networks.cfg"
echo "192.168.50.0/24    Agentic SOC lab" | sudo tee -a "$ZEEK/etc/networks.cfg" >/dev/null
sudo install -m 644 "$HERE/local.zeek" "$ZEEK/share/zeek/site/local.zeek"

sudo "$ZEEK/bin/zeekctl" deploy
sudo "$ZEEK/bin/zeekctl" status
# zeekctl cron restarts crashed workers and rotates logs.
echo "*/5 * * * * root $ZEEK/bin/zeekctl cron" | sudo tee /etc/cron.d/zeekctl >/dev/null
echo "Zeek logs: $ZEEK/logs/current/{conn,dns,http,ssl,files,notice}.log (JSON)"
