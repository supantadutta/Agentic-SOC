# Phase 1 — Proxmox and the isolated lab network

The lab runs on one Proxmox VE host (recommended: 8 cores/16 threads, 32 GB RAM, 1 TB NVMe,
1 GbE; 64 GB / 2 TB gives room for all VMs plus log and packet retention).

## Bridges

| Bridge | Physical port | Purpose |
|---|---|---|
| `vmbr0` | your uplink NIC | Proxmox management and the OPNsense WAN interface only |
| `vmbr1` | none | Isolated lab network `192.168.50.0/24`, gateway `192.168.50.1` (OPNsense LAN) |

Add `vmbr1` from the Proxmox UI (*Datacenter → Node → System → Network → Create → Linux
Bridge*, no ports, no IP), or append [`interfaces.vmbr1`](interfaces.vmbr1) to
`/etc/network/interfaces` and run `ifreload -a`.

`bridge-ageing 0` makes `vmbr1` flood every frame to every port (hub mode). The sensor VM's
capture NIC therefore sees all lab traffic without SPAN configuration. That is fine at lab
scale; for heavier traffic use `tc ... action mirred` port mirroring instead.

## VMs

| VM | IP | vCPU | RAM | Disk | NICs |
|---|---|---|---|---|---|
| OPNsense | 192.168.50.1 | 2 | 2 GB | 20 GB | `vmbr0` (WAN), `vmbr1` (LAN) |
| Wazuh | 192.168.50.10 | 8 | 10–12 GB | 200 GB | `vmbr1` |
| Agentic SOC | 192.168.50.20 | 4 | 6 GB | 50 GB | `vmbr1` |
| MISP | 192.168.50.30 | 4 | 6 GB | 80 GB | `vmbr1` |
| Network sensor | 192.168.50.40 | 4 | 4–6 GB | 80 GB | `vmbr1` (mgmt) + `vmbr1` (capture, no IP) |
| Windows Server / DC | 192.168.50.50 | 4 | 6–8 GB | 80 GB | `vmbr1` |
| Windows client | 192.168.50.60 | 4 | 4–6 GB | 60 GB | `vmbr1` |
| Linux endpoint | 192.168.50.70 | 2 | 2–4 GB | 30 GB | `vmbr1` |
| Kali | 192.168.50.100 | 2–4 | 4 GB | 50 GB | `vmbr1` |

Enable the QEMU guest agent on every VM, and take a snapshot of each endpoint once it is
configured, so attack scenarios can be repeated from a clean state.

## Firewall rules (OPNsense)

* LAN → WAN: allow only what the lab needs (package mirrors, threat-intel feeds, and the
  cloud LLM API if you use one). Block everything else, and always block Kali → WAN.
* WAN → LAN: block everything. Never port-forward Wazuh (443/1514/1515/9200/55000), MISP,
  PostgreSQL or the orchestrator API to the Internet.
* Create a **Host alias** named `AGENTIC_SOC_BLOCK` and a block rule on LAN (and WAN) that uses
  it as source and destination. The BLOCK_IP playbook adds addresses to this alias through the
  API (*System → Access → Users → API keys*), so it never edits rules directly. Give the API
  user only the alias privileges it needs.
