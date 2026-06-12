# active-sonar

An active network sonar engine. Uses Scapy to emit custom packet sweeps and renders live local subnet topologies through a force-directed D3.js graph.

A learning project in network cartography: start by mapping my own home LAN, then extend to remote networks I own.

> ⚠️ Scan only networks you own or have permission to scan.

## How it works

active-sonar runs an **ARP sweep** of a subnet: it broadcasts ARP requests, collects the IP/MAC of every host that answers, and writes the result to `network_topology.json` as a graph of `nodes` and `links` — ready to drop into a force-directed visualization.

## Setup

Requires Python 3.10+ on Linux/macOS/WSL.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install scapy
```

## Running

Raw packet crafting needs elevated privileges:

```bash
sudo .venv/bin/python sonar.py --subnet 192.168.1.0/24   # specific subnet
sudo .venv/bin/python sonar.py                            # default subnet
```

| Flag | Description | Default |
|------|-------------|---------|
| `-s`, `--subnet` | Target subnet in CIDR (e.g. `192.168.1.0/24`) | `172.28.0.0/24` |

Find your subnet with `ip addr` (Linux) or `ifconfig` (macOS). Results print to the terminal and are written to `network_topology.json`.

## Roadmap

**🗺️ Visualization frontend** — turn the JSON into a living map
- [ ] Render `network_topology.json` as a D3.js force-directed graph
- [ ] Serve it from a small local web app (FastAPI/Flask)
- [ ] Stream results live over WebSockets as hosts are discovered
- [ ] Interactive map: click for details, drag, filter by subnet

**🔍 Richer device data** — from "an IP is up" to "what is this thing?"
- [ ] MAC vendor (OUI) lookup → "Apple", "Raspberry Pi", "Ubiquiti"
- [ ] Reverse-DNS / mDNS hostnames instead of bare IPs
- [ ] Port & service fingerprinting of common ports
- [ ] OS fingerprinting from TTLs / scan responses

**🛰️ Beyond the local segment** — the path to remote networks
- [ ] ICMP and TCP-SYN sweeps for hosts beyond Layer 2
- [ ] Traceroute-based mapping of the hops to a remote network
- [ ] Run the scanner inside a remote network I own and merge vantage points

**🧱 Engineering quality** — make it a project, not a script
- [ ] `pyproject.toml` with pinned deps and a `sonar` console entry point
- [ ] Persist scans to SQLite and diff sweeps to detect new/vanished devices
- [ ] Continuous monitoring mode with alerts on unknown devices
- [ ] Tests with a mocked Scapy layer; type hints and dataclass models
- [ ] CI (lint + type-check + tests)
