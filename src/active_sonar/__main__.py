"""CLI entrypoint for active-sonar."""

from __future__ import annotations

import argparse
import json

from .network_mapper import build_topology, discover_hosts, write_topology_html


def main() -> int:
    parser = argparse.ArgumentParser(description="Map and visualize a local network with Scapy.")
    parser.add_argument("cidr", help="CIDR range to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--json", dest="json_output", help="Write topology JSON to file")
    parser.add_argument("--html", dest="html_output", help="Write topology HTML visualization")
    args = parser.parse_args()

    try:
        hosts = discover_hosts(args.cidr)
    except RuntimeError as exc:
        parser.exit(2, f"error: {exc}\n")

    topology = build_topology(hosts)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(topology, f, indent=2)

    if args.html_output:
        write_topology_html(topology, args.html_output)

    if not args.json_output and not args.html_output:
        print(json.dumps(topology, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
