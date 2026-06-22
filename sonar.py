from scapy.all import ARP, Ether, IP, ICMP, srp1, sr1
from ipaddress import ip_network, ip_address
from tqdm import tqdm
import json
import socket
import argparse

DEFAULT_TIMEOUT = 1
OUTPUT_FILE = "network_topology.json"


def get_args():
    parser = argparse.ArgumentParser(description="Simple network scanner using ARP or ICMP sweeps.")
    parser.add_argument(
        "-s", "--subnet",
        required=False,
        help="Target to scan: CIDR subnet (e.g. 192.168.0.0/24) or hyphenated range (e.g. 192.168.0.100-112)",
    )
    parser.add_argument(
        "-m", "--method",
        choices=["arp", "icmp"],
        default="arp",
        help="Discovery method: 'arp' (Layer 2, local subnet only) or 'icmp' (Layer 3 ping). Default: arp",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-host probe timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    return parser.parse_args()


def get_local_ip():
    """Helper to get the IP of the machine running the script."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        SOCK_IP = s.getsockname()[0]
    except Exception:
        SOCK_IP = '127.0.0.1'
    finally:
        s.close()
    return SOCK_IP


def get_local_subnet():
    """Derive the /24 subnet of the machine running the script (e.g. '192.168.0.0/24')."""
    ip = get_local_ip()
    return str(ip_network(f"{ip}/24", strict=False))


def parse_targets(target):
    """Expand a target string into a list of host IP strings.

    Supports CIDR notation (e.g. '192.168.0.0/24') and last-octet hyphenated
    ranges (e.g. '192.168.0.100-112', meaning .100 through .112 inclusive).
    """
    if "-" in target:
        base, end = target.rsplit("-", 1)
        prefix = base.rsplit(".", 1)[0]
        start = int(ip_address(base))
        stop = int(ip_address(f"{prefix}.{end}"))
        if stop < start:
            raise ValueError(f"Range end {end} is before start {base}")
        return [str(ip_address(addr)) for addr in range(start, stop + 1)]

    return [str(host) for host in ip_network(target, strict=False).hosts()]


def arp_probe(ip, timeout):
    """Send an ARP request to a single host. Returns a (ip, mac) dict if it replies, else None."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    received = srp1(packet, timeout=timeout, verbose=0)
    if received:
        return {"ip": received.psrc, "mac": received.hwsrc}
    return None


def icmp_probe(ip, timeout):
    """Send an ICMP echo request to a single host. Returns a {ip} dict if it replies, else None.

    ICMP works at Layer 3, so it can reach hosts beyond the local segment but does
    not learn the MAC address the way an ARP probe does.
    """
    packet = IP(dst=ip) / ICMP()
    received = sr1(packet, timeout=timeout, verbose=0)

    if received:
        return {"ip": received.src, "mac": None}
    return None


PROBES = {
    "arp": arp_probe,
    "icmp": icmp_probe,
}


def scan_subnet(ip_range, method="arp", timeout=DEFAULT_TIMEOUT):
    probe = PROBES[method]
    hosts = parse_targets(ip_range)
    scanner_ip = get_local_ip()

    nodes = [{"id": scanner_ip, "label": "Scanner", "group": "scanner"}]
    links = []

    desc = f"Scanning {ip_range} ({method.upper()})"
    with tqdm(hosts, desc=desc, unit="host") as progress:
        for host in progress:
            result = probe(str(host), timeout)
            if not result:
                continue

            found_ip = result["ip"]
            mac = result["mac"]
            tqdm.write(f"  Found — IP: {found_ip}" + (f"  MAC: {mac}" if mac else ""))

            node = {"id": found_ip, "label": found_ip, "group": "target"}
            if mac:
                node["mac"] = mac
            nodes.append(node)
            links.append({"source": scanner_ip, "target": found_ip})

    output = {"nodes": nodes, "links": links}
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=4)


if __name__ == "__main__":
    args = get_args()

    if args.subnet:
        target_subnet = args.subnet
    else:
        target_subnet = get_local_subnet()
        print(f"Using Default Subnet IP Range: {target_subnet}")

    scan_subnet(target_subnet, method=args.method, timeout=args.timeout)
