from scapy.all import ARP, Ether, srp
import json
import socket

import argparse

def get_args():
    parser = argparse.ArgumentParser(description="Simple network scanner using ARP requests.")
    parser.add_argument("-s", "--subnet", required=False, help="Target subnet to scan (e.g., 192.168.1.0/24)")
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


def scan_subnet(ip_range):
    print(f"Scanning {ip_range}...")

    # Craft the Packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    packet = ether/arp
    
    # Send the Packet and Capture the Response
    result, _ = srp(packet, timeout=3, verbose=0)

    scanner_ip = get_local_ip()
    
    nodes = [{"id": scanner_ip, "label": "Scanner", "group": "scanner"}]
    links = []
    
    for sent, received in result:
        print(f"IP: {received.psrc}, MAC: {received.hwsrc}")
        target_ip = received.psrc
        target_mac = received.hwsrc
        
        nodes.append({"id": target_ip, "label": target_ip, "group": "target"})
        links.append({"source": scanner_ip, "target": target_ip})
        
    # Output the results in JSON format
    output = {
        "nodes": nodes,
        "links": links
    }
    
    with open("network_topology.json", "w") as f:
        json.dump(output, f, indent=4)
        
if __name__ == "__main__":
    args = get_args()
    
    if args.subnet:
        target_subnet = args.subnet
    else:
        target_subnet = "172.28.0.0/24"
        print(f"Using Default Subnet IP Range: {target_subnet}")
    
    
    scan_subnet(target_subnet)