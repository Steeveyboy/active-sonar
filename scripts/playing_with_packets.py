from scapy.all import IP, TCP, Ether, ARP, srp1, hexdump

# Create a simple packet with IP and TCP layers
pkt = IP(ttl=10, dst="192.168.1.1") / TCP(dport=80, flags="S")

# Display the packet details
print(pkt.summary())

pkt = Ether() / ARP(pdst="192.168.1.1")

print(hexdump(pkt))


