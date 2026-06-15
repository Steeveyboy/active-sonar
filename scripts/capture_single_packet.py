from scapy.all import sniff, wrpcap, rdpcap

pkt = sniff(count=1)

wrpcap("captured_packet.pcap", pkt)
print("Captured packet saved to captured_packet.pcap")

packets = rdpcap("captured_packet.pcap")

print("Creating visualizations...")
packets[0].pdfdump("packet_viz.pdf", layer_shift=1)
