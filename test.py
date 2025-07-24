from scapy.all import sniff
def process_packet(packet):
    # Extract relevant information
    src_ip = packet[1].src if packet.haslayer('IP') else None
    dst_ip = packet[1].dst if packet.haslayer('IP') else None
    protocol = packet[1].proto if packet.haslayer('IP') else None
    payload = bytes(packet.payload) if packet.haslayer('Raw') else None

    # Display packet information
    print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload}")

# Start sniffing packets
sniff(prn=process_packet, count=10)