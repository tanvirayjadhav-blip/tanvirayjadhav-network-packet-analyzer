# tanvirayjadhav-network-packet-analyzer
"PRODIGY _TrackCode_TaskNumber02"
network-packet-analyzer
from scapy.all import sniff, IP, TCP, UDP import sys

--- Configuration ---
Set the interface to sniff on (e.g., "eth0", "Wi-Fi", "en0").
If set to None, Scapy often picks the default interface.
INTERFACE = None

Set the number of packets to capture. Use 0 for infinite capture.
PACKET_COUNT = 10

def analyze_packet(packet): """ Processes and displays relevant information from a single captured packet. """ if IP in packet: # --- 1. Extract IP Layer Information --- src_ip = packet[IP].src dst_ip = packet[IP].dst protocol = packet[IP].proto

    # Map the protocol number to a common name for readability
    protocol_name = 'Unknown'
    if protocol == 6:
        protocol_name = 'TCP'
    elif protocol == 17:
        protocol_name = 'UDP'
    elif protocol == 1:
        protocol_name = 'ICMP'
    
    # --- 2. Extract Payload and Ports (if TCP or UDP) ---
    payload_data = None
    src_port = 'N/A'
    dst_port = 'N/A'
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload_data = bytes(packet[TCP].payload)
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload_data = bytes(packet[UDP].payload)

    # --- 3. Display the Analyzed Information ---
    print("\n" + "="*50)
    print(f"| Protocol: {protocol_name:<10} (Num: {protocol}) |")
    print(f"| Source IP: {src_ip:<20} Port: {src_port:<5}|")
    print(f"| Dest. IP: {dst_ip:<20} Port: {dst_port:<5}|")
    
    if payload_data:
        # Display a snippet of the raw payload data
        payload_display = payload_data[:30].hex()
        print(f"| Payload (first 30 bytes): {payload_display}...")
    else:
        print("| Payload: [No decipherable payload data]")
    
    print("="*50)
    sys.stdout.flush() # Ensure immediate printing

# If the packet has no IP layer (e.g., ARP, L2 frames), skip it
else:
    # print(f"Non-IP packet captured: {packet.summary()}") 
    pass
    
