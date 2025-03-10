import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        print(f"[NETWORK] {packet[scapy.IP].src} → {packet[scapy.IP].dst}")

def monitor_network():
    print("Starting network monitoring...")
    scapy.sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    monitor_network()
