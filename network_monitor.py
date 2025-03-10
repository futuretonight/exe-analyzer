import tkinter as tk
import time
import threading

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def packet_callback(packet, result_text):
    """Process captured network packets"""
    if packet.haslayer(scapy.IP):
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst
        
        # Get protocol information
        proto = "TCP" if packet.haslayer(scapy.TCP) else "UDP" if packet.haslayer(scapy.UDP) else "Other"
        
        # Get port information if available
        src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else \
                   packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else "?"
        dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else \
                   packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else "?"
        
        # Log the packet information
        result_text.insert(tk.END, f"[NETWORK] {proto}: {src}:{src_port} → {dst}:{dst_port}\n")
        result_text.see(tk.END)

def monitor_network(result_text):
    """Start network monitoring using scapy"""
    if not SCAPY_AVAILABLE:
        result_text.insert(tk.END, "[NETWORK] Error: Scapy library not available. Network monitoring disabled.\n")
        result_text.see(tk.END)
        return
        
    try:
        result_text.insert(tk.END, "[NETWORK] Starting network monitoring...\n")
        result_text.see(tk.END)
        
        # Set up packet sniffer with a timeout to allow for clean stopping
        while True:
            try:
                scapy.sniff(prn=lambda packet: packet_callback(packet, result_text), 
                           store=False, timeout=2)
            except Exception as e:
                # Just log errors and continue
                result_text.insert(tk.END, f"[NETWORK] Sniffing error: {str(e)}\n")
                result_text.see(tk.END)
                time.sleep(1)
                
    except Exception as e:
        result_text.insert(tk.END, f"[NETWORK] Error in network monitoring: {str(e)}\n")
        result_text.see(tk.END)