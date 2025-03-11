import scapy.all as scapy
import tkinter as tk
import time

import threading

stop_event = threading.Event()  # Use this to signal all threads to stop

def packet_callback(packet, result_text):
    if packet.haslayer(scapy.IP):
        result_text.insert(tk.END, f"[NETWORK] {packet[scapy.IP].src} → {packet[scapy.IP].dst}\n")

def monitor_network(result_text):
    """Start network monitoring using Scapy"""
    result_text.insert(tk.END, "Starting network monitoring...\n")
    while not stop_event.is_set():
        try:
            scapy.sniff(prn=lambda packet: packet_callback(packet, result_text), 
                         store=False, timeout=2)  # Timeout prevents infinite loop
        except Exception as e:
            result_text.insert(tk.END, f"[NETWORK] Sniffing error: {str(e)}\n")
            time.sleep(1)

def stop_monitoring():
    """Stop the network monitoring loop"""
    result_text.insert(tk.END, "[NETWORK] Stopping monitoring...\n")
    stop_event.set()  # Stop all threads
    result_text.insert(tk.END, "[NETWORK] Monitoring stopped\n")

if __name__ == "__main__":
    root = tk.Tk()
    result_text = tk.Text(root)
    result_text.pack()
    monitor_network(result_text)  # Pass result_text to the function
    root.mainloop()
