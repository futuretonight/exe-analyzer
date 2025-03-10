import scapy.all as scapy
import tkinter as tk

def packet_callback(packet, result_text):
    if packet.haslayer(scapy.IP):
        result_text.insert(tk.END, f"[NETWORK] {packet[scapy.IP].src} → {packet[scapy.IP].dst}\n")

def monitor_network(result_text):
    result_text.insert(tk.END, "Starting network monitoring...\n")
    scapy.sniff(prn=lambda packet: packet_callback(packet, result_text), store=False)

if __name__ == "__main__":
    root = tk.Tk()
    result_text = tk.Text(root)
    result_text.pack()
    monitor_network(result_text)  # Pass result_text to the function
    root.mainloop()
