import tkinter as tk
import psutil
import time
import threading

def detect_keylogger(result_text):
    """Detect potential keyloggers on the system"""
    result_text.insert(tk.END, "[KEYLOGGER] Starting keylogger detection...\n")
    result_text.see(tk.END)
    
    suspicious_processes = []
    
    try:
        # List of common keylogger process names
        keylogger_names = [
            'keylogger', 'klog', 'keylog', 'keyspy', 'keycapture', 
            'spykey', 'hookkey', 'keyhook', 'keyboard spy', 'keysniffer'
        ]
        
        # Look for suspicious processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if process name contains suspicious keywords
                proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                if any(keyword in proc_name for keyword in keylogger_names):
                    suspicious_processes.append(proc.info)
                    result_text.insert(tk.END, f"[KEYLOGGER] Suspicious process found: {proc.info['name']} (PID: {proc.info['pid']})\n")
                    result_text.see(tk.END)
                
                # Check command line for suspicious keywords
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
                if any(keyword in cmdline for keyword in keylogger_names):
                    if proc.info not in suspicious_processes:
                        suspicious_processes.append(proc.info)
                        result_text.insert(tk.END, f"[KEYLOGGER] Suspicious cmdline: {proc.info['name']} (PID: {proc.info['pid']})\n")
                        result_text.see(tk.END)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        if not suspicious_processes:
            result_text.insert(tk.END, "[KEYLOGGER] No suspicious keylogger processes detected\n")
            result_text.see(tk.END)
    
    except Exception as e:
        result_text.insert(tk.END, f"[KEYLOGGER] Error during detection: {str(e)}\n")
        result_text.see(tk.END)