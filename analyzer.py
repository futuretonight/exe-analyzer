import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import subprocess
from setup import install_dependencies_and_gui
import api_hooking
import network_monitor
import cmd_monitor
import keylogger_detection
import rootkit_detector
import ransomware_detection
import cloud_scan

class AnalyzerApp:
    def __init__(self, master):
        self.master = master
        master.title("Executable Analyzer")
        self.selected_file = None
        self.monitoring_threads = []

        # Set a glassy background
        master.configure(bg="#1E1E1E")

        self.label = tk.Label(master, text="Executable Analyzer", font=("Courier", 16, "bold"), fg="green", bg="#1E1E1E")
        self.label.pack(pady=10)

        # File selection
        self.file_button = tk.Button(master, text="Select File for Analysis", command=self.select_file, bg="#2D2D2D", fg="yellow", activebackground="#3C3C3C")
        self.file_button.pack(pady=5)

        # API key entry
        self.api_key_label = tk.Label(master, text="Enter VirusTotal API Key:", bg="#1E1E1E", fg="white", font=("Courier", 12))
        self.api_key_label.pack(pady=5)
        
        self.api_key_entry = tk.Entry(master, bg="#FFFFFF", fg="black", font=("Courier", 12), width=40)
        self.api_key_entry.pack(pady=5)
        self.api_key_entry.bind('<Return>', self.save_api_key)

        # Control buttons
        self.button_frame = tk.Frame(master, bg="#1E1E1E")
        self.button_frame.pack(pady=10)
        
        self.start_button = tk.Button(self.button_frame, text="Start Monitoring", command=self.start_monitoring, bg="#2D2D2D", fg="green", activebackground="#3C3C3C")
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.scan_button = tk.Button(self.button_frame, text="Cloud Scan", command=self.scan_file, bg="#2D2D2D", fg="blue", activebackground="#3C3C3C")
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Monitoring", command=self.stop_monitoring, bg="#2D2D2D", fg="red", activebackground="#3C3C3C")
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Results display
        self.result_text = scrolledtext.ScrolledText(master, width=70, height=20, bg="black", fg="white", font=("Courier", 10))
        self.result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.monitoring = False

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a file for analysis", filetypes=[("Executable files", "*.exe;*.dll")])
        if file_path:
            self.selected_file = file_path
            self.result_text.insert(tk.END, f"Selected file: {file_path}\n")
            self.result_text.see(tk.END)

    def start_monitoring(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first")
            return

        self.monitoring = True
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Starting monitoring...\n")
        
        try:
            # Launch the process
            process = subprocess.Popen(self.selected_file)
            pid = process.pid
            
            self.result_text.insert(tk.END, f"Launched process with PID: {pid}\n")
            
            # Start monitoring in separate threads
            self.monitoring_threads.append(threading.Thread(target=cmd_monitor.monitor_process, args=(pid, self.result_text)))
            self.monitoring_threads.append(threading.Thread(target=network_monitor.monitor_network, args=(self.result_text,)))
            self.monitoring_threads.append(threading.Thread(target=keylogger_detection.detect_keylogger, args=(self.result_text,)))
            self.monitoring_threads.append(threading.Thread(target=rootkit_detector.detect_rootkits, args=(self.result_text,)))
            
            # Start API hooking
            api_hooking.hook_process(pid, self.result_text)
            
            # Start all threads
            for thread in self.monitoring_threads:
                thread.daemon = True
                thread.start()
                
            self.result_text.insert(tk.END, "All monitoring systems active\n")
            
        except Exception as e:
            self.result_text.insert(tk.END, f"Error starting monitoring: {str(e)}\n")
        
        self.result_text.see(tk.END)

    def stop_monitoring(self):
        self.monitoring = False
        self.result_text.insert(tk.END, "Stopping monitoring...\n")
        # Threads will terminate naturally since they're daemon threads
        self.monitoring_threads = []
        self.result_text.insert(tk.END, "Monitoring stopped\n")
        self.result_text.see(tk.END)

    def save_api_key(self, event=None):
        api_key = self.api_key_entry.get()
        if api_key:
            self.result_text.insert(tk.END, "API Key saved successfully\n")
            self.result_text.see(tk.END)

    def scan_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first")
            return
            
        api_key = self.api_key_entry.get()
        if not api_key:
            messagebox.showerror("Error", "Please enter a VirusTotal API key")
            return
            
        self.result_text.insert(tk.END, "Starting cloud scan...\n")
        
        try:
            result = cloud_scan.scan_file(self.selected_file, api_key)
            self.result_text.insert(tk.END, f"Scan Result: {result}\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error during cloud scan: {str(e)}\n")
            
        self.result_text.see(tk.END)

if __name__ == "__main__":
    install_dependencies_and_gui()
    root = tk.Tk()
    app = AnalyzerApp(root)
    root.geometry("800x600")
    root.mainloop()