import tkinter as tk
import psutil
import os
import sys
import platform
import subprocess
import threading
import time
import re
from collections import defaultdict

def detect_rootkits(result_text):
    """Perform comprehensive rootkit detection checks"""
    result_text.insert(tk.END, "[ROOTKIT] Starting rootkit detection...\n")
    result_text.see(tk.END)
    
    # Run checks in a separate thread
    threading.Thread(target=_run_rootkit_checks, args=(result_text,), daemon=True).start()

def _run_rootkit_checks(result_text):
    """Run various rootkit detection checks"""
    try:
        # Check if running on Windows
        if platform.system() == "Windows":
            _check_windows_rootkits(result_text)
        else:
            _check_linux_rootkits(result_text)
            
        # Cross-platform checks
        _check_network_anomalies(result_text)
        _check_file_integrity(result_text)
        _check_memory_anomalies(result_text)
        
        result_text.insert(tk.END, "[ROOTKIT] Rootkit detection completed\n")
        result_text.see(tk.END)
        
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error during rootkit detection: {str(e)}\n")
        result_text.see(tk.END)

def _check_windows_rootkits(result_text):
    """Windows-specific rootkit checks"""
    try:
        # Check for hidden processes
        result_text.insert(tk.END, "[ROOTKIT] Checking for hidden processes...\n")
        result_text.see(tk.END)
        
        # Get regular process list
        normal_procs = set([p.pid for p in psutil.process_iter()])
        
        # Check if Windows API and regular process lists differ
        # This is a simplified version - a real implementation would use Windows APIs
        if len(normal_procs) < 10:  # Suspiciously few processes
            result_text.insert(tk.END, "[ROOTKIT] WARNING: Suspiciously few processes detected\n")
            result_text.see(tk.END)
        
        # Check common rootkit file locations
        suspicious_paths = [
            r"C:\Windows\System32\drivers\rootkit",
            r"C:\Windows\System32\drivers\hidden",
            r"C:\Windows\System32\drivers\sst.sys",
            r"C:\Windows\System32\drivers\psdoom.sys",
            r"C:\Windows\System32\drivers\BEEP.sys",
            r"C:\Windows\System32\mimilib.dll",
            r"C:\Windows\System32\mimidrv.sys",
            r"C:\Windows\Temp\klogger.dll"
        ]
        
        for path in suspicious_paths:
            if os.path.exists(path):
                result_text.insert(tk.END, f"[ROOTKIT] WARNING: Suspicious file found: {path}\n")
                result_text.see(tk.END)
        
        # Check for common rootkit registry keys
        _check_registry_keys(result_text)
        
        # Check for SSDT hooks
        _check_ssdt_hooks(result_text)
        
        # Check for hidden services
        _check_hidden_services(result_text)
        
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error during Windows rootkit check: {str(e)}\n")
        result_text.see(tk.END)

def _check_linux_rootkits(result_text):
    """Linux-specific rootkit checks"""
    try:
        # Check for suspicious kernel modules
        result_text.insert(tk.END, "[ROOTKIT] Checking for suspicious kernel modules...\n")
        result_text.see(tk.END)
        
        suspicious_modules = [
            "rootkit", "hide", "hidepid", "hideproc", "suterusu", "adore", "modhide",
            "kkr", "knark", "rkit", "enyelkm", "synaptics", "aporq", "dkomrade"
        ]
        
        # Check loaded modules
        if os.path.exists("/proc/modules"):
            with open("/proc/modules", "r") as f:
                modules_content = f.read().lower()
                
                for module in suspicious_modules:
                    if module in modules_content:
                        result_text.insert(tk.END, f"[ROOTKIT] WARNING: Suspicious kernel module detected: {module}\n")
                        result_text.see(tk.END)
        
        # Check for hidden processes
        try:
            # Compare ps output with /proc directory
            ps_output = subprocess.check_output(["ps", "-ef"], universal_newlines=True)
            ps_pids = set(re.findall(r'\b\d+\b', ps_output))
            
            proc_pids = set()
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    proc_pids.add(pid)
            
            hidden_pids = proc_pids - ps_pids
            if hidden_pids:
                result_text.insert(tk.END, f"[ROOTKIT] WARNING: Possibly hidden processes found: {hidden_pids}\n")
                result_text.see(tk.END)
        except subprocess.SubprocessError:
            result_text.insert(tk.END, "[ROOTKIT] Could not compare process lists\n")
            result_text.see(tk.END)
        
        # Check common rootkit files
        rootkit_files = [
            "/dev/.hiddendir",
            "/etc/.hiddenfolder",
            "/lib/modules/.hidden",
            "/usr/share/.malware",
            "/tmp/.ICE-unix/.sshd",
            "/usr/bin/bsd-port",
            "/usr/bin/sshd2"
        ]
        
        for path in rootkit_files:
            if os.path.exists(path):
                result_text.insert(tk.END, f"[ROOTKIT] WARNING: Suspicious file found: {path}\n")
                result_text.see(tk.END)
                
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error during Linux rootkit check: {str(e)}\n")
        result_text.see(tk.END)

def _check_registry_keys(result_text):
    """Check Windows registry for suspicious keys"""
    if platform.system() != "Windows":
        return
        
    try:
        import winreg
        
        suspicious_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        
        result_text.insert(tk.END, "[ROOTKIT] Checking registry for suspicious entries...\n")
        result_text.see(tk.END)
        
        for hive, key_path in suspicious_keys:
            try:
                key = winreg.OpenKey(hive, key_path)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        # Check for suspicious values
                        suspicious_patterns = ["hidden", "rootkit", "spy", "keylog", "stealth"]
                        
                        for pattern in suspicious_patterns:
                            if pattern in name.lower() or (isinstance(value, str) and pattern in value.lower()):
                                result_text.insert(tk.END, f"[ROOTKIT] WARNING: Suspicious registry entry: {key_path}\\{name}\n")
                                result_text.see(tk.END)
                        i += 1
                    except WindowsError:
                        break
            except Exception:
                pass
    except ImportError:
        result_text.insert(tk.END, "[ROOTKIT] Cannot check registry (winreg module not available)\n")
        result_text.see(tk.END)

def _check_ssdt_hooks(result_text):
    """Check for SSDT hooks (Windows only)"""
    if platform.system() != "Windows":
        return
        
    # This would require a driver or more sophisticated detection
    # Simplified check just to demonstrate the concept
    result_text.insert(tk.END, "[ROOTKIT] Checking for SSDT hooks (limited capability)...\n")
    result_text.see(tk.END)

def _check_hidden_services(result_text):
    """Check for hidden services (Windows only)"""
    if platform.system() != "Windows":
        return
        
    try:
        # Get services using Windows command
        services_output = subprocess.check_output(["sc", "query", "type=", "service", "state=", "all"], universal_newlines=True)
        
        # Check for suspicious service names
        suspicious_names = ["hidden", "rootkit", "stealth", "spy", "keylog"]
        for name in suspicious_names:
            if name in services_output.lower():
                result_text.insert(tk.END, f"[ROOTKIT] WARNING: Potentially suspicious service containing '{name}' found\n")
                result_text.see(tk.END)
    except subprocess.SubprocessError:
        result_text.insert(tk.END, "[ROOTKIT] Could not check for hidden services\n")
        result_text.see(tk.END)

def _check_network_anomalies(result_text):
    """Check for network anomalies that might indicate rootkits"""
    try:
        result_text.insert(tk.END, "[ROOTKIT] Checking for network anomalies...\n")
        result_text.see(tk.END)
        
        # Check for suspicious connections
        connections = psutil.net_connections(kind='inet')
        
        # Look for listening on uncommon ports
        suspicious_ports = set()
        for conn in connections:
            # Check if it's a listening port
            if conn.status == 'LISTEN':
                # Common legitimate ports to ignore
                safe_ports = {80, 443, 22, 21, 25, 110, 143, 53, 3306, 5432, 3389, 1433, 8080}
                if conn.laddr.port not in safe_ports and conn.laddr.port > 1023:
                    suspicious_ports.add(conn.laddr.port)
        
        if suspicious_ports:
            result_text.insert(tk.END, f"[ROOTKIT] WARNING: Suspicious listening ports detected: {suspicious_ports}\n")
            result_text.see(tk.END)
        
        # Check for processes with network connections but hidden from task manager
        network_pids = set(conn.pid for conn in connections if conn.pid is not None)
        running_pids = set(p.pid for p in psutil.process_iter())
        
        hidden_network_pids = network_pids - running_pids
        if hidden_network_pids:
            result_text.insert(tk.END, f"[ROOTKIT] WARNING: Processes with network activity but hidden from process list: {hidden_network_pids}\n")
            result_text.see(tk.END)
            
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error checking network anomalies: {str(e)}\n")
        result_text.see(tk.END)

def _check_file_integrity(result_text):
    """Check integrity of critical system files"""
    try:
        result_text.insert(tk.END, "[ROOTKIT] Checking critical system file integrity...\n")
        result_text.see(tk.END)
        
        if platform.system() == "Windows":
            # Use SFC to check Windows system files
            try:
                # Run SFC in verification-only mode
                result = subprocess.run(["sfc", "/verifyonly"], 
                                       capture_output=True, 
                                       text=True, 
                                       check=False)
                
                if "Windows Resource Protection found corrupt files" in result.stdout:
                    result_text.insert(tk.END, "[ROOTKIT] WARNING: Corrupt system files detected by SFC\n")
                    result_text.see(tk.END)
            except subprocess.SubprocessError:
                result_text.insert(tk.END, "[ROOTKIT] Could not run SFC to verify system files\n")
                result_text.see(tk.END)
        else:
            # For Linux, check a few critical binaries
            critical_binaries = ["/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/top"]
            for binary in critical_binaries:
                if os.path.exists(binary):
                    # Check if file has been modified recently (simplified check)
                    mtime = os.path.getmtime(binary)
                    now = time.time()
                    
                    # If modified in the last 24 hours and not part of a system update
                    if now - mtime < 86400:  # 24 hours in seconds
                        result_text.insert(tk.END, f"[ROOTKIT] WARNING: Critical binary {binary} was modified recently\n")
                        result_text.see(tk.END)
    
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error checking file integrity: {str(e)}\n")
        result_text.see(tk.END)

def _check_memory_anomalies(result_text):
    """Check for memory anomalies that might indicate rootkits"""
    try:
        result_text.insert(tk.END, "[ROOTKIT] Checking for memory anomalies...\n")
        result_text.see(tk.END)
        
        # Check for unusual memory patterns
        # This is simplified - real detection would be more sophisticated
        processes = list(psutil.process_iter(['pid', 'name', 'memory_info']))
        
        # Group by process name to identify anomalies
        memory_by_name = defaultdict(list)
        for proc in processes:
            try:
                memory_by_name[proc.info['name']].append(proc.info['memory_info'].rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Look for duplicate processes with significantly different memory usage
        for name, memory_values in memory_by_name.items():
            if len(memory_values) > 1:
                avg = sum(memory_values) / len(memory_values)
                outliers = [m for m in memory_values if abs(m - avg) > avg * 0.7]  # 70% deviation
                
                if outliers and len(outliers) < len(memory_values):
                    result_text.insert(tk.END, f"[ROOTKIT] WARNING: Process {name} has instances with unusual memory patterns\n")
                    result_text.see(tk.END)
                    
    except Exception as e:
        result_text.insert(tk.END, f"[ROOTKIT] Error checking memory anomalies: {str(e)}\n")
        result_text.see(tk.END)

# Run standalone test if executed directly
if __name__ == "__main__":
    # Create a simple test window
    root = tk.Tk()
    root.title("Rootkit Detector Test")
    
    # Create a text widget to display results
    result_text = tk.scrolledtext.ScrolledText(root, width=80, height=20)
    result_text.pack(padx=10, pady=10)
    
    # Create a button to run the detection
    test_button = tk.Button(root, text="Run Rootkit Detection", 
                          command=lambda: detect_rootkits(result_text))
    test_button.pack(pady=10)
    
    root.mainloop()