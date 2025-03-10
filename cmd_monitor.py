import psutil
import tkinter as tk
import time
import threading

def monitor_process(pid, result_text):
    """Monitor a process using its PID and log activities"""
    try:
        process = psutil.Process(pid)
        result_text.insert(tk.END, f"Monitoring process: {process.name()} (PID: {pid})\n")
        result_text.see(tk.END)
        
        # Get initial state
        initial_connections = set([(conn.laddr.ip, conn.laddr.port, conn.raddr.ip if conn.raddr else None, 
                                    conn.raddr.port if conn.raddr else None, conn.status) 
                                   for conn in process.connections() if conn.laddr])
        
        initial_files = set([file.path for file in process.open_files()])
        
        # Monitor continuously
        while True:
            try:
                # Check if process is still running
                if not psutil.pid_exists(pid):
                    result_text.insert(tk.END, f"Process {pid} has terminated\n")
                    result_text.see(tk.END)
                    break
                
                # Check for new network connections
                current_connections = set([(conn.laddr.ip, conn.laddr.port, conn.raddr.ip if conn.raddr else None,
                                           conn.raddr.port if conn.raddr else None, conn.status) 
                                          for conn in process.connections() if conn.laddr])
                
                new_connections = current_connections - initial_connections
                for conn in new_connections:
                    if conn[2]:  # If there's a remote address
                        result_text.insert(tk.END, f"[PROCESS] New connection: {conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]} ({conn[4]})\n")
                        result_text.see(tk.END)
                initial_connections = current_connections
                
                # Check for new files
                current_files = set([file.path for file in process.open_files()])
                new_files = current_files - initial_files
                for file_path in new_files:
                    result_text.insert(tk.END, f"[PROCESS] File accessed: {file_path}\n")
                    result_text.see(tk.END)
                initial_files = current_files
                
                time.sleep(1)  # Check every second
                
            except psutil.NoSuchProcess:
                result_text.insert(tk.END, f"Process {pid} has terminated\n")
                result_text.see(tk.END)
                break
            except Exception as e:
                result_text.insert(tk.END, f"Error monitoring process: {str(e)}\n")
                result_text.see(tk.END)
                time.sleep(5)  # Wait longer on error
                
    except Exception as e:
        result_text.insert(tk.END, f"Error setting up process monitoring: {str(e)}\n")
        result_text.see(tk.END)