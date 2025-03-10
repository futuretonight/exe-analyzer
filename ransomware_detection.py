import os
import hashlib
import tkinter as tk
import time
import threading

class FileMonitor:
    def __init__(self, directory, result_text):
        self.directory = directory
        self.result_text = result_text
        self.file_hashes = {}
        self.running = False
    
    def calculate_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, "rb") as f:
                md5_hash = hashlib.md5()
                for byte_block in iter(lambda: f.read(4096), b""):
                    md5_hash.update(byte_block)
            return md5_hash.hexdigest()
        except Exception:
            return None
    
    def initialize_file_hashes(self):
        """Create initial hashes of all files in the directory"""
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                hash_value = self.calculate_hash(file_path)
                if hash_value:
                    self.file_hashes[file_path] = hash_value
    
    def check_for_changes(self):
        """Check if files have been modified/encrypted"""
        modified_files = []
        
        for file_path, original_hash in self.file_hashes.items():
            if os.path.exists(file_path):
                current_hash = self.calculate_hash(file_path)
                if current_hash and current_hash != original_hash:
                    modified_files.append(file_path)
        
        return modified_files
    
    def start_monitoring(self):
        """Start monitoring files for changes"""
        self.running = True
        self.result_text.insert(tk.END, f"[RANSOMWARE] Starting monitoring of {self.directory}\n")
        self.result_text.see(tk.END)
        
        self.initialize_file_hashes()
        self.result_text.insert(tk.END, f"[RANSOMWARE] Initialized hashes for {len(self.file_hashes)} files\n")
        self.result_text.see(tk.END)
        
        while self.running:
            modified_files = self.check_for_changes()
            
            if modified_files:
                self.result_text.insert(tk.END, f"[RANSOMWARE] WARNING: {len(modified_files)} files modified!\n")
                
                # Show some of the modified files
                for file in modified_files[:5]:
                    self.result_text.insert(tk.END, f"[RANSOMWARE] Modified: {file}\n")
                
                if len(modified_files) > 5:
                    self.result_text.insert(tk.END, f"[RANSOMWARE] And {len(modified_files) - 5} more files...\n")
                
                self.result_text.see(tk.END)
            
            time.sleep(5)  # Check every 5 seconds
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False

def monitor_directory(directory, result_text):
    """Start monitoring a directory for ransomware activity"""
    monitor = FileMonitor(directory, result_text)
    
    # Run monitor in a separate thread
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return monitor

def detect_encryption_patterns(file_path, result_text):
    """Analyze file for encryption patterns"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4096)  # Read first 4KB
            
            # Check for randomness (encrypted data tends to be highly random)
            entropy = 0
            byte_count = {}
            
            for byte in header:
                byte_count[byte] = byte_count.get(byte, 0) + 1
            
            for count in byte_count.values():
                p = count / len(header)
                entropy -= p * (p.bit_length() if p > 0 else 0)
            
            # High entropy often indicates encryption
            if entropy > 7.8:  # Very high entropy threshold
                result_text.insert(tk.END, f"[RANSOMWARE] File may be encrypted: {file_path} (High entropy: {entropy:.2f})\n")
                result_text.see(tk.END)
                return True
            
            return False
            
    except Exception as e:
        result_text.insert(tk.END, f"[RANSOMWARE] Error analyzing file: {str(e)}\n")
        result_text.see(tk.END)
        return False