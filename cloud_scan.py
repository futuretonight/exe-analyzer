import requests
import hashlib
import os
import tkinter as tk
import json

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read in chunks in case of large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file(file_path, api_key):
    """Scan a file using VirusTotal API"""
    if not api_key:
        raise ValueError("API Key is missing")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)
    
    # First, check if the file has already been analyzed
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            # File exists in VirusTotal database
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if total > 0:
                return {
                    "status": "existing_scan",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
        
        # If the response code is not 200 or we couldn't parse the data properly,
        # upload the file for scanning
        upload_url = "https://www.virustotal.com/api/v3/files"
        
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            upload_response = requests.post(upload_url, headers=headers, files=files)
            
            if upload_response.status_code == 200:
                upload_data = upload_response.json()
                analysis_id = upload_data.get('data', {}).get('id')
                
                if analysis_id:
                    return {
                        "status": "submitted",
                        "analysis_id": analysis_id,
                        "message": "File submitted for analysis. Check back later for results.",
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                    }
        
        return {
            "status": "error",
            "message": f"Failed to scan file. HTTP Status: {upload_response.status_code}"
        }
    
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error during scanning: {str(e)}"
        }