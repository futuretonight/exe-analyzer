import requests
import hashlib

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

def get_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def check_virus_total(file_path):
    file_hash = get_file_hash(file_path)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        positives = result['data']['attributes']['last_analysis_stats']['malicious']
        if positives > 0:
            return f"[MALICIOUS] {positives} security vendors flagged this file!"
        return "[SAFE] No threats detected."
    return "[ERROR] Unable to contact VirusTotal."

if __name__ == "__main__":
    file_path = input("Enter file path to check: ")
    print(check_virus_total(file_path))
