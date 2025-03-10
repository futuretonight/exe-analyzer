import os
import requests
import zipfile
import shutil
import subprocess
import sys

# GitHub repo details
UPDATE_URL = "https://github.com/YOUR_REPO/releases/latest"
DOWNLOAD_URL = "https://github.com/YOUR_REPO/releases/latest/download/malware_tool.zip"

# Required dependencies
REQUIRED_LIBRARIES = ["frida", "psutil", "scapy", "keyboard", "requests"]

def install_dependencies():
    """Checks and installs missing dependencies."""
    for lib in REQUIRED_LIBRARIES:
        try:
            __import__(lib)  # Try importing the library
        except ImportError:
            print(f"Installing {lib}...")
            subprocess.run([sys.executable, "-m", "pip", "install", lib], check=True)
    print("✅ All dependencies installed!")

def check_for_updates():
    """Checks GitHub for the latest version."""
    try:
        response = requests.get(UPDATE_URL)
        latest_version = response.text.split('tag/')[1].split('"')[0]  # Extract latest version
        return latest_version
    except Exception as e:
        print(f"⚠️ Update check failed: {e}")
        return None

def download_update():
    """Downloads and extracts the latest update."""
    try:
        print("⬇️ Downloading update...")
        response = requests.get(DOWNLOAD_URL, stream=True)
        with open("update.zip", "wb") as f:
            f.write(response.content)
        
        print("📦 Extracting update...")
        with zipfile.ZipFile("update.zip", "r") as zip_ref:
            zip_ref.extractall("update_temp")

        shutil.move("update_temp/malware_tool.exe", "malware_tool.exe")
        os.remove("update.zip")
        shutil.rmtree("update_temp")
        print("✅ Update complete! Restart the application.")
    except Exception as e:
        print(f"⚠️ Update failed: {e}")

if __name__ == "__main__":
    print("🔄 Checking for updates & dependencies...")
    install_dependencies()
    latest_version = check_for_updates()
    
    if latest_version:
        print(f"📢 Latest Version: {latest_version}")
        download_update()
