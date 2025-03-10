import os
import hashlib

def detect_encryption(file_path):
    original_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    while True:
        new_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
        if original_hash != new_hash:
            print(f"[RANSOMWARE DETECTED] File modified: {file_path}")
            break

if __name__ == "__main__":
    file_path = input("Enter a file to monitor: ")
    detect_encryption(file_path)
