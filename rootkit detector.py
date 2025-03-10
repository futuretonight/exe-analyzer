import psutil

def detect_rootkits():
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        if not proc.info['exe']:
            print(f"[ROOTKIT DETECTED] {proc.info['name']} (PID {proc.info['pid']})")

if __name__ == "__main__":
    detect_rootkits()
