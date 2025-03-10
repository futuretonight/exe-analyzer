import psutil

def monitor_process(pid):
    process = psutil.Process(pid)
    for cmd in process.cmdline():
        print(f"[CMD] {cmd}")

if __name__ == "__main__":
    pid = int(input("Enter target process PID: "))
    monitor_process(pid)
