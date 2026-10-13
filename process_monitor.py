
import psutil
import time
from datetime import datetime

CPU_THRESHOLD = 70
HIGH_CPU_DURATION = 10
SCAN_INTERVAL = 2

def collect_processes():
    processes = {}
    for process in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            info = process.info
            processes[info["pid"]] = {
                "name": info["name"] or "Unknown",
                "cpu": info["cpu_percent"] or 0.0
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def monitor_processes():
    previous_pids = set()
    high_cpu_since = {}
    print("Process Security Monitor Started")
    print("Press Ctrl+C to stop monitoring\n")

    for process in psutil.process_iter():
        try:
            process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        while True:
            current = collect_processes()
            current_pids = set(current.keys())
            now = time.time()

            for pid in current_pids - previous_pids:
                print(f"[{datetime.now()}] NEW PROCESS: {current[pid]['name']} (PID: {pid})")

            for pid, info in current.items():
                if info["cpu"] >= CPU_THRESHOLD:
                    high_cpu_since.setdefault(pid, now)
                    if now - high_cpu_since[pid] >= HIGH_CPU_DURATION:
                        print(f"[{datetime.now()}] HIGH CPU: {info['name']} (PID: {pid}, CPU: {info['cpu']}%)")
                else:
                    high_cpu_since.pop(pid, None)

            for pid in list(high_cpu_since):
                if pid not in current_pids:
                    high_cpu_since.pop(pid, None)

            previous_pids = current_pids
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\nProcess monitoring stopped.")

if __name__ == "__main__":
    monitor_processes()
