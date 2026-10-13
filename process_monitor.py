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
                "cpu": info["cpu_percent"] or 0.0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def monitor_processes(stop_event=None, callback=None):
    """Monitor processes and optionally send events to the threat engine."""
    previous_pids = set()
    high_cpu_since = {}

    print("Process Security Monitor Started")

    # Prime CPU measurements before collecting actual readings.
    for process in psutil.process_iter():
        try:
            process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        while stop_event is None or not stop_event.is_set():
            current = collect_processes()
            current_pids = set(current.keys())
            now = time.time()

            # Detect newly appearing processes.
            for pid in current_pids - previous_pids:
                info = current[pid]
                print(
                    f"[{datetime.now()}] NEW PROCESS: "
                    f"{info['name']} (PID: {pid})"
                )

                if callback:
                    callback({
                        "event_type": "NEW_PROCESS",
                        "pid": pid,
                        "process_name": info["name"],
                        "description": (
                            f"New process detected: {info['name']} (PID: {pid})"
                        ),
                        "details": {"cpu_percent": info["cpu"]},
                    })

            # Detect processes with sustained high CPU usage.
            for pid, info in current.items():
                if info["cpu"] >= CPU_THRESHOLD:
                    high_cpu_since.setdefault(pid, now)

                    if now - high_cpu_since[pid] >= HIGH_CPU_DURATION:
                        print(
                            f"[{datetime.now()}] HIGH CPU: "
                            f"{info['name']} (PID: {pid}, CPU: {info['cpu']}%)"
                        )

                        if callback:
                            callback({
                                "event_type": "HIGH_CPU_PROCESS",
                                "pid": pid,
                                "process_name": info["name"],
                                "description": (
                                    f"{info['name']} (PID: {pid}) "
                                    f"using {info['cpu']:.1f}% CPU"
                                ),
                                "value": info["cpu"],
                                "details": {"cpu_percent": info["cpu"]},
                            })

                        # Avoid generating an event every scan for the same
                        # continuous high-CPU episode.
                        high_cpu_since[pid] = now + 10**9
                else:
                    high_cpu_since.pop(pid, None)

            for pid in list(high_cpu_since):
                if pid not in current_pids:
                    high_cpu_since.pop(pid, None)

            previous_pids = current_pids

            # Check the stop signal frequently so shutdown is responsive.
            for _ in range(int(SCAN_INTERVAL * 10)):
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nProcess monitoring stopped.")

if __name__ == "__main__":
    monitor_processes()
