"""Run a bounded CPU and memory workload to exercise per-process alerts."""
import argparse
from datetime import datetime, timezone
import json
import os
import threading
import time

from resource_monitor import MonitorConfig, ResourceMonitor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=8.0)
    parser.add_argument("--memory-mb", type=int, default=32)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if args.seconds <= 0 or args.memory_mb < 1 or args.interval <= 0 or args.samples < 1:
        parser.error("seconds, memory-mb, interval, and samples must be positive")

    observed = []
    config = MonitorConfig(
        interval_seconds=args.interval,
        sustained_samples=args.samples,
        system_cpu_threshold_percent=101.0,
        system_memory_threshold_percent=101.0,
        process_cpu_threshold_percent=30.0,
        process_memory_threshold_mb=max(1.0, args.memory_mb * 0.75),
    )
    monitor = ResourceMonitor(config, callback=observed.append)

    # Touch each page so the memory allocation is resident and measurable.
    workload_memory = bytearray(args.memory_mb * 1024 * 1024)
    for offset in range(0, len(workload_memory), 4096):
        workload_memory[offset] = 1
    deadline = time.monotonic() + args.seconds

    def burn_cpu():
        value = 1
        while time.monotonic() < deadline:
            value = (value * 1664525 + 1013904223) & 0xFFFFFFFF

    worker = threading.Thread(target=burn_cpu, name="harmless-cpu-workload")
    worker.start()
    sample_deadline = deadline + args.interval * (args.samples + 2)
    try:
        while time.monotonic() < sample_deadline:
            _, events = monitor.sample_once()
            for event in events:
                print(json.dumps(event.to_dict()), flush=True)
            time.sleep(args.interval)
    finally:
        worker.join()

    process_alerts = [event for event in observed
                      if event.event_type == "sustained_process_resource_spike"
                      and event.details.get("pid") == os.getpid()]
    if not process_alerts:
        print("No sustained process alert observed; check platform permissions and thresholds.", flush=True)
        raise SystemExit(1)
    print(json.dumps({"result": "PASS", "pid": os.getpid(), "memory_mb": args.memory_mb,
                      "duration_seconds": args.seconds,
                      "alert_event_types": [event.event_type for event in process_alerts],
                      "timestamp": datetime.now(timezone.utc).isoformat()}), flush=True)


if __name__ == "__main__":
    main()
