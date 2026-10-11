
import time
from datetime import datetime

import psutil


# Configurable thresholds for initial testing
CPU_THRESHOLD = 85.0
MEMORY_THRESHOLD = 90.0

# Require repeated high readings to reduce false alarms
CONSECUTIVE_READINGS = 3

# Store the previous readings for each resource
_high_readings = {
    "cpu": 0,
    "memory": 0,
}


def get_resource_usage():
    """Return current system CPU and memory usage."""

    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent

    return {
        "cpu_percent": cpu_usage,
        "memory_percent": memory_usage,
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
    }


def check_resource_anomalies(usage):
    """Generate events for sustained high CPU or memory usage."""

    events = []

    checks = [
        (
            "cpu",
            usage["cpu_percent"],
            CPU_THRESHOLD,
            "high_cpu",
            "High CPU utilisation detected",
            15,
        ),
        (
            "memory",
            usage["memory_percent"],
            MEMORY_THRESHOLD,
            "high_memory",
            "High memory utilisation detected",
            10,
        ),
    ]

    for resource, value, threshold, event_type, description, score in checks:

        if value > threshold:
            _high_readings[resource] += 1
        else:
            _high_readings[resource] = 0

        if _high_readings[resource] == CONSECUTIVE_READINGS:
            events.append({
                "timestamp": usage["timestamp"],
                "module": "resource",
                "event_type": event_type,
                "description": description,
                "severity": "medium",
                "score": score,
                "value": value,
                "threshold": threshold,
            })

    return events


def monitor_resources(interval=2):
    """Continuously monitor CPU and memory usage."""

    print("Resource monitoring started.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            usage = get_resource_usage()
            events = check_resource_anomalies(usage)

            print(
                f"CPU: {usage['cpu_percent']:5.1f}% | "
                f"Memory: {usage['memory_percent']:5.1f}%"
            )

            for event in events:
                print(
                    f"ALERT: {event['description']} "
                    f"({event['value']:.1f}%)"
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nResource monitoring stopped.")


if __name__ == "__main__":
    monitor_resources()
