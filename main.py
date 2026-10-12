import threading
import time

from core.engine import ThreatEngine
from core.adapters import from_resource_event
from resource_monitoring.resource_monitor import ResourceMonitor, MonitorConfig


def main():
    engine = ThreatEngine("threats.db")
    stop = threading.Event()

    # Person 3: resource monitor
    def on_resource_event(sec_event):
        engine.submit(from_resource_event(sec_event))

    resource = ResourceMonitor(MonitorConfig(), callback=on_resource_event)
    threads = [threading.Thread(target=resource.run, args=(stop,), daemon=True)]

    # TODO: add Person 1 (process monitor) here
    # TODO: add Person 2 (file-system monitor) here

    for t in threads:
        t.start()

    print("Threat detection running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        print("Stopped.")


if __name__ == "__main__":
    main()