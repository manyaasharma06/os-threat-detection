import threading
import time
from pathlib import Path

from core.engine import ThreatEngine
from core.adapters import (
    from_resource_event,
    from_filesystem_event,
    from_process_event,
)
from resource_monitoring.resource_monitor import ResourceMonitor, MonitorConfig
from filesystem_monitoring.file_monitor import FileSystemMonitor
from process_monitor import monitor_processes


def main():
    project_dir = Path(__file__).resolve().parent
    db_path = project_dir / "threats.db"
    test_dir = project_dir / "monitor_test_files"

    test_dir.mkdir(exist_ok=True)

    engine = ThreatEngine(str(db_path))
    stop = threading.Event()

    # Person 3: resource monitoring
    def on_resource_event(sec_event):
        engine.submit(from_resource_event(sec_event))

    resource = ResourceMonitor(
        MonitorConfig(),
        callback=on_resource_event,
    )

    # Person 2: filesystem monitoring
    def on_filesystem_event(data):
        score, level = engine.submit(from_filesystem_event(data))
        print(f"[FILESYSTEM] Threat score={score}, severity={level}")

    filesystem = FileSystemMonitor(
        watch_path=str(test_dir),
        recursive=True,
        callback=on_filesystem_event,
    )

    # Person 1: process monitoring
    def on_process_event(data):
        score, level = engine.submit(from_process_event(data))
        print(f"[PROCESS] Threat score={score}, severity={level}")

    threads = [
        threading.Thread(
            target=resource.run,
            args=(stop,),
            daemon=True,
        ),
        threading.Thread(
            target=monitor_processes,
            kwargs={
                "stop_event": stop,
                "callback": on_process_event,
            },
            daemon=True,
        ),
    ]

    filesystem.start()

    for thread in threads:
        thread.start()

    print("\nThreat detection running.")
    print("Process and resource monitors are active.")
    print(f"Filesystem monitoring: {test_dir}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitors...")
        stop.set()
    finally:
        filesystem.stop()

        for thread in threads:
            thread.join(timeout=3)

        engine.db.close()
        print("Threat detection stopped.")


if __name__ == "__main__":
    main()
