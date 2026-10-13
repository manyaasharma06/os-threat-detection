
import threading
import time
from pathlib import Path

from core.engine import ThreatEngine
from core.adapters import from_resource_event, from_filesystem_event
from resource_monitoring.resource_monitor import ResourceMonitor, MonitorConfig
from filesystem_monitoring.file_monitor import FileSystemMonitor


def main():
    project_dir = Path(__file__).resolve().parent
    db_path = project_dir / "threats.db"

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
        watch_path=str(project_dir / "monitor_test_files"),
        recursive=True,
        callback=on_filesystem_event,
    )

    # Start the monitors
    threads = [
        threading.Thread(
            target=resource.run,
            args=(stop,),
            daemon=True,
        )
    ]

    filesystem.start()

    for thread in threads:
        thread.start()

    print("Threat detection running.")
    print("Create, edit, or delete files inside monitor_test_files/ to test.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        print("Stopping monitors...")
    finally:
        filesystem.stop()
        for thread in threads:
            thread.join(timeout=2)
        engine.db.close()
        print("Threat detection stopped.")
        
if __name__ == "__main__":
    main()
