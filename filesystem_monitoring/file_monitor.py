
import json
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class FileMonitorHandler(FileSystemEventHandler):
    """Detect file-system events and flag unusually frequent changes."""

    def __init__(self, mass_change_threshold=20, time_window=10, callback=None):
        super().__init__()
        self.mass_change_threshold = mass_change_threshold
        self.time_window = time_window
        self.callback = callback
        self.recent_changes = deque()
        self.lock = Lock()
        self.reported_mass_change = False

    def _record_event(self, event_type, path, destination=None):
        if getattr(self, "_ignore_next", False):
            return

        now = time.time()

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "filesystem_monitor",
            "event_type": event_type,
            "severity": "INFO",
            "path": str(path),
        }

        if destination:
            event["destination"] = str(destination)

        with self.lock:
            self.recent_changes.append(now)

            while (
                self.recent_changes
                and now - self.recent_changes[0] > self.time_window
            ):
                self.recent_changes.popleft()

            if len(self.recent_changes) >= self.mass_change_threshold:
                event["event_type"] = "MASS_FILE_CHANGE"
                event["severity"] = "HIGH"
                event["details"] = {
                    "changes_in_window": len(self.recent_changes),
                    "window_seconds": self.time_window,
                }

                if self.reported_mass_change:
                    should_report = False
                else:
                    self.reported_mass_change = True
                    should_report = True
            else:
                should_report = True

        if should_report:
            print(json.dumps(event, indent=2))

            if self.callback:
                self.callback(event)

    def on_created(self, event):
        if not event.is_directory:
            self._record_event("FILE_CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record_event("FILE_MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record_event("FILE_DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record_event(
                "FILE_MOVED",
                event.src_path,
                destination=event.dest_path,
            )
    
    def dispatch(self, event):
        """Ignore Git and virtual-environment internals."""
        ignored_parts = {".git", ".venv", "venv", "__pycache__"}

        paths = [getattr(event, "src_path", "")]
        destination = getattr(event, "dest_path", None)

        if destination:
            paths.append(destination)

        for path in paths:
            if path and ignored_parts.intersection(Path(path).parts):
                return

        super().dispatch(event)



class FileSystemMonitor:
    """Start and stop monitoring a directory."""

    def __init__(
        self,
        watch_path,
        recursive=True,
        mass_change_threshold=20,
        time_window=10,
        callback=None,
    ):
        self.watch_path = Path(watch_path).expanduser().resolve()

        if not self.watch_path.exists():
            raise FileNotFoundError(
                f"Monitoring path does not exist: {self.watch_path}"
            )

        if not self.watch_path.is_dir():
            raise NotADirectoryError(
                f"Monitoring path is not a directory: {self.watch_path}"
            )

        self.handler = FileMonitorHandler(
            mass_change_threshold=mass_change_threshold,
            time_window=time_window,
            callback=callback,
        )
        self.observer = Observer()
        self.recursive = recursive

    def start(self):
        self.observer.schedule(
            self.handler,
            str(self.watch_path),
            recursive=self.recursive,
        )
        self.observer.start()
        print(f"Monitoring directory: {self.watch_path}")

    def stop(self):
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        print("File-system monitoring stopped.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Monitor file-system activity."
    )
    parser.add_argument("path", help="Directory to monitor")
    parser.add_argument(
        "--threshold", type=int, default=20,
        help="Number of changes that trigger an alert",
    )
    parser.add_argument(
        "--window", type=int, default=10,
        help="Time window in seconds for change detection",
    )
    args = parser.parse_args()

    monitor = FileSystemMonitor(
        args.path,
        mass_change_threshold=args.threshold,
        time_window=args.window,
    )

    try:
        monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
