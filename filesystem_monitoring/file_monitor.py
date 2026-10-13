
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

    def __init__(
        self,
        mass_change_threshold=20,
        time_window=10,
        callback=None,
        ransomware_change_threshold=8,
        suspicious_extension_threshold=2,
        suspicious_extensions=(".locked", ".encrypted", ".crypt", ".enc"),
    ):
        super().__init__()
        if mass_change_threshold < 1 or time_window <= 0:
            raise ValueError("mass_change_threshold and time_window must be positive")
        if ransomware_change_threshold < 1 or suspicious_extension_threshold < 1:
            raise ValueError("ransomware thresholds must be positive")
        self.mass_change_threshold = mass_change_threshold
        self.time_window = time_window
        self.ransomware_change_threshold = ransomware_change_threshold
        self.suspicious_extension_threshold = suspicious_extension_threshold
        self.suspicious_extensions = {ext.lower() for ext in suspicious_extensions}
        self.callback = callback
        self.recent_changes = deque()
        self.lock = Lock()
        self.reported_mass_change = False
        self.reported_ransomware_pattern = False

    def _record_event(self, event_type, path, destination=None):
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

        events = [event]
        with self.lock:
            self.recent_changes.append((now, event_type, str(path), str(destination) if destination else None))

            while (
                self.recent_changes
                and now - self.recent_changes[0][0] > self.time_window
            ):
                self.recent_changes.popleft()

            change_count = len(self.recent_changes)
            if change_count >= self.mass_change_threshold:
                if not self.reported_mass_change:
                    events.append({
                        **event,
                        "event_type": "MASS_FILE_CHANGE",
                        "severity": "HIGH",
                        "details": {
                            "changes_in_window": change_count,
                            "window_seconds": self.time_window,
                        },
                    })
                    self.reported_mass_change = True
            else:
                # Re-arm after the old burst has aged out of the time window.
                self.reported_mass_change = False

            suspicious_paths = sorted({
                destination or source
                for _, _, source, destination in self.recent_changes
                if Path(destination or source).suffix.lower() in self.suspicious_extensions
            })
            if (
                change_count >= self.ransomware_change_threshold
                and len(suspicious_paths) >= self.suspicious_extension_threshold
            ):
                if not self.reported_ransomware_pattern:
                    events.append({
                        **event,
                        "event_type": "RANSOMWARE_PATTERN",
                        "severity": "CRITICAL",
                        "details": {
                            "changes_in_window": change_count,
                            "window_seconds": self.time_window,
                            "suspicious_extension_count": len(suspicious_paths),
                            "suspicious_extensions": sorted({Path(p).suffix.lower() for p in suspicious_paths}),
                            "paths_sample": suspicious_paths[-10:],
                        },
                    })
                    self.reported_ransomware_pattern = True
            else:
                self.reported_ransomware_pattern = False

        for emitted in events:
            print(json.dumps(emitted, indent=2))
            if self.callback:
                self.callback(emitted)

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
        ignored_parts = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}
        ignored_suffixes = (".db", ".db-journal", ".db-wal", ".db-shm",
                            ".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm",
                            ".sqlite3", ".log")

        paths = [getattr(event, "src_path", "")]
        destination = getattr(event, "dest_path", None)

        if destination:
            paths.append(destination)

        for path in paths:
            if path:
                candidate = Path(path)
                parts = {part.casefold() for part in candidate.parts}
                if ignored_parts.intersection(parts) or candidate.name.casefold().endswith(ignored_suffixes):
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
        ransomware_change_threshold=8,
        suspicious_extension_threshold=2,
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
            ransomware_change_threshold=ransomware_change_threshold,
            suspicious_extension_threshold=suspicious_extension_threshold,
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
