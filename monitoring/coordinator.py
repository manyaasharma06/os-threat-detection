"""Lifecycle coordinator for the three monitoring modules.

Monitor callbacks normalize and enqueue events quickly. A single dispatcher
thread submits them to the central engine, so a slow database write in one
callback does not stall the other monitors.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
from queue import Queue
import threading
import time
from typing import Callable

from core.adapters import from_filesystem_event, from_process_event, from_resource_event
from core.event import Event

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CoordinatorConfig:
    process_poll_interval_seconds: float = 2.0
    process_cpu_threshold_percent: float = 70.0
    process_high_cpu_duration_seconds: float = 10.0
    file_mass_change_threshold: int = 20
    file_time_window_seconds: float = 10.0
    file_ransomware_change_threshold: int = 8
    resource_interval_seconds: float = 1.0
    resource_sustained_samples: int = 3

    def __post_init__(self):
        if self.process_poll_interval_seconds <= 0:
            raise ValueError("process_poll_interval_seconds must be positive")
        if self.process_high_cpu_duration_seconds <= 0:
            raise ValueError("process_high_cpu_duration_seconds must be positive")
        if self.file_mass_change_threshold < 1 or self.file_ransomware_change_threshold < 1:
            raise ValueError("file change thresholds must be positive")
        if self.file_time_window_seconds <= 0 or self.resource_interval_seconds <= 0:
            raise ValueError("monitor intervals must be positive")
        if self.resource_sustained_samples < 1:
            raise ValueError("resource_sustained_samples must be at least 1")


class MonitoringCoordinator:
    """Start and stop the process, file-system, and resource monitors once."""

    def __init__(
        self,
        submit_event: Callable[[Event], object],
        filesystem_path: str | Path,
        config: CoordinatorConfig | None = None,
    ):
        if not callable(submit_event):
            raise TypeError("submit_event must be a callable such as ThreatEngine.submit")
        self.filesystem_path = Path(filesystem_path).expanduser().resolve()
        if not self.filesystem_path.exists() or not self.filesystem_path.is_dir():
            raise ValueError(f"File-system watch path must be an existing directory: {self.filesystem_path}")
        self.submit_event = submit_event
        self.config = config or CoordinatorConfig()
        self.stop_event = threading.Event()
        self.event_queue: Queue[Event | None] = Queue()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._lifecycle_lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._stopped = False

    def _enqueue(self, event: Event) -> None:
        if not isinstance(event, Event):
            raise TypeError(f"Expected core.event.Event, got {type(event).__name__}")
        self.event_queue.put(event)

    def _dispatch_events(self) -> None:
        while True:
            event = self.event_queue.get()
            try:
                if event is None:
                    return
                self.submit_event(event)
            except Exception:
                logger.exception("Central event handler failed for %s/%s", event.source, event.event_type)
            finally:
                self.event_queue.task_done()

    def _guarded_worker(self, name: str, worker: Callable[[], None]) -> None:
        try:
            worker()
        except Exception:
            # A module failure is visible in logs and does not stop sibling threads.
            logger.exception("%s monitor stopped after an error", name)

    def _run_process_monitor(self) -> None:
        # Import lazily so a missing process dependency doesn't prevent the
        # file-system and resource workers from starting.
        import process_monitor

        config = self.config
        for process in process_monitor.psutil.process_iter():
            try:
                process.cpu_percent(interval=None)
            except (process_monitor.psutil.NoSuchProcess, process_monitor.psutil.AccessDenied):
                continue

        # Establish a baseline so pre-existing processes are not mislabeled as
        # newly created when monitoring begins.
        previous = process_monitor.collect_processes()
        previous_pids = set(previous)
        high_cpu_since: dict[int, float] = {}
        high_cpu_reported: set[int] = set()

        while not self.stop_event.is_set():
            current = process_monitor.collect_processes()
            current_pids = set(current)
            now = time.monotonic()
            timestamp = datetime.now(timezone.utc).isoformat()

            for pid in current_pids - previous_pids:
                self._enqueue(from_process_event("NEW_PROCESS", {"pid": pid, **current[pid]}, timestamp))

            for pid, details in current.items():
                cpu = float(details.get("cpu", 0.0))
                if cpu >= config.process_cpu_threshold_percent:
                    high_cpu_since.setdefault(pid, now)
                    if (now - high_cpu_since[pid] >= config.process_high_cpu_duration_seconds
                            and pid not in high_cpu_reported):
                        self._enqueue(from_process_event("HIGH_CPU_PROCESS", {"pid": pid, **details}, timestamp))
                        high_cpu_reported.add(pid)
                else:
                    high_cpu_since.pop(pid, None)
                    high_cpu_reported.discard(pid)

            for pid in set(high_cpu_since) - current_pids:
                high_cpu_since.pop(pid, None)
                high_cpu_reported.discard(pid)

            previous_pids = current_pids
            self.stop_event.wait(config.process_poll_interval_seconds)

    def _run_filesystem_monitor(self) -> None:
        from filesystem_monitoring.file_monitor import FileSystemMonitor

        monitor = FileSystemMonitor(
            self.filesystem_path,
            mass_change_threshold=self.config.file_mass_change_threshold,
            time_window=self.config.file_time_window_seconds,
            ransomware_change_threshold=self.config.file_ransomware_change_threshold,
            callback=lambda raw: self._enqueue(from_filesystem_event(raw)),
        )
        try:
            monitor.start()
            while not self.stop_event.wait(0.25):
                pass
        finally:
            monitor.stop()

    def _run_resource_monitor(self) -> None:
        from resource_monitoring.resource_monitor import MonitorConfig, ResourceMonitor

        monitor = ResourceMonitor(
            MonitorConfig(
                interval_seconds=self.config.resource_interval_seconds,
                sustained_samples=self.config.resource_sustained_samples,
            ),
            callback=lambda raw: self._enqueue(from_resource_event(raw)),
        )
        monitor.run(self.stop_event)

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._started:
                raise RuntimeError("MonitoringCoordinator instances can only be started once")
            self._started = True
            workers = [
                ("event-dispatcher", self._dispatch_events),
                ("process", self._run_process_monitor),
                ("filesystem", self._run_filesystem_monitor),
                ("resource", self._run_resource_monitor),
            ]
            workers_to_start = [
                threading.Thread(
                    name=f"monitor-{name}",
                    target=self._guarded_worker,
                    args=(name, worker),
                )
                for name, worker in workers
            ]
            self._threads = []
            for thread in workers_to_start:
                thread.start()
                self._threads.append(thread)

    def stop(self) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
            self.stop_event.set()
            dispatcher = [thread for thread in self._threads if thread.name == "monitor-event-dispatcher"]
            monitors = [thread for thread in self._threads if thread not in dispatcher]
            for thread in monitors:
                if thread is not threading.current_thread():
                    thread.join()
            if dispatcher:
                # FIFO sentinel drains all events emitted before the monitor threads ended.
                self.event_queue.put(None)
                for thread in dispatcher:
                    if thread is not threading.current_thread():
                        thread.join()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self.stop_event.wait(0.5):
                pass
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            self.stop()
