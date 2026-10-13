import tempfile
import unittest
from pathlib import Path

from core.event import Event
from monitoring.coordinator import MonitoringCoordinator


class FakeCoordinator(MonitoringCoordinator):
    def _run_process_monitor(self):
        self._enqueue(Event(source="process", event_type="NEW_PROCESS", pid=1))

    def _run_filesystem_monitor(self):
        self._enqueue(Event(source="filesystem", event_type="FILE_CREATED"))

    def _run_resource_monitor(self):
        self._enqueue(Event(source="resource", event_type="HIGH_SYSTEM_CPU"))


class OneWorkerFailsCoordinator(FakeCoordinator):
    def _run_process_monitor(self):
        raise RuntimeError("simulated process-monitor startup failure")


class CoordinatorTests(unittest.TestCase):
    def test_dispatches_all_modules_and_stops_cleanly(self):
        submitted = []
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            coordinator = FakeCoordinator(submitted.append, Path(tmp))
            coordinator.start()
            coordinator.stop()
            self.assertCountEqual(
                [event.source for event in submitted],
                ["process", "filesystem", "resource"],
            )
            self.assertTrue(all(not thread.is_alive() for thread in coordinator._threads))

    def test_start_cannot_create_duplicate_monitor_threads(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            coordinator = FakeCoordinator(lambda event: None, Path(tmp))
            coordinator.start()
            try:
                with self.assertRaises(RuntimeError):
                    coordinator.start()
            finally:
                coordinator.stop()

    def test_one_monitor_failure_does_not_stop_sibling_monitors(self):
        submitted = []
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            coordinator = OneWorkerFailsCoordinator(submitted.append, Path(tmp))
            coordinator.start()
            coordinator.stop()
        self.assertCountEqual([event.source for event in submitted], ["filesystem", "resource"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
