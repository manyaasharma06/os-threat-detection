
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileMovedEvent

from filesystem_monitoring.file_monitor import FileMonitorHandler


class TestFileMonitorHandler(unittest.TestCase):

    def setUp(self):
        self.callback = Mock()
        self.handler = FileMonitorHandler(
            mass_change_threshold=3,
            time_window=10,
            callback=self.callback,
        )

    def test_created_event(self):
        self.handler.on_created(FileCreatedEvent("/tmp/example.txt"))

        event = self.callback.call_args.args[0]
        self.assertEqual(event["event_type"], "FILE_CREATED")
        self.assertEqual(event["source"], "filesystem_monitor")

    def test_deleted_event(self):
        self.handler.on_deleted(FileDeletedEvent("/tmp/example.txt"))

        event = self.callback.call_args.args[0]
        self.assertEqual(event["event_type"], "FILE_DELETED")

    def test_moved_event(self):
        self.handler.on_moved(
            FileMovedEvent("/tmp/old.txt", "/tmp/new.txt")
        )

        event = self.callback.call_args.args[0]
        self.assertEqual(event["event_type"], "FILE_MOVED")
        self.assertEqual(event["destination"], "/tmp/new.txt")

    def test_mass_change_alert(self):
        self.handler.on_created(FileCreatedEvent("/tmp/one.txt"))
        self.handler.on_deleted(FileDeletedEvent("/tmp/two.txt"))
        self.handler.on_created(FileCreatedEvent("/tmp/three.txt"))

        events = [
            call.args[0] for call in self.callback.call_args_list
        ]
        self.assertEqual(events[-1]["event_type"], "MASS_FILE_CHANGE")
        self.assertEqual(events[-1]["severity"], "HIGH")

    def test_ransomware_pattern_uses_configured_extensions_and_window(self):
        self.handler = FileMonitorHandler(
            mass_change_threshold=100,
            ransomware_change_threshold=3,
            suspicious_extension_threshold=2,
            time_window=10,
            callback=self.callback,
        )
        self.handler.on_created(FileCreatedEvent("/tmp/a.locked"))
        self.handler.on_created(FileCreatedEvent("/tmp/b.encrypted"))
        self.handler.on_modified(FileCreatedEvent("/tmp/c.txt"))
        event = self.callback.call_args_list[-1].args[0]
        self.assertEqual(event["event_type"], "RANSOMWARE_PATTERN")
        self.assertEqual(event["severity"], "CRITICAL")
        self.assertEqual(event["details"]["suspicious_extension_count"], 2)

    @patch("filesystem_monitoring.file_monitor.time.time",
           side_effect=[0.0, 0.1, 0.2, 2.0, 2.1, 2.2])
    def test_mass_change_alert_rearms_after_window_expires(self, _):
        self.handler = FileMonitorHandler(
            mass_change_threshold=3,
            time_window=1,
            callback=self.callback,
        )
        for index in range(6):
            self.handler.on_created(FileCreatedEvent(f"/tmp/{index}.txt"))
        alerts = [call.args[0] for call in self.callback.call_args_list
                  if call.args[0]["event_type"] == "MASS_FILE_CHANGE"]
        self.assertEqual(len(alerts), 2)


if __name__ == "__main__":
    unittest.main()
