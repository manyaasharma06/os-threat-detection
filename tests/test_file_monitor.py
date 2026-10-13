
import unittest
from unittest.mock import Mock

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


if __name__ == "__main__":
    unittest.main()
