"""Controlled tests for the resource monitor's sustained-threshold rule."""
import unittest
from unittest.mock import patch

from resource_monitor import MonitorConfig, ResourceMonitor


class ResourceMonitorTests(unittest.TestCase):
    def setUp(self):
        self.config = MonitorConfig(sustained_samples=2, system_cpu_threshold_percent=50,
                                    system_memory_threshold_percent=50,
                                    process_cpu_threshold_percent=50, process_memory_threshold_mb=100)
        self.monitor = ResourceMonitor(self.config)

    @patch.object(ResourceMonitor, "_processes", return_value=[])
    @patch.object(ResourceMonitor, "_system_memory", return_value=(20.0, 20, 100))
    @patch.object(ResourceMonitor, "_system_cpu", side_effect=[80.0, 80.0, 10.0])
    def test_sustained_system_cpu_alert_once_and_recovers(self, *_):
        _, first = self.monitor.sample_once()
        _, second = self.monitor.sample_once()
        _, third = self.monitor.sample_once()
        self.assertEqual(first, [])
        self.assertEqual([e.event_type for e in second], ["sustained_system_resource_spike"])
        self.assertEqual(third, [])

    @patch.object(ResourceMonitor, "_processes", side_effect=[
        [{"pid": 7, "name": "safe-worker", "cpu_percent": 70.0, "memory_bytes": 1024}],
        [{"pid": 7, "name": "safe-worker", "cpu_percent": 70.0, "memory_bytes": 1024}],
    ])
    @patch.object(ResourceMonitor, "_system_memory", return_value=(20.0, 20, 100))
    @patch.object(ResourceMonitor, "_system_cpu", return_value=10.0)
    def test_sustained_process_alert_includes_pid(self, *_):
        self.assertEqual(self.monitor.sample_once()[1], [])
        events = self.monitor.sample_once()[1]
        self.assertEqual(events[0].event_type, "sustained_process_resource_spike")
        self.assertEqual(events[0].details["pid"], 7)

    @patch("resource_monitor.time.monotonic", side_effect=[10.0, 11.0])
    def test_process_cpu_is_sample_delta_not_since_boot_average(self, _):
        identity = (123, 456)
        self.assertEqual(self.monitor._sample_process_cpu(identity, 4.0), 0.0)
        self.assertAlmostEqual(self.monitor._sample_process_cpu(identity, 4.8), 80.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
