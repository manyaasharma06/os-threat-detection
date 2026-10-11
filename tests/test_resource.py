
import unittest

from modules.resource_monitor import (
    check_resource_anomalies,
    _high_readings,
)


class TestResourceMonitor(unittest.TestCase):

    def setUp(self):
        _high_readings["cpu"] = 0
        _high_readings["memory"] = 0

    def make_usage(self, cpu, memory):
        return {
            "cpu_percent": cpu,
            "memory_percent": memory,
            "timestamp": "2026-10-11T12:00:00",
        }

    def test_normal_usage_creates_no_alert(self):
        usage = self.make_usage(30, 50)

        events = check_resource_anomalies(usage)

        self.assertEqual(events, [])

    def test_cpu_alert_after_three_high_readings(self):
        usage = self.make_usage(95, 50)

        self.assertEqual(check_resource_anomalies(usage), [])
        self.assertEqual(check_resource_anomalies(usage), [])

        events = check_resource_anomalies(usage)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "high_cpu")
        self.assertEqual(events[0]["module"], "resource")

    def test_memory_alert_after_three_high_readings(self):
        usage = self.make_usage(30, 95)

        self.assertEqual(check_resource_anomalies(usage), [])
        self.assertEqual(check_resource_anomalies(usage), [])

        events = check_resource_anomalies(usage)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "high_memory")

    def test_reading_below_threshold_resets_counter(self):
        check_resource_anomalies(self.make_usage(95, 50))
        check_resource_anomalies(self.make_usage(95, 50))

        events = check_resource_anomalies(
            self.make_usage(30, 50)
        )

        self.assertEqual(events, [])
        self.assertEqual(_high_readings["cpu"], 0)


if __name__ == "__main__":
    unittest.main()
