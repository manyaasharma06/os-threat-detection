import unittest
from unittest.mock import patch, MagicMock
import process_monitor


class TestProcessMonitor(unittest.TestCase):

    @patch("process_monitor.psutil.process_iter")
    def test_collect_processes_empty(self, mock_process_iter):
        mock_process_iter.return_value = []
        result = process_monitor.collect_processes()
        self.assertEqual(result, {})

    @patch("process_monitor.psutil.process_iter")
    def test_collect_processes_with_process(self, mock_process_iter):
        mock_process = MagicMock()
        mock_process.info = {
            "pid": 1234,
            "name": "sample_process",
            "cpu_percent": 15.0
        }
        mock_process_iter.return_value = [mock_process]

        result = process_monitor.collect_processes()

        self.assertIn(1234, result)
        self.assertEqual(result[1234]["name"], "sample_process")
        self.assertEqual(result[1234]["cpu"], 15.0)


if __name__ == "__main__":
    unittest.main()


