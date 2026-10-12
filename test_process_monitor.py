import unittest
from unittest.mock import patch
import process_monitor


class TestProcessMonitor(unittest.TestCase):

    @patch("process_monitor.psutil.process_iter")
    def test_collect_processes(self, mock_process_iter):
        mock_process_iter.return_value = []
        result = process_monitor.collect_processes()
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()

