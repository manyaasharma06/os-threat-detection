
# Process Security Module

## 1. Objective

The Process Security Module monitors running processes and detects unusual process activity to support operating system threat detection.

## 2. Responsibilities

- Collect process IDs (PIDs), process names, and CPU usage.
- Detect newly created processes after monitoring starts.
- Detect sustained high CPU consumption.
- Generate alerts when process activity matches configured anomaly rules.
- Test process collection using harmless sample data.

## 3. Technologies Used

- Python 3
- psutil
- unittest
- GitHub

## 4. Detection Rules

| Rule | Description | Initial Threshold |
|---|---|---|
| New Process | Reports a PID that appears after monitoring begins | Checked every 2 seconds |
| High CPU | Flags a process with sustained high CPU consumption | 70% CPU for at least 10 seconds |
| Process Access | Skips processes that disappear or cannot be accessed | Exception handling |

Thresholds can be adjusted in `process_monitor.py`.

## 5. Files

- `process_monitor.py` - Main process monitoring implementation.
- `test_process_monitor.py` - Unit tests for process collection.
- `requirements.txt` - External Python dependencies.

## 6. Testing Plan

| Test | Expected Result | Status |
|---|---|---|
| Empty process list | Returns an empty dictionary | Test written; execution pending |
| Sample process | Captures PID, name, and CPU value | Test written; execution pending |
| New process | Reports a newly observed PID | Manual test pending |
| Sustained high CPU | Reports a process exceeding the threshold for the configured duration | Manual test pending |

## 7. Limitations

- A process already running when monitoring starts is not reported as new.
- Some process details may be unavailable because of operating system permissions.
- CPU measurements require sampling time and may initially be zero.
- The module currently prints alerts to the console; integration with the central threat detection module is a separate task.

## 8. Future Integration

The module can be connected to the central detection module by sending process events in the shared event format agreed upon by the project team.

## 9. Conclusion

This module provides process monitoring and basic anomaly detection for the operating system threat detection project. Final validation requires executing the tests and checking the results on the target system.
