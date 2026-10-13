# File-System Monitoring Module (Person 2)

Uses Watchdog to monitor a selected directory for file creation, modification, deletion, and move/rename events. The coordinator should watch a dedicated test or data folder, not the whole project tree.

## Rules

| Event | Trigger | Shared event name |
|---|---|---|
| File activity | A file is created, modified, deleted, or moved | `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_RENAMED` |
| Mass change | At least 20 changes in 10 seconds by default | `MASS_FILE_CHANGE` |
| Ransomware-like pattern | At least 8 changes in the window, including at least 2 paths ending in `.locked`, `.encrypted`, `.crypt`, or `.enc` | `RANSOMWARE_PATTERN` |

Thresholds are configurable on `FileSystemMonitor` / `FileMonitorHandler`. One mass-change and one ransomware-pattern alert are emitted per active burst; alerts re-arm when the activity ages out of the configured time window. The heuristic indicates a pattern and is not a malware verdict.

The handler skips `.git`, virtual environments (`.venv`, `venv`), `__pycache__`, `.pytest_cache`, and database/log files to prevent self-generated event floods when monitoring a project folder.

## Test

```powershell
python -m unittest -v tests.test_file_monitor
```

Tests use Watchdog's harmless synthetic event classes and temporary sample paths; no real files are changed.
