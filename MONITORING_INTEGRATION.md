# Monitoring Integration Handoff (Draft)

This branch combines the Person 1 process monitor, Person 2 file-system monitor, Person 3 resource monitor, and Person 4's documented central event interface. The central engine and SQLite implementation from `person4-core` are included unchanged.

## Run

Install Python 3.10+ and dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create or choose a dedicated test folder, then start the integrated monitor:

```powershell
python main.py --watch-path "C:\monitoring-test" --db threats.db
```

Stop with Ctrl+C. All monitor callbacks normalize into `core.event.Event`, enter one thread-safe queue, and are submitted to `ThreatEngine.submit`. The queue dispatcher keeps SQLite work out of the monitor callback threads. A module failure is logged without preventing sibling monitor threads from starting. Shutdown waits for monitors to finish and drains queued events.

## Shared Event Interface

The `Event` class in `core/event.py` is the canonical contract: `source`, `event_type`, `description`, `pid`, `process_name`, `value`, `details`, and Unix-seconds `timestamp`. Adapters convert monitor ISO timestamps to the engine's numeric timestamp field.

| Module | Shared event types | Key fields |
|---|---|---|
| Process | `NEW_PROCESS`, `HIGH_CPU_PROCESS` | PID, process name, CPU percentage |
| File system | `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_RENAMED`, `MASS_FILE_CHANGE`, `RANSOMWARE_PATTERN` | Path, destination for rename, change count/window |
| Resource | `HIGH_SYSTEM_CPU`, `HIGH_SYSTEM_MEMORY`, `HIGH_PROCESS_RESOURCE` | CPU/memory measurement, thresholds, PID/name where applicable |

The process integration uses Person 1's existing `collect_processes()` function and preserves its defaults: 70% CPU for 10 seconds, sampled every 2 seconds. It emits one high-CPU event per continuous high-CPU period and re-arms after recovery. Existing processes are baselined at startup rather than mislabeled as newly created.

## Tests and Harmless Workloads

Run all automated tests:

```powershell
python -m pytest -q
```

Person 3's controlled high-resource workload:

```powershell
python resource_monitoring/simulate_workload.py --seconds 8 --memory-mb 32
```

The file-system tests use synthetic Watchdog events. For a live check, use only the dedicated `--watch-path` folder and create/delete sample files there. The watcher excludes `.git`, virtual environments, Python caches, SQLite databases, and log files.

## Known Limits / Review Notes

- The coordinator uses Person 1's current process collector; it reports process creation and sustained high CPU but does not implement a suspicious-process-name list.
- The file ransomware heuristic uses configured suspicious extensions plus change count; it can produce false positives and is not a definitive verdict.
- Linux and Windows process CPU values are sample-to-sample percentages; the first sample for each process is the baseline. macOS process CPU comes from `ps` and system CPU is unavailable in the current system-counter implementation.
- Access restrictions can hide process details. Polling can miss processes that start and exit between process samples.
- Person 2's source branch contains an unrelated root path with a carriage return that Windows Git cannot check out. This integration branch copies the module files explicitly and omits that path.

## Verification Status

Person 3's original two unit tests passed before integration. Final combined test results and the live workload result must be recorded after running the commands above in an environment with `psutil`, `watchdog`, and `pytest` installed. This document remains a draft until Person 4 and Person B review the event mappings and integration base.
