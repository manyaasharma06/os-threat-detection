# Resource Monitoring Module - Ishani Nair

Samples system-wide CPU and memory utilisation and tracks per-process PID, name, CPU estimate, and memory use. It emits threshold alerts in a shared JSON-compatible event envelope for central correlation/storage.

## Run

Requires Python 3.10+; standard library only.

```powershell
python resource_monitor.py --interval 1 --samples 3
```

Each output line contains a `sample` (system metrics and process list) and zero or more `events`. Configure thresholds through `MonitorConfig` when importing the module. The default sustained threshold is 3 consecutive samples; defaults are system CPU 85%, system memory 90%, process CPU 80%, and process memory 1024 MB.

## Detection rules

- `sustained_system_resource_spike`: system CPU or memory is at or above its threshold for the configured consecutive sample count.
- `sustained_process_resource_spike`: an individual process exceeds its CPU or memory threshold for the configured consecutive sample count. Event details include PID, name, measurements, thresholds, and sample count.

Alerts fire once when a metric reaches the sustained count and re-arm after it falls below threshold. Events use `event_id`, UTC `timestamp`, `source`, `event_type`, `severity`, `confidence`, and `details` fields. Samples contain system and process measurements.

## Platform notes

Linux reads `/proc`; Windows reads system/process counters through Win32 APIs; macOS uses `vm_stat` and `ps`. Linux per-process CPU is an approximate percentage of total machine CPU based on accumulated process ticks since start, and the Windows process CPU field is currently reported as 0 (memory monitoring works there). Permission changes and short-lived processes may affect per-process coverage. CPU sampling compares two system counter readings; the first sample may not include a CPU percentage.

## Harmless tests

```powershell
python -m unittest -v
```

Tests mock controlled system/process readings and verify sustained alerts, recovery behavior, and PID details without creating load or changing system settings.
