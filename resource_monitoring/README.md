# Resource Monitoring Module (Person 3)

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

Linux reads `/proc`; Windows reads system/process counters through Win32 APIs; macOS uses `vm_stat` and `ps`. Per-process CPU is calculated from the change in accumulated CPU time between samples, with the first sample serving as a baseline and reporting 0%. A process at 100% uses about one logical CPU core; multi-threaded processes can exceed 100%. Permission changes and short-lived processes may affect per-process coverage. Windows and Linux system CPU use counter deltas; unsupported system CPU counters are reported as `null` rather than fabricated.

## Harmless tests

```powershell
python -m unittest -v
```

Unit tests mock controlled readings and verify sustained alerts, recovery behavior, PID details, and sample-delta CPU calculations without changing system settings. To exercise a real, bounded CPU and memory workload:

```powershell
python resource_monitoring/simulate_workload.py --seconds 8 --memory-mb 32
```

The simulator allocates and touches the requested memory and runs a CPU loop in the current process. It uses low thresholds for this controlled sample and fails if a sustained process alert is not observed.
