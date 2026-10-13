from resource_monitoring.resource_monitor import SecurityEvent
from core.adapters import from_resource_event
from core.adapters import from_filesystem_event, from_process_event


def make(event_type, details):
    return SecurityEvent("id1", "2026-01-01T00:00:00", "resource_monitor",
                         event_type, "high", 0.85, details)


def test_system_cpu_mapping():
    e = from_resource_event(make("sustained_system_resource_spike",
        {"metric": "system_cpu", "value_percent": 90.0, "consecutive_samples": 3}))
    assert e.event_type == "HIGH_SYSTEM_CPU"
    assert e.source == "resource"
    assert e.value == 90.0


def test_system_memory_mapping():
    e = from_resource_event(make("sustained_system_resource_spike",
        {"metric": "system_memory", "value_percent": 95.0, "consecutive_samples": 3}))
    assert e.event_type == "HIGH_SYSTEM_MEMORY"


def test_process_mapping_keeps_pid():
    e = from_resource_event(make("sustained_process_resource_spike",
        {"pid": 7, "name": "worker", "cpu_percent": 70.0, "memory_mb": 50.0}))
    assert e.event_type == "HIGH_PROCESS_RESOURCE"
    assert e.pid == 7
    assert e.process_name == "worker"


def test_process_event_mapping_keeps_pid_cpu_and_timestamp():
    e = from_process_event("HIGH_CPU_PROCESS",
        {"pid": 1234, "name": "worker.exe", "cpu": 88.5},
        "2026-10-13T10:30:00+00:00")
    assert e.source == "process"
    assert e.event_type == "HIGH_CPU_PROCESS"
    assert e.pid == 1234
    assert e.process_name == "worker.exe"
    assert e.value == 88.5
    assert e.timestamp == 1791887400.0


def test_filesystem_move_maps_to_shared_rename_event():
    e = from_filesystem_event({
        "timestamp": "2026-10-13T10:30:00+00:00",
        "event_type": "FILE_MOVED",
        "source": "filesystem_monitor",
        "path": "old.txt",
        "destination": "new.txt",
    })
    assert e.source == "filesystem"
    assert e.event_type == "FILE_RENAMED"
    assert e.details == {"path": "old.txt", "destination": "new.txt"}
    assert e.timestamp == 1791887400.0


def test_filesystem_mass_change_keeps_count():
    e = from_filesystem_event({
        "timestamp": "2026-10-13T10:30:00+00:00",
        "event_type": "MASS_FILE_CHANGE",
        "path": "sample.dat",
        "details": {"changes_in_window": 25, "window_seconds": 10},
    })
    assert e.event_type == "MASS_FILE_CHANGE"
    assert e.value == 25.0
