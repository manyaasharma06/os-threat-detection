from resource_monitoring.resource_monitor import SecurityEvent
from core.adapters import from_resource_event


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