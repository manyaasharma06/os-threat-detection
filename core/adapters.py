from core.event import Event
from datetime import datetime
import time


def _event_timestamp(value):
    """Convert monitor ISO-8601 timestamps to the engine's Unix-seconds field."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def from_process_event(event_type, process, timestamp=None):
    """Normalize a Person 1 process sample/alert into Person 4's Event."""
    pid = process.get("pid")
    name = process.get("name") or "Unknown"
    cpu = process.get("cpu", process.get("cpu_percent"))
    normalized_type = event_type.upper()
    if normalized_type not in {"NEW_PROCESS", "HIGH_CPU_PROCESS", "SUSPICIOUS_PROCESS_NAME"}:
        raise ValueError(f"Unsupported process event type: {event_type}")
    if normalized_type == "NEW_PROCESS":
        description = f"New process {name} (PID {pid})"
    else:
        description = f"{name} (PID {pid}) using {float(cpu or 0):.1f}% CPU"
    return Event(
        source="process",
        event_type=normalized_type,
        description=description,
        pid=pid,
        process_name=name,
        value=float(cpu) if cpu is not None else None,
        details=dict(process),
        timestamp=_event_timestamp(timestamp),
    )


def from_filesystem_event(event):
    """Normalize Person 2's callback dictionary into Person 4's Event."""
    details = dict(event.get("details") or {})
    for key in ("path", "destination"):
        if event.get(key) is not None:
            details[key] = event[key]
    original_type = event.get("event_type", "UNKNOWN")
    event_type = {"FILE_MOVED": "FILE_RENAMED"}.get(original_type, original_type).upper()
    if event_type not in {
        "FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED", "FILE_RENAMED",
        "MASS_FILE_CHANGE", "RANSOMWARE_PATTERN",
    }:
        raise ValueError(f"Unsupported file-system event type: {original_type}")
    path = details.get("path", "unknown path")
    destination = details.get("destination")
    description = f"{event_type}: {path}"
    if destination:
        description += f" -> {destination}"
    value = details.get("changes_in_window")
    return Event(
        source="filesystem",
        event_type=event_type,
        description=description,
        value=float(value) if value is not None else None,
        details=details,
        timestamp=_event_timestamp(event.get("timestamp")),
    )


def from_resource_event(sec):
    """Convert Person 3's SecurityEvent into our shared Event."""
    d = sec.details

    if sec.event_type == "sustained_system_resource_spike":
        metric = d.get("metric")
        event_type = "HIGH_SYSTEM_CPU" if metric == "system_cpu" else "HIGH_SYSTEM_MEMORY"
        return Event(
            source="resource",
            event_type=event_type,
            description=f"{metric} at {d.get('value_percent')}% "
                        f"for {d.get('consecutive_samples')} samples",
            value=d.get("value_percent"),
            details=d,
            timestamp=_event_timestamp(getattr(sec, "timestamp", None)),
        )

    if sec.event_type == "sustained_process_resource_spike":
        return Event(
            source="resource",
            event_type="HIGH_PROCESS_RESOURCE",
            description=f"{d.get('name')} (PID {d.get('pid')}) using "
                        f"{d.get('cpu_percent'):.1f}% CPU, {d.get('memory_mb')} MB",
            pid=d.get("pid"),
            process_name=d.get("name"),
            value=d.get("cpu_percent"),
            details=d,
            timestamp=_event_timestamp(getattr(sec, "timestamp", None)),
        )

    # unknown type: pass it through with the default score
    return Event(source="resource", event_type=sec.event_type.upper(),
                 description=sec.event_type, details=d,
                 timestamp=_event_timestamp(getattr(sec, "timestamp", None)))
