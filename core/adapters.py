
from core.event import Event


def from_resource_event(sec):
    """Convert Person 3's SecurityEvent into our shared Event."""
    d = sec.details

    if sec.event_type == "sustained_system_resource_spike":
        metric = d.get("metric")
        event_type = (
            "HIGH_SYSTEM_CPU"
            if metric == "system_cpu"
            else "HIGH_SYSTEM_MEMORY"
        )
        return Event(
            source="resource",
            event_type=event_type,
            description=(
                f"{metric} at {d.get('value_percent')}% "
                f"for {d.get('consecutive_samples')} samples"
            ),
            value=d.get("value_percent"),
            details=d,
        )

    if sec.event_type == "sustained_process_resource_spike":
        cpu = d.get("cpu_percent") or 0
        return Event(
            source="resource",
            event_type="HIGH_PROCESS_RESOURCE",
            description=(
                f"{d.get('name')} (PID {d.get('pid')}) using "
                f"{cpu:.1f}% CPU, {d.get('memory_mb')} MB"
            ),
            pid=d.get("pid"),
            process_name=d.get("name"),
            value=cpu,
            details=d,
        )

    return Event(
        source="resource",
        event_type=sec.event_type.upper(),
        description=sec.event_type,
        details=d,
    )


def from_filesystem_event(data):
    """Convert a file-monitor dictionary into the shared Event format."""
    event_type = data.get("event_type", "UNKNOWN")

    # The threat engine's scoring table uses FILE_RENAMED.
    if event_type == "FILE_MOVED":
        event_type = "FILE_RENAMED"

    details = dict(data.get("details") or {})

    for key in ("path", "destination"):
        if data.get(key):
            details[key] = data[key]

    path = data.get("path", "")
    destination = data.get("destination")
    description = f"{event_type}: {path}"

    if destination:
        description += f" -> {destination}"

    return Event(
        source="filesystem",
        event_type=event_type,
        description=description,
        value=details.get("changes_in_window"),
        details=details,
    )

def from_process_event(data):
    """Convert a process-monitor dictionary into the shared Event format."""
    event_type = data.get("event_type", "UNKNOWN")

    pid = data.get("pid")
    process_name = data.get("process_name", "Unknown")
    details = dict(data.get("details") or {})

    return Event(
        source="process",
        event_type=event_type,
        description=data.get("description", f"{event_type}: {process_name}"),
        pid=pid,
        process_name=process_name,
        value=data.get("value"),
        details=details,
    )