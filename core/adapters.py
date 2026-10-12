from core.event import Event


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
        )

    # unknown type: pass it through with the default score
    return Event(source="resource", event_type=sec.event_type.upper(),
                 description=sec.event_type, details=d)