BASE_SCORES = {
    # process module
    "NEW_PROCESS": 5,
    "SUSPICIOUS_PROCESS_NAME": 30,
    "HIGH_CPU_PROCESS": 20,
    # filesystem module
    "FILE_CREATED": 2,
    "FILE_MODIFIED": 2,
    "FILE_DELETED": 4,
    "FILE_RENAMED": 4,
    "MASS_FILE_CHANGE": 35,
    "RANSOMWARE_PATTERN": 60,
    # resource module
    "HIGH_SYSTEM_CPU": 15,
    "HIGH_SYSTEM_MEMORY": 15,
    "HIGH_PROCESS_RESOURCE": 20,
}


def base_score(event):
    score = BASE_SCORES.get(event.event_type, 5)
    # extra points if CPU/memory value is extreme
    if event.source in ("process", "resource") and event.value is not None:
        if event.value >= 95:
            score += 10
        elif event.value >= 85:
            score += 5
    return score


def severity_level(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"