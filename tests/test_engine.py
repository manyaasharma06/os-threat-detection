import time
from core.event import Event
from core.engine import ThreatEngine
from core.scoring import severity_level


def make_engine():
    return ThreatEngine(":memory:")   # temporary database, not saved to disk


def test_severity_levels():
    assert severity_level(10) == "LOW"
    assert severity_level(30) == "MEDIUM"
    assert severity_level(60) == "HIGH"
    assert severity_level(95) == "CRITICAL"


def test_low_event_no_alert():
    eng = make_engine()
    score, level = eng.submit(Event("process", "NEW_PROCESS", pid=1))
    assert level == "LOW"
    assert eng.db.get_alerts() == []


def test_correlation_raises_score():
    eng = make_engine()
    eng.submit(Event("process", "HIGH_CPU_PROCESS", pid=42, value=90))
    score, _ = eng.submit(Event("filesystem", "MASS_FILE_CHANGE", pid=42))
    assert score > 55   # 35 base + 20 cross-source + 15 same-PID


def test_events_stored():
    eng = make_engine()
    eng.submit(Event("resource", "HIGH_SYSTEM_CPU", value=92))
    assert len(eng.db.get_events()) == 1


def test_old_events_expire():
    eng = make_engine()
    old = Event("process", "HIGH_CPU_PROCESS", pid=7, timestamp=time.time() - 500)
    eng.submit(old)
    score, _ = eng.submit(Event("filesystem", "MASS_FILE_CHANGE", pid=7))
    assert score == 35   # no bonus, because the old event expired