# Person 4: Central Threat Detection and Response Module

## 1. Overview

This module receives events from the three monitoring modules (Process, File-System, Resource), scores each event, correlates events across modules, stores everything in SQLite, and raises threat alerts.

Flow:

```
Monitors -> engine.submit(event) -> store event -> score + correlate -> severity -> alert (if score >= 30) -> store alert
```

Files:

| File | Purpose |
|---|---|
| `core/event.py` | Shared event format |
| `core/scoring.py` | Base scores and severity levels |
| `core/correlator.py` | Cross-module correlation |
| `core/database.py` | SQLite storage |
| `core/engine.py` | Connects everything; entry point for monitors |
| `tests/test_engine.py` | Automated tests |
| `simulate.py` | Demo that simulates an attack |

## 2. Shared Event Format

Every module creates an `Event` and passes it to `engine.submit(event)`.

| Field | Type | Meaning |
|---|---|---|
| source | str | `"process"`, `"filesystem"` or `"resource"` |
| event_type | str | What was detected (see table below) |
| description | str | Human-readable text |
| pid | int or None | Process ID involved, if known |
| process_name | str or None | Process name, if known |
| value | float or None | Measured value (CPU %, memory %, etc.) |
| details | dict | Any extra data |
| timestamp | float | Time of the event (set automatically) |

Usage example:

```python
from core.event import Event
from core.engine import ThreatEngine

engine = ThreatEngine()
engine.submit(Event(source="process", event_type="HIGH_CPU_PROCESS",
                    description="chrome at 91% CPU", pid=1234,
                    process_name="chrome.exe", value=91))
```

### Event types

| Module | event_type values |
|---|---|
| Process | NEW_PROCESS, HIGH_CPU_PROCESS, SUSPICIOUS_PROCESS_NAME |
| File-system | FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_RENAMED, MASS_FILE_CHANGE, RANSOMWARE_PATTERN |
| Resource | HIGH_SYSTEM_CPU, HIGH_SYSTEM_MEMORY, HIGH_PROCESS_RESOURCE |

Unknown event types receive a default base score of 5.

## 3. Threat-Scoring Algorithm

### 3.1 Base scores

| event_type | Base score | Reason |
|---|---|---|
| NEW_PROCESS | 5 | Very common and usually harmless |
| SUSPICIOUS_PROCESS_NAME | 30 | Direct indicator of malicious software |
| HIGH_CPU_PROCESS | 20 | Possible abuse (e.g. mining), but common in normal use |
| FILE_CREATED | 2 | Normal activity |
| FILE_MODIFIED | 2 | Normal activity |
| FILE_DELETED | 4 | Slightly more risky than creating |
| FILE_RENAMED | 4 | Renaming is used by ransomware |
| MASS_FILE_CHANGE | 35 | Many changes in a short window is unusual |
| RANSOMWARE_PATTERN | 60 | Strongest file-based indicator |
| HIGH_SYSTEM_CPU | 15 | Can be normal load |
| HIGH_SYSTEM_MEMORY | 15 | Can be normal load |
| HIGH_PROCESS_RESOURCE | 20 | One process using heavy resources |

### 3.2 Value bonus

For process and resource events that carry a `value` (CPU or memory %):

- value >= 95: +10
- value >= 85: +5

### 3.3 Severity levels

| Score | Severity |
|---|---|
| 0 to 29 | LOW |
| 30 to 59 | MEDIUM |
| 60 to 89 | HIGH |
| 90 to 100 | CRITICAL |

An alert is created and stored when the score is **30 or more** (MEDIUM and above). LOW events are stored as events only.

## 4. Correlation Rules

One weak signal is low risk. Signals from different modules close together in time, especially from the same process, are more suspicious. The correlator remembers events from the last **60 seconds** and applies these bonuses:

| Rule | Bonus |
|---|---|
| Another module has reported an event in the window | +20 for each other module |
| The same PID was reported by a different module | +15 |

The final score is capped at **100**.

## 5. Database Schema (SQLite)

**events**

| Column | Type |
|---|---|
| id | INTEGER, primary key |
| timestamp | REAL |
| source | TEXT |
| event_type | TEXT |
| description | TEXT |
| pid | INTEGER |
| process_name | TEXT |
| value | REAL |
| details | TEXT (JSON) |

**alerts**

| Column | Type |
|---|---|
| id | INTEGER, primary key |
| timestamp | REAL |
| score | INTEGER |
| severity | TEXT |
| reason | TEXT (explains how the score was built) |
| event_id | INTEGER, foreign key to events.id |

A lock is used around all database operations because three monitors may submit events from different threads.

## 6. Test Results

### 6.1 Automated tests (pytest)

| Test | What it checks | Result |
|---|---|---|
| test_severity_levels | Scores map to the correct severity | PASSED |
| test_low_event_no_alert | A plain NEW_PROCESS is LOW and creates no alert | PASSED |
| test_correlation_raises_score | Related events from two modules score higher | PASSED |
| test_events_stored | Submitted events are saved in the database | PASSED |
| test_old_events_expire | Events older than 60 seconds give no correlation bonus | PASSED |

Result: **5 passed**.

### 6.2 Simulation (`python simulate.py`)

A fake attack by one process (PID 1234) was simulated:

| Step | Event | Score | Severity | Alert? |
|---|---|---|---|---|
| 1 | NEW_PROCESS (notepad.exe) | 5 | LOW | No |
| 2 | HIGH_CPU_PROCESS at 92% (20 + 5 value bonus) | 25 | LOW | No |
| 3 | MASS_FILE_CHANGE, same PID | 70 | HIGH | Yes |
| 4 | RANSOMWARE_PATTERN, same PID | 95 | CRITICAL | Yes |
| 5 | HIGH_SYSTEM_MEMORY at 96% | 65 | HIGH | Yes |

Output:

```
[ALERT][HIGH] score=70 | 150 files changed in 10s | MASS_FILE_CHANGE (+35); also seen from ['process'] (+20); same PID 1234 across modules (+15)
[ALERT][CRITICAL] score=95 | Mass rename to .locked | RANSOMWARE_PATTERN (+60); also seen from ['process'] (+20); same PID 1234 across modules (+15)
[ALERT][HIGH] score=65 | Memory at 96% | HIGH_SYSTEM_MEMORY (+25); also seen from ['filesystem', 'process'] (+40)
```

Observations:
- Steps 1 and 2 alone are low risk and create no alerts.
- Once the same process also changes many files, correlation raises the score to HIGH, then CRITICAL.
- The memory spike alone would score only 25, but because two other modules had reported events, it rose to 65.
- All three alerts were saved in the `alerts` table.

## 7. Limitations and Future Work

- Score weights and the 60-second window are fixed values chosen by us; they could be made configurable.
- Correlation uses PID and time only; it does not track parent/child processes.
- Alerts are printed to the console and stored in SQLite; there is no dashboard.

## 8. Integration with Resource Monitor (Person 3)

Person 3's monitor uses its own `SecurityEvent` format, so `core/adapters.py`
converts it into the shared `Event`:

| Resource monitor event | Shared event_type |
|---|---|
| sustained_system_resource_spike (system_cpu) | HIGH_SYSTEM_CPU |
| sustained_system_resource_spike (system_memory) | HIGH_SYSTEM_MEMORY |
| sustained_process_resource_spike | HIGH_PROCESS_RESOURCE (pid and name kept) |

`main.py` creates one `ThreatEngine` and passes events from the monitor's
callback into `engine.submit()`.

Tests: `tests/test_adapters.py` (3 tests) check each mapping. All 8 tests
pass. A live run with the memory threshold lowered stored
HIGH_SYSTEM_MEMORY events in the database.