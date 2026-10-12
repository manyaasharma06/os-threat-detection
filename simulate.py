import time
from core.event import Event
from core.engine import ThreatEngine

engine = ThreatEngine("demo.db")

print("--- 1. Normal activity ---")
engine.submit(Event("process", "NEW_PROCESS", "New process started",
                    pid=500, process_name="notepad.exe"))

print("--- 2. Suspicious process starts eating CPU ---")
engine.submit(Event("process", "HIGH_CPU_PROCESS", "CPU at 92%",
                    pid=1234, process_name="evil.exe", value=92))
time.sleep(1)

print("--- 3. Same process starts changing many files ---")
engine.submit(Event("filesystem", "MASS_FILE_CHANGE", "150 files changed in 10s",
                    pid=1234, process_name="evil.exe"))
time.sleep(1)

print("--- 4. Ransomware pattern appears ---")
engine.submit(Event("filesystem", "RANSOMWARE_PATTERN", "Mass rename to .locked",
                    pid=1234, process_name="evil.exe"))

print("--- 5. System memory spikes ---")
engine.submit(Event("resource", "HIGH_SYSTEM_MEMORY", "Memory at 96%", value=96))

print("\n=== Alerts stored in database ===")
for alert in engine.db.get_alerts():
    print(alert)