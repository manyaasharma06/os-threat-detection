import threading
from core.database import Database
from core.correlator import Correlator
from core.scoring import severity_level

ALERT_THRESHOLD = 30   # MEDIUM and above creates an alert


class ThreatEngine:
    def __init__(self, db_path="threats.db"):
        self.db = Database(db_path)
        self.correlator = Correlator()
        self.lock = threading.Lock()

    def submit(self, event):
        with self.lock:
            event_id = self.db.insert_event(event)
            score, reasons = self.correlator.evaluate(event)
            level = severity_level(score)
            if score >= ALERT_THRESHOLD:
                self.db.insert_alert(event.timestamp, score, level,
                                     "; ".join(reasons), event_id)
                print(f"[ALERT][{level}] score={score} | "
                      f"{event.description} | {'; '.join(reasons)}")
            return score, level