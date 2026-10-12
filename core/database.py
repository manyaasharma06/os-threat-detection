import sqlite3
import json
import threading


class Database:
    def __init__(self, path="threats.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._create_tables()

    def _create_tables(self):
        with self.lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                source TEXT,
                event_type TEXT,
                description TEXT,
                pid INTEGER,
                process_name TEXT,
                value REAL,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                score INTEGER,
                severity TEXT,
                reason TEXT,
                event_id INTEGER,
                FOREIGN KEY(event_id) REFERENCES events(id)
            );
            """)
            self.conn.commit()

    def insert_event(self, e):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO events (timestamp, source, event_type, description, "
                "pid, process_name, value, details) VALUES (?,?,?,?,?,?,?,?)",
                (e.timestamp, e.source, e.event_type, e.description,
                 e.pid, e.process_name, e.value, json.dumps(e.details)))
            self.conn.commit()
            return cur.lastrowid

    def insert_alert(self, timestamp, score, severity, reason, event_id):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO alerts (timestamp, score, severity, reason, event_id) "
                "VALUES (?,?,?,?,?)",
                (timestamp, score, severity, reason, event_id))
            self.conn.commit()
            return cur.lastrowid

    def get_alerts(self):
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()

    def get_events(self, limit=100):
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,)).fetchall()

    def close(self):
        self.conn.close()