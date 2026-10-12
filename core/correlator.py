from collections import deque
from core.scoring import base_score

WINDOW_SECONDS = 60       # how long events are remembered
CROSS_SOURCE_BONUS = 20   # per extra module reporting in the window
SAME_PID_BONUS = 15       # same process seen by different modules


class Correlator:
    def __init__(self):
        self.recent = deque()   # stores events from the last WINDOW_SECONDS

    def _prune(self, now):
        while self.recent and now - self.recent[0].timestamp > WINDOW_SECONDS:
            self.recent.popleft()

    def evaluate(self, event):
        """Returns (final_score, reasons_list)."""
        self._prune(event.timestamp)
        score = base_score(event)
        reasons = [f"{event.event_type} (+{score})"]

        # other modules reporting in the same window
        other_sources = {e.source for e in self.recent if e.source != event.source}
        if other_sources:
            bonus = CROSS_SOURCE_BONUS * len(other_sources)
            score += bonus
            reasons.append(f"also seen from {sorted(other_sources)} (+{bonus})")

        # same process involved across modules
        if event.pid is not None:
            same_pid = any(e.pid == event.pid and e.source != event.source
                           for e in self.recent)
            if same_pid:
                score += SAME_PID_BONUS
                reasons.append(f"same PID {event.pid} across modules (+{SAME_PID_BONUS})")

        self.recent.append(event)
        return min(score, 100), reasons