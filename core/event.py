from dataclasses import dataclass, field, asdict
import time

SOURCES = ("process", "filesystem", "resource")


@dataclass
class Event:
    source: str                 # "process" | "filesystem" | "resource"
    event_type: str             # e.g. "NEW_PROCESS", "MASS_FILE_CHANGE"
    description: str = ""
    pid: int | None = None
    process_name: str | None = None
    value: float | None = None  # cpu %, memory %, files changed, etc.
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)