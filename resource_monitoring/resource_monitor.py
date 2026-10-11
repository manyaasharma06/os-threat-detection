"""System and per-process CPU/memory monitoring using Python's standard library."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import platform
import time
import uuid


@dataclass(frozen=True)
class MonitorConfig:
    interval_seconds: float = 1.0
    sustained_samples: int = 3
    system_cpu_threshold_percent: float = 85.0
    system_memory_threshold_percent: float = 90.0
    process_cpu_threshold_percent: float = 80.0
    process_memory_threshold_mb: float = 1024.0


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    confidence: float
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _event(event_type: str, details: dict) -> SecurityEvent:
    return SecurityEvent(str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                         "resource_monitor", event_type, "high", 0.85, details)


class ResourceMonitor:
    """Samples machine CPU/memory and process resource use.

    Linux reads /proc. Windows uses ctypes + psapi. macOS uses `ps`/`vm_stat`.
    Threshold alerts fire after N consecutive samples and reset after recovery.
    """
    def __init__(self, config: MonitorConfig | None = None, callback=None):
        self.config = config or MonitorConfig()
        if self.config.interval_seconds <= 0 or self.config.sustained_samples < 1:
            raise ValueError("interval_seconds must be positive and sustained_samples at least 1")
        self.callback = callback
        self._system_streak: dict[str, int] = {}
        self._process_streak: dict[tuple[int, str], int] = {}
        self._previous_cpu = self._read_cpu_counters()
        self._running = False

    def _read_cpu_counters(self):
        if platform.system() == "Linux":
            try:
                with open("/proc/stat", encoding="ascii") as f:
                    values = list(map(int, f.readline().split()[1:]))
                return (sum(values), values[3] + (values[4] if len(values) > 4 else 0))
            except (OSError, ValueError, IndexError):
                return None
        if platform.system() == "Windows":
            import ctypes
            class FILETIME(ctypes.Structure):
                _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]
            idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
            if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
                def num(x): return (x.dwHighDateTime << 32) | x.dwLowDateTime
                return (num(kernel) + num(user), num(idle))
            return None
        return None

    def _system_cpu(self) -> float | None:
        current = self._read_cpu_counters()
        previous = self._previous_cpu
        self._previous_cpu = current
        if current is None or previous is None:
            return None
        total_delta = current[0] - previous[0]
        idle_delta = current[1] - previous[1]
        return max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)) if total_delta > 0 else None

    def _system_memory(self) -> tuple[float, int, int] | None:
        if platform.system() == "Linux":
            try:
                values = {}
                with open("/proc/meminfo", encoding="ascii") as f:
                    for line in f:
                        key, raw = line.split(":", 1)
                        values[key] = int(raw.split()[0]) * 1024
                total = values["MemTotal"]
                available = values.get("MemAvailable", values.get("MemFree", 0))
                used = total - available
                return used * 100.0 / total, used, total
            except (OSError, ValueError, KeyError):
                return None
        if platform.system() == "Windows":
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            info = MEMORYSTATUSEX(); info.dwLength = ctypes.sizeof(info)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
                used = info.ullTotalPhys - info.ullAvailPhys
                return info.dwMemoryLoad, used, info.ullTotalPhys
        if platform.system() == "Darwin":
            try:
                import subprocess
                out = subprocess.check_output(["vm_stat"], text=True)
                page_size = int(out.split("page size of ")[1].split(" bytes")[0])
                numbers = {}
                for line in out.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        numbers[k] = int(v.strip().rstrip("."))
                total = os.sysconf("SC_PHYS_PAGES") * page_size
                free = sum(numbers.get(k, 0) for k in ("Pages free", "Pages inactive", "Pages speculative")) * page_size
                used = total - free
                return used * 100.0 / total, used, total
            except (OSError, ValueError, KeyError, IndexError):
                return None
        return None

    def _processes(self) -> list[dict]:
        system = platform.system()
        if system == "Linux":
            return self._linux_processes()
        if system == "Windows":
            return self._windows_processes()
        if system == "Darwin":
            return self._mac_processes()
        return []

    def _linux_processes(self) -> list[dict]:
        result = []
        try:
            with open("/proc/stat", encoding="ascii") as f:
                total_ticks = sum(map(int, f.readline().split()[1:]))
        except (OSError, ValueError):
            total_ticks = 0
        page = os.sysconf("SC_PAGE_SIZE")
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                pid = int(entry.name)
                raw = open(f"/proc/{pid}/stat", encoding="utf-8").read()
                fields = raw[raw.rfind(")") + 2:].split()
                name = raw[raw.find("(") + 1:raw.rfind(")")]
                ticks = int(fields[11]) + int(fields[12])
                rss = max(0, int(fields[21]) * page)
                result.append({"pid": pid, "name": name, "cpu_percent": 100.0 * ticks / total_ticks if total_ticks else 0.0,
                               "memory_bytes": rss})
            except (OSError, ValueError, IndexError, ProcessLookupError):
                continue
        return result

    def _windows_processes(self) -> list[dict]:
        import ctypes
        from ctypes import wintypes
        psapi, kernel = ctypes.windll.psapi, ctypes.windll.kernel32
        pids = (wintypes.DWORD * 4096)(); needed = wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(needed)):
            return []
        result = []
        for pid in pids[:needed.value // ctypes.sizeof(wintypes.DWORD)]:
            handle = kernel.OpenProcess(0x1000 | 0x0400, False, pid)
            if not handle:
                continue
            try:
                buf = ctypes.create_unicode_buffer(260)
                psapi.GetModuleBaseNameW(handle, None, buf, len(buf))
                class PMC(ctypes.Structure):
                    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
                pmc = PMC(); pmc.cb = ctypes.sizeof(pmc)
                psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb)
                result.append({"pid": int(pid), "name": buf.value or "?", "cpu_percent": 0.0,
                               "memory_bytes": int(pmc.WorkingSetSize)})
            finally:
                kernel.CloseHandle(handle)
        return result

    def _mac_processes(self) -> list[dict]:
        import subprocess
        try:
            out = subprocess.check_output(["ps", "-axo", "pid=,pcpu=,rss=,comm="], text=True)
        except (OSError, subprocess.CalledProcessError):
            return []
        result = []
        for line in out.splitlines():
            try:
                pid, cpu, rss, name = line.strip().split(None, 3)
                result.append({"pid": int(pid), "name": name, "cpu_percent": float(cpu),
                               "memory_bytes": int(rss) * 1024})
            except (ValueError, TypeError):
                continue
        return result

    def sample_once(self) -> tuple[dict, list[SecurityEvent]]:
        cpu = self._system_cpu()
        memory = self._system_memory()
        processes = self._processes()
        snapshot = {"timestamp": datetime.now(timezone.utc).isoformat(), "system_cpu_percent": cpu,
                    "system_memory_percent": memory[0] if memory else None,
                    "system_memory_used_bytes": memory[1] if memory else None,
                    "system_memory_total_bytes": memory[2] if memory else None, "processes": processes}
        emitted = []
        checks = [("system_cpu", cpu, self.config.system_cpu_threshold_percent),
                  ("system_memory", memory[0] if memory else None, self.config.system_memory_threshold_percent)]
        for name, value, threshold in checks:
            if value is None:
                continue
            self._system_streak[name] = self._system_streak.get(name, 0) + 1 if value >= threshold else 0
            if self._system_streak[name] == self.config.sustained_samples:
                details = {"metric": name, "value_percent": round(value, 2), "threshold_percent": threshold,
                           "consecutive_samples": self.config.sustained_samples}
                emitted.append(_event("sustained_system_resource_spike", details))
        active = set()
        for process in processes:
            key = (process["pid"], process["name"])
            active.add(key)
            over_cpu = process["cpu_percent"] >= self.config.process_cpu_threshold_percent
            over_mem = process["memory_bytes"] >= self.config.process_memory_threshold_mb * 1024 * 1024
            if over_cpu or over_mem:
                streak = self._process_streak.get(key, 0) + 1
                self._process_streak[key] = streak
                if streak == self.config.sustained_samples:
                    emitted.append(_event("sustained_process_resource_spike", {
                        **process, "memory_mb": round(process["memory_bytes"] / 1024 / 1024, 2),
                        "cpu_threshold_percent": self.config.process_cpu_threshold_percent,
                        "memory_threshold_mb": self.config.process_memory_threshold_mb,
                        "consecutive_samples": streak}))
            else:
                self._process_streak[key] = 0
        self._process_streak = {k: v for k, v in self._process_streak.items() if k in active}
        for event in emitted:
            if self.callback:
                self.callback(event)
        return snapshot, emitted

    def run(self, stop_event=None) -> None:
        self._running = True
        try:
            while self._running and not (stop_event and stop_event.is_set()):
                self.sample_once()
                time.sleep(self.config.interval_seconds)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False


def print_sample(snapshot: dict, events: list[SecurityEvent]) -> None:
    print(json.dumps({"sample": snapshot, "events": [e.to_dict() for e in events]}), flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Monitor system and per-process CPU and memory")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--samples", type=int, default=3, help="Consecutive high samples before alert")
    args = parser.parse_args()
    monitor = ResourceMonitor(MonitorConfig(interval_seconds=args.interval, sustained_samples=args.samples))
    print("Monitoring resources; press Ctrl+C to stop", flush=True)
    try:
        while True:
            snapshot, events = monitor.sample_once()
            print_sample(snapshot, events)
            time.sleep(monitor.config.interval_seconds)
    except KeyboardInterrupt:
        pass
