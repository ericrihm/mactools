"""macOS Unified Log interface — wraps `log show`, `log stream`, `log stats`."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from mactools_core.runner import run


@dataclass
class LogEntry:
    timestamp: str
    process: str
    pid: int
    subsystem: str
    category: str
    message: str
    level: str
    activity_id: str = ""
    thread_id: str = ""

    @property
    def datetime(self) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(self.timestamp.replace(" ", "T").split("+")[0])
        except (ValueError, IndexError):
            return None


@dataclass
class LogStats:
    total_events: int = 0
    error_count: int = 0
    fault_count: int = 0
    info_count: int = 0
    debug_count: int = 0
    default_count: int = 0
    earliest: str = ""
    latest: str = ""


_ENTRY_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+"
    r"0x([0-9a-f]+)\s+"
    r"(\w+)\s+"
    r"0x([0-9a-f]+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\S+)\s*:\s*(?:\((\S+)\)\s*)?(?:\[(\S+)\]\s*)?(.*)",
    re.IGNORECASE,
)


def parse_log_output(text: str) -> list[LogEntry]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Timestamp") or line.startswith("---"):
            continue
        m = _ENTRY_RE.match(line)
        if m:
            entries.append(LogEntry(
                timestamp=m.group(1),
                activity_id=m.group(2),
                level=m.group(3),
                thread_id=m.group(4),
                pid=int(m.group(5)),
                process=m.group(7) or "",
                subsystem=m.group(8) or "",
                category=m.group(9) or "",
                message=m.group(10) or "",
            ))
        elif entries:
            entries[-1].message += "\n" + line
    return entries


def log_show(
    last: str = "5m",
    predicate: Optional[str] = None,
    process: Optional[str] = None,
    level: str = "error",
    limit: int = 500,
) -> list[LogEntry]:
    cmd = ["log", "show", "--last", last, "--style", "compact"]
    if predicate and process:
        cmd.extend(["--predicate", f'({predicate}) AND process == "{process}"'])
    elif predicate:
        cmd.extend(["--predicate", predicate])
    elif process:
        cmd.extend(["--predicate", f'process == "{process}"'])
    if level:
        cmd.extend(["--info" if level == "info" else "--debug" if level == "debug" else ""])
        cmd = [c for c in cmd if c]
    r = run(cmd, timeout=60)
    if not r.ok:
        return []
    entries = parse_log_output(r.stdout)
    return entries[:limit]


def log_stats() -> LogStats:
    r = run(["log", "stats"], timeout=30)
    if not r.ok:
        return LogStats()
    stats = LogStats()
    for line in r.stdout.splitlines():
        if "Total:" in line or "total:" in line:
            nums = re.findall(r"\d+", line)
            if nums:
                stats.total_events = int(nums[0])
        if "Error:" in line or "error:" in line:
            nums = re.findall(r"\d+", line)
            if nums:
                stats.error_count = int(nums[0])
        if "Fault:" in line or "fault:" in line:
            nums = re.findall(r"\d+", line)
            if nums:
                stats.fault_count = int(nums[0])
    return stats


def log_show_json(
    last: str = "5m",
    predicate: Optional[str] = None,
) -> list[dict]:
    cmd = ["log", "show", "--last", last, "--style", "ndjson"]
    if predicate:
        cmd.extend(["--predicate", predicate])
    r = run(cmd, timeout=60)
    if not r.ok:
        return []
    import json
    entries = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries
