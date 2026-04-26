"""macOS power management — pmset, powermetrics, IOKit battery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run


@dataclass
class PowerSettings:
    sleep_timer: int = 0
    display_sleep: int = 0
    disk_sleep: int = 0
    wake_on_lan: bool = False
    power_nap: bool = False
    autopoweroff: bool = False
    standby: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class SleepPreventer:
    name: str
    pid: int = 0
    assertion_type: str = ""
    detail: str = ""


@dataclass
class ScheduledEvent:
    event_type: str
    time: str
    owner: str = ""


@dataclass
class ThermalState:
    level: str = "nominal"
    cpu_speed_limit: int = 100
    details: str = ""


def get_power_settings() -> PowerSettings:
    r = run(["pmset", "-g", "custom"])
    if not r.ok:
        return PowerSettings()
    settings = PowerSettings()
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("sleep"):
            m = re.search(r"\d+", line)
            if m:
                settings.sleep_timer = int(m.group())
        elif line.startswith("displaysleep"):
            m = re.search(r"\d+", line)
            if m:
                settings.display_sleep = int(m.group())
        elif line.startswith("disksleep"):
            m = re.search(r"\d+", line)
            if m:
                settings.disk_sleep = int(m.group())
        elif "womp" in line:
            settings.wake_on_lan = "1" in line
        elif "powernap" in line:
            settings.power_nap = "1" in line
    return settings


def get_sleep_preventers() -> list[SleepPreventer]:
    r = run(["pmset", "-g", "assertions"])
    if not r.ok:
        return []
    preventers = []
    for line in r.stdout.splitlines():
        line = line.strip()
        m = re.match(r"pid (\d+)\((\w+)\):\s+\[.*\]\s+(\S+)\s+named:\s+\"(.*)\"", line)
        if m:
            preventers.append(SleepPreventer(
                pid=int(m.group(1)),
                name=m.group(2),
                assertion_type=m.group(3),
                detail=m.group(4),
            ))
    return preventers


def get_scheduled_events() -> list[ScheduledEvent]:
    r = run(["pmset", "-g", "sched"])
    if not r.ok:
        return []
    events = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or "Repeating" in line or "Scheduled" in line:
            continue
        m = re.match(r"(\w+)\s+at\s+(.+?)(?:\s+by\s+(.+))?$", line)
        if m:
            events.append(ScheduledEvent(
                event_type=m.group(1),
                time=m.group(2).strip(),
                owner=m.group(3).strip() if m.group(3) else "",
            ))
    return events


def get_thermal_state() -> ThermalState:
    r = run(["pmset", "-g", "therm"])
    if not r.ok:
        return ThermalState()
    text = r.stdout.lower()
    if "speed limit" in text:
        m = re.search(r"cpu_speed_limit\s*=\s*(\d+)", text)
        limit = int(m.group(1)) if m else 100
        level = "nominal" if limit == 100 else "throttled" if limit > 50 else "critical"
        return ThermalState(level=level, cpu_speed_limit=limit, details=r.stdout.strip())
    return ThermalState(details=r.stdout.strip())
