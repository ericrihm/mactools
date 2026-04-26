"""Engine for macOS energy and thermal intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field

from mactools_core.power import (
    PowerSettings,
    ScheduledEvent,
    SleepPreventer,
    ThermalState,
    get_power_settings,
    get_scheduled_events,
    get_sleep_preventers,
    get_thermal_state,
)


# ---------------------------------------------------------------------------
# Audit result
# ---------------------------------------------------------------------------

@dataclass
class EnergyAudit:
    power_settings: PowerSettings
    preventers: list[SleepPreventer]
    thermal: ThermalState
    schedule: list[ScheduledEvent]
    issues: list["EnergyIssue"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "power_settings": {
                "sleep_timer": self.power_settings.sleep_timer,
                "display_sleep": self.power_settings.display_sleep,
                "disk_sleep": self.power_settings.disk_sleep,
                "wake_on_lan": self.power_settings.wake_on_lan,
                "power_nap": self.power_settings.power_nap,
            },
            "sleep_preventers": [
                {
                    "name": p.name,
                    "pid": p.pid,
                    "assertion_type": p.assertion_type,
                    "detail": p.detail,
                }
                for p in self.preventers
            ],
            "thermal": {
                "level": self.thermal.level,
                "cpu_speed_limit": self.thermal.cpu_speed_limit,
                "details": self.thermal.details,
            },
            "schedule": [
                {"event_type": e.event_type, "time": e.time, "owner": e.owner}
                for e in self.schedule
            ],
            "issues": [i.to_dict() for i in self.issues],
        }


@dataclass
class EnergyIssue:
    severity: str   # "critical" | "warning" | "info"
    category: str
    title: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Known unnecessary wakers — processes that often hold assertions spuriously.
# ---------------------------------------------------------------------------

_KNOWN_UNNECESSARY_WAKERS = {
    "coreaudiod": "Audio daemon — may hold assertion after playback ends. Restart audio.",
    "sharingd": "Sharing services — disable AirDrop/Sharing if not needed.",
    "bluetoothd": "Bluetooth daemon — disable Bluetooth when not in use.",
    "powerd": "Power management daemon — this assertion should self-clear.",
    "backupd": "Time Machine backup — normal during active backups.",
}

_MEDIA_WAKERS = {"coreaudiod", "mds", "mdworker", "com.apple.WebKit"}

_HIGH_IMPACT_ASSERTION_TYPES = {
    "PreventUserIdleSystemSleep",
    "PreventSystemSleep",
    "BackgroundTask",
}


def identify_energy_issues(
    settings: PowerSettings,
    preventers: list[SleepPreventer],
    thermal: ThermalState,
) -> list[EnergyIssue]:
    """Flag energy problems: unnecessary wake preventers, bad sleep settings, throttling."""
    issues: list[EnergyIssue] = []

    # --- Thermal throttling ---
    if thermal.level == "critical":
        issues.append(EnergyIssue(
            severity="critical",
            category="Thermal",
            title="CPU critically throttled",
            detail=f"CPU speed limited to {thermal.cpu_speed_limit}% due to extreme thermal pressure. "
                   "Quit demanding applications, ensure ventilation is unobstructed.",
        ))
    elif thermal.level == "throttled":
        issues.append(EnergyIssue(
            severity="warning",
            category="Thermal",
            title=f"CPU thermally throttled to {thermal.cpu_speed_limit}%",
            detail="The system is reducing CPU speed to manage heat. "
                   "Performance-sensitive tasks will be slower than normal.",
        ))

    # --- Aggressive sleep settings ---
    if settings.sleep_timer == 0:
        issues.append(EnergyIssue(
            severity="info",
            category="Power",
            title="System sleep is disabled (sleep=0)",
            detail="The Mac will never sleep automatically. "
                   "Consider setting sleep to 15–30 minutes on battery to preserve energy.",
        ))
    elif settings.sleep_timer > 60:
        issues.append(EnergyIssue(
            severity="info",
            category="Power",
            title=f"System sleep timer set to {settings.sleep_timer} minutes",
            detail="A long sleep timer wastes energy when idle. "
                   "Values of 10–20 minutes are typical for desktop use.",
        ))

    if settings.display_sleep == 0:
        issues.append(EnergyIssue(
            severity="warning",
            category="Power",
            title="Display sleep is disabled",
            detail="The display never sleeps, consuming significant power. "
                   "Set to 2–5 minutes with: pmset -a displaysleep 5",
        ))

    # --- Wake-on-LAN when not needed ---
    if settings.wake_on_lan:
        issues.append(EnergyIssue(
            severity="info",
            category="Power",
            title="Wake-on-LAN is enabled",
            detail="The Mac can be woken remotely over the network. "
                   "Disable with: sudo pmset -a womp 0 if remote wake is not needed.",
        ))

    # --- Power Nap ---
    if settings.power_nap:
        issues.append(EnergyIssue(
            severity="info",
            category="Power",
            title="Power Nap is enabled",
            detail="Power Nap wakes the Mac periodically for Mail, iCloud, and backups while asleep. "
                   "Disable with: sudo pmset -a powernap 0 to extend battery life.",
        ))

    # --- Sleep preventers ---
    high_impact = [
        p for p in preventers
        if p.assertion_type in _HIGH_IMPACT_ASSERTION_TYPES
    ]
    if len(high_impact) > 3:
        names = ", ".join({p.name for p in high_impact})
        issues.append(EnergyIssue(
            severity="warning",
            category="Wake",
            title=f"{len(high_impact)} processes preventing system sleep",
            detail=f"Processes: {names}. "
                   "Multiple simultaneous sleep preventers are unusual outside heavy workloads.",
        ))

    for p in preventers:
        if p.name in _KNOWN_UNNECESSARY_WAKERS and p.assertion_type in _HIGH_IMPACT_ASSERTION_TYPES:
            hint = _KNOWN_UNNECESSARY_WAKERS[p.name]
            issues.append(EnergyIssue(
                severity="info",
                category="Wake",
                title=f"{p.name} (pid {p.pid}) is preventing sleep",
                detail=f"{hint} Assertion: {p.assertion_type} — \"{p.detail}\"",
            ))

    if not issues:
        issues.append(EnergyIssue(
            severity="info",
            category="Overall",
            title="Energy configuration looks healthy",
            detail="No significant power management issues detected.",
        ))

    return issues


def audit_energy() -> EnergyAudit:
    """Collect all energy data and run issue detection."""
    settings = get_power_settings()
    preventers = get_sleep_preventers()
    thermal = get_thermal_state()
    schedule = get_scheduled_events()
    issues = identify_energy_issues(settings, preventers, thermal)
    return EnergyAudit(
        power_settings=settings,
        preventers=preventers,
        thermal=thermal,
        schedule=schedule,
        issues=issues,
    )
