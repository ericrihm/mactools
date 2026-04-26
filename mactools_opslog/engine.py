"""Core triage and severity logic for opslog — pure functions, no side effects."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mactools_core.unified_log import LogEntry


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

# (pattern, severity) — evaluated in order; first match wins.
_SEVERITY_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"kernel panic", re.IGNORECASE), "critical"),
    (re.compile(r"panic\b", re.IGNORECASE), "critical"),
    (re.compile(r"out of memory|OOM|low memory", re.IGNORECASE), "critical"),
    (re.compile(r"sandbox violation|deny.*sandbox|sandbox.*deny", re.IGNORECASE), "warning"),
    (re.compile(r"codesign.*fail|invalid signature|signature invalid", re.IGNORECASE), "warning"),
    (re.compile(r"crash|crashed|segfault|SIGSEGV|SIGABRT", re.IGNORECASE), "critical"),
    (re.compile(r"xpc.*error|error.*xpc", re.IGNORECASE), "info"),
    (re.compile(r"connection.*invalidated|invalidated.*connection", re.IGNORECASE), "info"),
    (re.compile(r"timeout|timed out", re.IGNORECASE), "warning"),
    (re.compile(r"permission denied|not permitted|EPERM|EACCES", re.IGNORECASE), "warning"),
    (re.compile(r"disk.*full|no space left|ENOSPC", re.IGNORECASE), "critical"),
    (re.compile(r"failed|failure", re.IGNORECASE), "warning"),
    (re.compile(r"error\b", re.IGNORECASE), "warning"),
    (re.compile(r"fault\b", re.IGNORECASE), "critical"),
]

_LEVEL_SEVERITY: dict[str, str] = {
    "fault": "critical",
    "error": "warning",
    "warning": "warning",
    "info": "info",
    "debug": "info",
    "default": "info",
}


def classify_severity(entry: "LogEntry") -> str:
    """Return a severity string for a LogEntry using heuristic rules.

    Checks the message text first (content rules), then falls back to the
    log level field.  Always returns one of: 'critical', 'warning', 'info'.
    """
    msg = entry.message
    for pattern, severity in _SEVERITY_RULES:
        if pattern.search(msg):
            return severity
    return _LEVEL_SEVERITY.get(entry.level.lower(), "info")


# ---------------------------------------------------------------------------
# Triage grouping
# ---------------------------------------------------------------------------

@dataclass
class TriageGroup:
    process: str
    subsystem: str
    severity: str
    count: int
    sample_messages: list[str] = field(default_factory=list)
    levels: dict[str, int] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.process}|{self.subsystem}"


def triage_errors(entries: list["LogEntry"]) -> list[TriageGroup]:
    """Group a list of LogEntry objects by (process, subsystem).

    Counts occurrences, tracks unique severity levels, and collects up to
    three representative sample messages.  Returns groups sorted by frequency
    (descending), with critical groups promoted ahead of same-count groups.
    """
    groups: dict[str, TriageGroup] = {}
    seen_messages: dict[str, set[str]] = defaultdict(set)

    for entry in entries:
        key = f"{entry.process}|{entry.subsystem}"
        severity = classify_severity(entry)

        if key not in groups:
            groups[key] = TriageGroup(
                process=entry.process,
                subsystem=entry.subsystem,
                severity=severity,
                count=0,
                sample_messages=[],
                levels={},
            )

        g = groups[key]
        g.count += 1

        # Escalate severity if we see something worse
        _order = ["info", "warning", "critical"]
        if _order.index(severity) > _order.index(g.severity):
            g.severity = severity

        # Track level distribution
        lvl = entry.level.lower()
        g.levels[lvl] = g.levels.get(lvl, 0) + 1

        # Collect up to 3 distinct sample messages (trimmed)
        msg = entry.message.strip()[:200]
        if msg and msg not in seen_messages[key] and len(g.sample_messages) < 3:
            g.sample_messages.append(msg)
            seen_messages[key].add(msg)

    _sev_rank = {"critical": 2, "warning": 1, "info": 0}
    return sorted(
        groups.values(),
        key=lambda g: (_sev_rank.get(g.severity, 0), g.count),
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Triage report builder
# ---------------------------------------------------------------------------

@dataclass
class TriageReport:
    total_entries: int
    total_groups: int
    critical_count: int
    warning_count: int
    info_count: int
    groups: list[TriageGroup]


def build_triage_report(groups: list[TriageGroup]) -> TriageReport:
    """Produce a structured TriageReport from a list of TriageGroup objects."""
    total_entries = sum(g.count for g in groups)
    critical = sum(1 for g in groups if g.severity == "critical")
    warning = sum(1 for g in groups if g.severity == "warning")
    info = sum(1 for g in groups if g.severity == "info")
    return TriageReport(
        total_entries=total_entries,
        total_groups=len(groups),
        critical_count=critical,
        warning_count=warning,
        info_count=info,
        groups=groups,
    )
