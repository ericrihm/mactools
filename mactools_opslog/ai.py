"""AI integration for opslog — system prompts, context builders, analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mactools_core.ai import analyze, AnalysisResult, DEFAULT_MODEL

if TYPE_CHECKING:
    from mactools_core.unified_log import LogEntry, LogStats


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS: dict[str, str] = {
    "triage": (
        "You are an expert macOS systems engineer analyzing Unified Log output. "
        "Your job is to triage a set of log errors and faults, identify the most "
        "significant issues, and explain their likely root causes. "
        "Focus on actionable findings: what is broken, why, and what to check next. "
        "Group related errors together. Ignore routine noise like XPC connection "
        "resets or sandbox denials for com.apple.* unless they are unusually frequent. "
        "Be concise — use bullet points. Highlight critical issues first."
    ),
    "explain": (
        "You are an expert macOS systems engineer. Explain the following macOS Unified "
        "Log entries in plain language. For each entry describe: what component is "
        "reporting, what the error means in plain English, whether it is likely "
        "harmless or indicates a real problem, and any remediation steps if applicable. "
        "Be concise and technical but accessible."
    ),
    "timeline": (
        "You are an expert macOS systems engineer analyzing a sequence of log events. "
        "Reconstruct the timeline of what happened: identify the initiating event, "
        "downstream effects, and the final state. Look for causal chains — one error "
        "triggering others. Highlight the root cause if identifiable. "
        "Format your response as a numbered timeline followed by a root-cause summary."
    ),
}


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(
    entries: list["LogEntry"],
    stats: "LogStats | None" = None,
) -> str:
    """Build a compact context string from log entries and optional stats.

    Trims each entry to the key fields to stay within token limits.
    """
    lines: list[str] = []

    if stats:
        lines.append(
            f"Log stats — total: {stats.total_events}, "
            f"errors: {stats.error_count}, faults: {stats.fault_count}"
        )
        lines.append("")

    lines.append(f"Log entries ({len(entries)} total):")
    lines.append("")

    for entry in entries:
        ts = entry.timestamp
        proc = entry.process or "(unknown)"
        sub = entry.subsystem or ""
        lvl = entry.level.upper()
        msg = entry.message.strip()[:300]
        if sub:
            lines.append(f"[{ts}] {lvl} {proc} ({sub}): {msg}")
        else:
            lines.append(f"[{ts}] {lvl} {proc}: {msg}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Analysis dispatcher
# ---------------------------------------------------------------------------

def analyze_logs(
    entries: list["LogEntry"],
    analysis_type: str = "triage",
    model: str = DEFAULT_MODEL,
    stats: "LogStats | None" = None,
) -> AnalysisResult:
    """Run Claude analysis on log entries.

    Args:
        entries: List of LogEntry objects to analyze.
        analysis_type: One of 'triage', 'explain', 'timeline'.
        model: Claude model identifier.
        stats: Optional LogStats for additional context.

    Returns:
        AnalysisResult from mactools_core.ai.analyze.
    """
    system_prompt = SYSTEM_PROMPTS.get(analysis_type, SYSTEM_PROMPTS["triage"])
    context = build_context(entries, stats=stats)
    result = analyze(system_prompt=system_prompt, context=context, model=model)
    result.analysis_type = analysis_type
    return result
