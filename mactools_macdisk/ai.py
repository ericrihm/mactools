"""AI integration for macdisk — system prompts and disk layout explanation."""

from __future__ import annotations

from mactools_core.ai import analyze, AnalysisResult, DEFAULT_MODEL


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS: dict[str, str] = {
    "explain": (
        "You are a macOS storage expert who explains disk layouts to non-technical users. "
        "Given a summary of APFS containers, volumes, capacities, and SMART status, explain: "
        "1. What the disk layout means in plain English (what each volume is for). "
        "2. How much free space is available and whether it is adequate. "
        "3. Any health concerns (SMART warnings, low space, unencrypted volumes). "
        "4. One or two concrete recommendations if there are issues. "
        "Be friendly and concise. Avoid raw disk identifiers (disk0s1) unless necessary — "
        "prefer volume names. Explain APFS concepts simply (containers share space, "
        "volumes are like named partitions)."
    ),
    "issues": (
        "You are a macOS storage health advisor. "
        "Given a list of flagged disk issues with severity levels, provide: "
        "1. A one-sentence overall assessment. "
        "2. The top actionable steps to address each issue, prioritized by severity. "
        "3. Any risks of ignoring the issues (data loss, performance degradation, etc.). "
        "Be direct and practical. Assume the user is comfortable with System Settings "
        "but not with terminal commands unless necessary."
    ),
}


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def explain_disk_layout(disk_summary: str, model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask Claude to explain a disk layout summary in plain English."""
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["explain"],
        context=disk_summary,
        model=model,
    )
    result.analysis_type = "explain"
    return result


def explain_issues(issues_summary: str, model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask Claude to explain and prioritize a list of disk issues."""
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["issues"],
        context=issues_summary,
        model=model,
    )
    result.analysis_type = "issues"
    return result
