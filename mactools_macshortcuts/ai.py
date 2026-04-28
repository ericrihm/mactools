"""AI integration for macshortcuts — system prompts and shortcut suggestions."""

from __future__ import annotations

from mactools_core.ai import analyze, AnalysisResult, DEFAULT_MODEL


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS: dict[str, str] = {
    "suggest": (
        "You are a macOS Shortcuts expert who helps users automate their workflows. "
        "Given a description of an automation the user wants, and a list of their "
        "existing shortcuts, suggest what Shortcut to build. Include: "
        "1. A suggested name for the shortcut. "
        "2. A step-by-step action list (use real Shortcuts app action names where possible). "
        "3. Whether any existing shortcut already covers or partially covers this need. "
        "4. Any apps or permissions required. "
        "Be specific and practical. Mention if the automation would work better as a "
        "Focus Mode, Automation, or Shortcut. Keep suggestions to 10 steps or fewer."
    ),
    "audit": (
        "You are a macOS Shortcuts curator helping a user review their shortcut library. "
        "Given a list of shortcut names, provide: "
        "1. Groupings by likely purpose (e.g., productivity, media, system, utilities). "
        "2. Observations about gaps or redundancies. "
        "3. Two or three suggestions for new shortcuts that would complement what they have. "
        "Be concise and avoid listing every shortcut back to the user — focus on patterns "
        "and recommendations."
    ),
}


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def suggest_shortcut(context_text: str, model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask AI to suggest a shortcut based on a description and existing library."""
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["suggest"],
        context=context_text,
        model=model,
    )
    result.analysis_type = "suggest"
    return result


def audit_shortcuts(shortcut_names: list[str], model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask AI to audit and categorize the user's shortcut library."""
    names_block = "\n".join(f"  - {n}" for n in shortcut_names) if shortcut_names else "  (none)"
    context = f"Installed shortcuts ({len(shortcut_names)} total):\n{names_block}"
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["audit"],
        context=context,
        model=model,
    )
    result.analysis_type = "audit"
    return result
