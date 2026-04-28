"""AI integration for macspot — system prompts and analysis helpers."""

from __future__ import annotations

from mactools_core.ai import analyze, AnalysisResult, DEFAULT_MODEL


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS: dict[str, str] = {
    "search": (
        "You are a macOS Spotlight expert. "
        "Translate the user's natural-language search query into the most precise "
        "mdfind metadata predicate possible. "
        "Output ONLY the raw predicate string — no explanation, no backticks, no quotes "
        "wrapping the entire predicate. "
        "Use standard kMDItem attribute names. "
        "Combine multiple conditions with &&. "
        "For temporal conditions use $time.today, $time.this_week, $time.this_month, "
        "$time.this_year. "
        "For file types use kMDItemContentType or kMDItemContentTypeTree. "
        "Example input: 'PDFs modified this week' "
        "Example output: kMDItemContentType == \"com.adobe.pdf\" && kMDItemFSContentChangeDate >= $time.this_week"
    ),
    "health": (
        "You are a macOS system expert. "
        "Given Spotlight index health information for one or more volumes, explain: "
        "1. Whether Spotlight is working correctly overall. "
        "2. Any volumes where indexing is disabled and what that means for search. "
        "3. Concrete steps to re-enable or rebuild an index if needed. "
        "Be concise (3-5 sentences). Use plain English — no jargon without explanation."
    ),
}


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def translate_query(query: str, model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask AI to translate a natural-language query into an mdfind predicate."""
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["search"],
        context=f"Translate this search query into an mdfind predicate: {query}",
        model=model,
    )
    result.analysis_type = "search"
    return result


def explain_health(health_text: str, model: str = DEFAULT_MODEL) -> AnalysisResult:
    """Ask AI to explain Spotlight index health in plain English."""
    result = analyze(
        system_prompt=SYSTEM_PROMPTS["health"],
        context=health_text,
        model=model,
    )
    result.analysis_type = "health"
    return result
