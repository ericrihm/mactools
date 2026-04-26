"""Claude AI integration — API with CLI fallback."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass
class AnalysisResult:
    text: str
    model: str
    analysis_type: str
    ok: bool


DEFAULT_MODEL = "claude-sonnet-4-6"


def analyze(
    system_prompt: str,
    context: str,
    model: str = DEFAULT_MODEL,
) -> AnalysisResult:
    try:
        from anthropic import Anthropic
        client = Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": context}],
        )
        return AnalysisResult(
            text=resp.content[0].text, model=model,
            analysis_type="api", ok=True,
        )
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["claude", "-p", context, "--model", model],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode == 0:
            return AnalysisResult(
                text=r.stdout.strip(), model=model,
                analysis_type="cli", ok=True,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return AnalysisResult(
        text="Analysis unavailable — no API key or claude CLI found.",
        model=model, analysis_type="none", ok=False,
    )
