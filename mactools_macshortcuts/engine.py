"""macshortcuts analysis engine — list, audit, and AI context building."""

from __future__ import annotations

from dataclasses import dataclass, field

from mactools_core.shortcuts import Shortcut, list_shortcuts


# ---------------------------------------------------------------------------
# Shortcut listing
# ---------------------------------------------------------------------------

def list_all_shortcuts() -> list[Shortcut]:
    """Return all installed Shortcuts, sorted alphabetically by name."""
    shortcuts = list_shortcuts()
    return sorted(shortcuts, key=lambda s: s.name.lower())


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dataclass
class ShortcutAuditResult:
    total: int
    shortcuts: list[Shortcut]
    duplicates: list[str]       # names that appear more than once
    empty_names: int             # shortcuts with blank names


def audit_shortcuts(shortcuts: list[Shortcut] | None = None) -> ShortcutAuditResult:
    """Inspect installed shortcuts and surface potential issues.

    Args:
        shortcuts: Pre-fetched list, or *None* to fetch automatically.
    """
    if shortcuts is None:
        shortcuts = list_all_shortcuts()

    name_counts: dict[str, int] = {}
    empty_names = 0
    for s in shortcuts:
        if not s.name.strip():
            empty_names += 1
        else:
            name_counts[s.name] = name_counts.get(s.name, 0) + 1

    duplicates = sorted(name for name, count in name_counts.items() if count > 1)

    return ShortcutAuditResult(
        total=len(shortcuts),
        shortcuts=shortcuts,
        duplicates=duplicates,
        empty_names=empty_names,
    )


# ---------------------------------------------------------------------------
# AI context builder
# ---------------------------------------------------------------------------

@dataclass
class ShortcutSuggestionContext:
    description: str
    installed_names: list[str]
    context_text: str


def suggest_shortcut(description: str, shortcuts: list[Shortcut] | None = None) -> ShortcutSuggestionContext:
    """Build an AI context string for shortcut recommendation.

    Provides the description alongside the list of already-installed shortcuts
    so that Claude can avoid recommending duplicates and can reference
    existing shortcuts that might partially solve the request.

    Args:
        description: Natural-language description of the desired automation.
        shortcuts: Pre-fetched shortcut list, or *None* to fetch automatically.
    """
    if shortcuts is None:
        shortcuts = list_all_shortcuts()

    installed_names = [s.name for s in shortcuts]

    installed_block = "\n".join(f"  - {n}" for n in installed_names) if installed_names else "  (none installed)"

    context_text = (
        f"User wants to build a macOS Shortcut for:\n"
        f"  {description}\n\n"
        f"Already-installed shortcuts ({len(installed_names)} total):\n"
        f"{installed_block}\n"
    )

    return ShortcutSuggestionContext(
        description=description,
        installed_names=installed_names,
        context_text=context_text,
    )
