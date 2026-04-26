"""Engine for macOS defaults system intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mactools_core.defaults import (
    INTERESTING_DEFAULTS,
    list_domains,
    read_domain,
    read_key,
)


# ---------------------------------------------------------------------------
# Factory baseline — known default values for interesting keys.
# None means "absent by default" (key not set).
# ---------------------------------------------------------------------------

FACTORY_VALUES: dict[str, dict[str, Any]] = {
    "com.apple.finder": {
        "AppleShowAllFiles": False,
        "ShowPathbar": False,
        "ShowStatusBar": False,
        "_FXSortFoldersFirst": False,
    },
    "NSGlobalDomain": {
        "AppleShowAllExtensions": False,
        "NSAutomaticSpellingCorrectionEnabled": True,
        "AppleInterfaceStyle": None,   # absent = light mode
        "KeyRepeat": 6,
        "InitialKeyRepeat": 25,
    },
    "com.apple.dock": {
        "autohide": False,
        "tilesize": 48,
        "show-recents": True,
        "mineffect": "genie",
    },
    "com.apple.screencapture": {
        "location": None,   # absent = Desktop
        "type": "png",
        "disable-shadow": False,
    },
}


@dataclass
class DefaultsFinding:
    domain: str
    key: str
    description: str
    current_value: Any
    factory_value: Any
    modified: bool
    value_type: str


@dataclass
class AuditResult:
    findings: list[DefaultsFinding] = field(default_factory=list)
    modified_count: int = 0
    total_checked: int = 0

    def to_dict(self) -> dict:
        return {
            "modified_count": self.modified_count,
            "total_checked": self.total_checked,
            "findings": [
                {
                    "domain": f.domain,
                    "key": f.key,
                    "description": f.description,
                    "current_value": f.current_value,
                    "factory_value": f.factory_value,
                    "modified": f.modified,
                }
                for f in self.findings
            ],
        }


def audit_defaults() -> AuditResult:
    """Read INTERESTING_DEFAULTS, compare each key to factory values."""
    result = AuditResult()
    for domain, keys in INTERESTING_DEFAULTS.items():
        domain_data = read_domain(domain)
        for key, (description, value_type) in keys.items():
            current = domain_data.keys.get(key)
            factory = FACTORY_VALUES.get(domain, {}).get(key)
            modified = current != factory and not (current is None and factory is None)
            finding = DefaultsFinding(
                domain=domain,
                key=key,
                description=description,
                current_value=current,
                factory_value=factory,
                modified=modified,
                value_type=value_type,
            )
            result.findings.append(finding)
            result.total_checked += 1
            if modified:
                result.modified_count += 1
    return result


def search_key(key: str) -> list[dict]:
    """Search all defaults domains for keys matching `key` (case-insensitive substring)."""
    key_lower = key.lower()
    matches = []
    domains = list_domains()
    for domain in domains:
        d = read_domain(domain)
        if d.error or not d.keys:
            continue
        for k, v in d.keys.items():
            if key_lower in k.lower():
                # Truncate large values
                display_value = v
                if isinstance(v, (bytes, bytearray)):
                    display_value = f"<binary {len(v)} bytes>"
                elif isinstance(v, str) and len(v) > 200:
                    display_value = v[:200] + "…"
                elif isinstance(v, dict) and len(v) > 10:
                    display_value = f"<dict {len(v)} keys>"
                elif isinstance(v, list) and len(v) > 10:
                    display_value = f"<list {len(v)} items>"
                matches.append({
                    "domain": domain,
                    "key": k,
                    "value": display_value,
                })
    return matches


def get_power_user_recommendations() -> list[dict]:
    """Return curated list of power-user defaults changes with explanations and commands."""
    return [
        {
            "category": "Finder",
            "title": "Show all hidden files",
            "key": "AppleShowAllFiles",
            "domain": "com.apple.finder",
            "command": "defaults write com.apple.finder AppleShowAllFiles -bool true && killall Finder",
            "explanation": "Reveals dotfiles and system-hidden files in Finder. Essential for developers.",
            "restart_required": "Finder",
        },
        {
            "category": "Finder",
            "title": "Show file extensions always",
            "key": "AppleShowAllExtensions",
            "domain": "NSGlobalDomain",
            "command": "defaults write NSGlobalDomain AppleShowAllExtensions -bool true && killall Finder",
            "explanation": "Prevents hidden extensions from masking file types (e.g., .docx vs .pdf).",
            "restart_required": "Finder",
        },
        {
            "category": "Finder",
            "title": "Show path bar",
            "key": "ShowPathbar",
            "domain": "com.apple.finder",
            "command": "defaults write com.apple.finder ShowPathbar -bool true && killall Finder",
            "explanation": "Displays the full folder path at the bottom of every Finder window.",
            "restart_required": "Finder",
        },
        {
            "category": "Finder",
            "title": "Sort folders before files",
            "key": "_FXSortFoldersFirst",
            "domain": "com.apple.finder",
            "command": "defaults write com.apple.finder _FXSortFoldersFirst -bool true && killall Finder",
            "explanation": "Groups all folders at the top of Finder listings, matching most professional file managers.",
            "restart_required": "Finder",
        },
        {
            "category": "Keyboard",
            "title": "Faster key repeat",
            "key": "KeyRepeat",
            "domain": "NSGlobalDomain",
            "command": "defaults write NSGlobalDomain KeyRepeat -int 2",
            "explanation": "Sets key repeat interval to minimum (2). Dramatically speeds up cursor movement and text editing.",
            "restart_required": "logout",
        },
        {
            "category": "Keyboard",
            "title": "Shorter key repeat delay",
            "key": "InitialKeyRepeat",
            "domain": "NSGlobalDomain",
            "command": "defaults write NSGlobalDomain InitialKeyRepeat -int 15",
            "explanation": "Reduces delay before key repeat starts. Makes keyboard navigation snappier.",
            "restart_required": "logout",
        },
        {
            "category": "Keyboard",
            "title": "Disable auto-correct",
            "key": "NSAutomaticSpellingCorrectionEnabled",
            "domain": "NSGlobalDomain",
            "command": "defaults write NSGlobalDomain NSAutomaticSpellingCorrectionEnabled -bool false",
            "explanation": "Stops macOS from silently replacing words you type — crucial for code and technical writing.",
            "restart_required": "none",
        },
        {
            "category": "Dock",
            "title": "Auto-hide the Dock",
            "key": "autohide",
            "domain": "com.apple.dock",
            "command": "defaults write com.apple.dock autohide -bool true && killall Dock",
            "explanation": "Maximizes screen real estate by hiding the Dock until you move the cursor to the edge.",
            "restart_required": "Dock",
        },
        {
            "category": "Dock",
            "title": "Hide recent apps from Dock",
            "key": "show-recents",
            "domain": "com.apple.dock",
            "command": "defaults write com.apple.dock show-recents -bool false && killall Dock",
            "explanation": "Removes the auto-populated recent apps section, keeping the Dock clean and intentional.",
            "restart_required": "Dock",
        },
        {
            "category": "Screenshots",
            "title": "Disable screenshot window shadow",
            "key": "disable-shadow",
            "domain": "com.apple.screencapture",
            "command": "defaults write com.apple.screencapture disable-shadow -bool true",
            "explanation": "Window screenshots capture without drop shadow, giving cleaner results for documentation.",
            "restart_required": "none",
        },
    ]
