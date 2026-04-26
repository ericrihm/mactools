"""macOS defaults system parser — preference domains and keys."""

from __future__ import annotations

import plistlib
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

from mactools_core.runner import run


@dataclass
class DefaultsDomain:
    name: str
    keys: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def key_count(self) -> int:
        return len(self.keys)


def list_domains() -> list[str]:
    r = run(["defaults", "domains"])
    if not r.ok:
        return []
    raw = r.stdout.strip()
    return [d.strip() for d in raw.split(",") if d.strip()]


def read_domain(domain: str) -> DefaultsDomain:
    r = run(["defaults", "export", domain, "-"])
    if not r.ok:
        return DefaultsDomain(name=domain, error=r.stderr.strip())
    try:
        data = plistlib.loads(r.stdout.encode() if isinstance(r.stdout, str) else r.stdout)
        return DefaultsDomain(name=domain, keys=data if isinstance(data, dict) else {})
    except (plistlib.InvalidFileException, Exception):
        return DefaultsDomain(name=domain, error="failed to parse plist")


def read_key(domain: str, key: str) -> Any:
    try:
        result = subprocess.run(
            ["defaults", "read", domain, key],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def find_modified_defaults(domains: Optional[list[str]] = None) -> list[dict]:
    if domains is None:
        domains = list_domains()
    modified = []
    for domain in domains:
        d = read_domain(domain)
        if d.error or not d.keys:
            continue
        if not domain.startswith("com.apple."):
            modified.append({
                "domain": domain, "keys": len(d.keys),
                "reason": "third-party domain",
            })
    return modified


INTERESTING_DEFAULTS = {
    "com.apple.finder": {
        "AppleShowAllFiles": ("Show hidden files", "bool"),
        "ShowPathbar": ("Show path bar", "bool"),
        "ShowStatusBar": ("Show status bar", "bool"),
        "_FXSortFoldersFirst": ("Sort folders first", "bool"),
    },
    "NSGlobalDomain": {
        "AppleShowAllExtensions": ("Show file extensions", "bool"),
        "NSAutomaticSpellingCorrectionEnabled": ("Auto-correct", "bool"),
        "AppleInterfaceStyle": ("Dark mode", "string"),
        "KeyRepeat": ("Key repeat speed", "int"),
        "InitialKeyRepeat": ("Key repeat delay", "int"),
    },
    "com.apple.dock": {
        "autohide": ("Auto-hide dock", "bool"),
        "tilesize": ("Dock icon size", "int"),
        "show-recents": ("Show recent apps", "bool"),
        "mineffect": ("Minimize effect", "string"),
    },
    "com.apple.screencapture": {
        "location": ("Screenshot location", "string"),
        "type": ("Screenshot format", "string"),
        "disable-shadow": ("Disable shadow", "bool"),
    },
}
