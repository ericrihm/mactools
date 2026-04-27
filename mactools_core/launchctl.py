"""macOS launchctl parser — service enumeration and analysis."""

from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mactools_core.runner import run


LAUNCH_DIRS = [
    Path("/System/Library/LaunchDaemons"),
    Path("/System/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/Library/LaunchAgents"),
    Path.home() / "Library" / "LaunchAgents",
]


@dataclass
class LaunchService:
    label: str
    pid: int = -1
    status: int = 0
    running: bool = False
    plist_path: Optional[str] = None
    program: Optional[str] = None
    program_args: list[str] = field(default_factory=list)
    run_at_load: bool = False
    keep_alive: bool = False
    source: str = "unknown"
    is_apple: bool = False

    @property
    def vendor(self) -> str:
        if self.is_apple:
            return "Apple"
        label = self.label.lower()
        for prefix, vendor in _KNOWN_VENDORS.items():
            if prefix in label:
                return vendor
        return "Third-party"


_KNOWN_VENDORS = {
    "com.apple.": "Apple",
    "com.google.": "Google",
    "com.microsoft.": "Microsoft",
    "com.docker.": "Docker",
    "com.orbstack.": "OrbStack",
    "com.github.": "GitHub",
    "com.1password.": "1Password",
    "com.crowdstrike.": "CrowdStrike",
    "com.adobe.": "Adobe",
    "com.jetbrains.": "JetBrains",
    "com.zoom.": "Zoom",
    "com.slack.": "Slack",
    "com.spotify.": "Spotify",
    "homebrew.": "Homebrew",
    "org.mozilla.": "Mozilla",
}


def list_services() -> list[LaunchService]:
    r = run(["launchctl", "list"])
    if not r.ok:
        return []
    services = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        pid_str, status_str, label = parts[0].strip(), parts[1].strip(), parts[2].strip()
        pid = int(pid_str) if pid_str != "-" else -1
        status = int(status_str) if status_str != "-" else 0
        svc = LaunchService(
            label=label, pid=pid, status=status,
            running=pid > 0,
            is_apple=label.startswith("com.apple.") or label.startswith("[system]"),
        )
        services.append(svc)
    return services


def enrich_from_plists(services: list[LaunchService]) -> list[LaunchService]:
    plist_map = _build_plist_map()
    for svc in services:
        path = plist_map.get(svc.label)
        if path:
            svc.plist_path = str(path)
            svc.source = _classify_source(path)
            try:
                with open(path, "rb") as f:
                    plist = plistlib.load(f)
                svc.program = plist.get("Program", "")
                svc.program_args = plist.get("ProgramArguments", [])
                svc.run_at_load = plist.get("RunAtLoad", False)
                svc.keep_alive = bool(plist.get("KeepAlive", False))
            except (plistlib.InvalidFileException, PermissionError, FileNotFoundError, OSError):
                pass
    return services


def _build_plist_map() -> dict[str, Path]:
    mapping = {}
    for d in LAUNCH_DIRS:
        if not d.exists():
            continue
        for f in d.glob("*.plist"):
            try:
                with open(f, "rb") as fh:
                    plist = plistlib.load(fh)
                label = plist.get("Label", f.stem)
                mapping[label] = f
            except (plistlib.InvalidFileException, PermissionError, OSError):
                mapping[f.stem] = f
    return mapping


def _classify_source(path: Path) -> str:
    s = str(path)
    if "/System/Library/" in s:
        return "system"
    if s.startswith(str(Path.home())):
        return "user"
    if "/Library/" in s:
        return "global"
    return "unknown"


def get_service_detail(label: str) -> dict:
    r = run(["launchctl", "print", f"gui/{_get_uid()}/{label}"])
    if not r.ok:
        r = run(["launchctl", "print", f"system/{label}"])
    if not r.ok:
        return {"label": label, "error": "not found"}
    return {"label": label, "raw": r.stdout}


def _get_uid() -> int:
    import os
    return os.getuid()
