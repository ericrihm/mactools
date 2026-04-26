"""macOS Spotlight — mdutil, mdfind, mdls wrappers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from mactools_core.runner import run


@dataclass
class IndexStatus:
    volume: str
    enabled: bool = False
    status: str = ""


@dataclass
class FileMetadata:
    path: str
    attributes: dict[str, Any] = field(default_factory=dict)


def get_index_status() -> list[IndexStatus]:
    r = run(["mdutil", "-sa"])
    if not r.ok:
        return []
    statuses = []
    current_vol = ""
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.endswith(":") and "/" in line:
            current_vol = line.rstrip(":")
        elif "Indexing" in line and current_vol:
            enabled = "enabled" in line.lower()
            statuses.append(IndexStatus(
                volume=current_vol, enabled=enabled, status=line,
            ))
            current_vol = ""
    return statuses


def search(query: str, directory: Optional[str] = None, limit: int = 50) -> list[str]:
    cmd = ["mdfind"]
    if directory:
        cmd.extend(["-onlyin", directory])
    cmd.append(query)
    r = run(cmd, timeout=15)
    if not r.ok:
        return []
    results = [line.strip() for line in r.stdout.splitlines() if line.strip()]
    return results[:limit]


def search_predicate(predicate: str, directory: Optional[str] = None, limit: int = 50) -> list[str]:
    cmd = ["mdfind"]
    if directory:
        cmd.extend(["-onlyin", directory])
    cmd.extend(["-interpret", predicate])
    r = run(cmd, timeout=15)
    if not r.ok:
        return []
    results = [line.strip() for line in r.stdout.splitlines() if line.strip()]
    return results[:limit]


def get_metadata(path: str) -> FileMetadata:
    r = run(["mdls", "-plist", "-", path])
    if not r.ok:
        return FileMetadata(path=path)
    try:
        import plistlib
        data = plistlib.loads(r.stdout.encode() if isinstance(r.stdout, str) else r.stdout)
        return FileMetadata(path=path, attributes=data if isinstance(data, dict) else {})
    except Exception:
        return FileMetadata(path=path)
